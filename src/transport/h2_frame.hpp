#pragma once
#include "transport/http2_session.hpp"
#include "transport/http1_handshake.hpp"
#include "transport/hpack.hpp"
#include "common/byte_reader.hpp"
#include <algorithm>
#include <cstring>
#include <optional>
#include <span>
#include <tl/expected.hpp>
#include <string>
#include <vector>

namespace transport {
inline constexpr size_t kHttp2FrameHeaderSize = 9;
inline constexpr size_t kHttp2MaxFramePayload = 16 * 1024;
inline constexpr size_t kHttp2MaxHeaderBlockSize = 64 * 1024;
inline constexpr size_t kHttp2MaxConcurrentStreams = 256;
// RFC 9113 5.2.2: keep reading control frames when a consumer stalls.
// One stream cannot occupy the whole connection window. Allocation budgets
// also cover tiny-frame capacity amplification and the gRPC assembly buffer.
inline constexpr size_t kHttp2MaxQueuedStreamBytes = 4 * 1024 * 1024;
// A partially consumed head and an incompletely filled tail each retain at
// most one frame allocation beyond the unread-byte window.
inline constexpr size_t kHttp2MaxQueuedStreamStorage =
    kHttp2MaxQueuedStreamBytes + 2 * kHttp2MaxFramePayload;
inline constexpr uint32_t kHttp2ConnectionReceiveWindow = 8 * 1024 * 1024;
inline constexpr size_t kHttp2ReceiveMemoryLimit = 16 * 1024 * 1024;
inline constexpr uint32_t kDefaultInitialWindow = 4 * 1024 * 1024;
// RFC 9113 6.x frame flags.
inline constexpr uint8_t kFlagEndStream = 0x1;
inline constexpr uint8_t kFlagAck = 0x1;
inline constexpr uint8_t kFlagEndHeaders = 0x4;
inline constexpr uint8_t kFlagPadded = 0x8;
inline constexpr uint8_t kFlagPriority = 0x20;

enum class H2FrameType : uint8_t {
    DATA = 0x0,
    HEADERS = 0x1,
    PRIORITY = 0x2,
    RST_STREAM = 0x3,
    SETTINGS = 0x4,
    PUSH_PROMISE = 0x5,
    PING = 0x6,
    GOAWAY = 0x7,
    WINDOW_UPDATE = 0x8,
    CONTINUATION = 0x9,
};

enum class H2Error : uint32_t {
    Protocol = 0x1,
    FlowControl = 0x3,
    StreamClosed = 0x5,
    FrameSize = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    Compression = 0x9,
    ExcessiveLoad = 0xb,
};

enum class H2PayloadCodec : uint8_t {
    GrpcHunk,
    RawData,
};

struct H2Frame {
    static constexpr size_t kInlinePayloadCapacity = 64;

    H2FrameType type = H2FrameType::DATA;
    uint8_t flags = 0;
    uint8_t inline_size = 0;
    uint32_t stream_id = 0;
    std::array<uint8_t, kInlinePayloadCapacity> inline_payload{};
    common::BufferGuard buffer_payload;

    [[nodiscard]] std::span<const uint8_t> Payload() const noexcept {
        return buffer_payload
            ? buffer_payload->Bytes()
            : std::span<const uint8_t>(inline_payload.data(), inline_size);
    }
};

net::awaitable<std::optional<H2Frame>> ReadH2Frame(AsyncStream& stream);
net::awaitable<void> WriteH2FrameBuffers(
    AsyncStream&, H2FrameType, uint8_t, uint32_t,
    std::span<const net::const_buffer>);
std::optional<std::span<const uint8_t>> H2HeaderBlockFragment(const H2Frame&);
std::span<const uint8_t> H2DataPayload(const H2Frame&);

// Sans-I/O cursor slicing body buffers into DATA frame payloads without
// copying. Each payload fits WriteH2FrameBuffers beside the frame header.
class H2DataCursor {
public:
    static constexpr size_t kMaxParts = 7;

    explicit H2DataCursor(std::span<const net::const_buffer> buffers) noexcept
        : buffers_(buffers) {
        for (const auto& buffer : buffers) remaining_ += buffer.size();
    }

    [[nodiscard]] size_t Remaining() const noexcept { return remaining_; }

    // Next payload of at most `limit` bytes; shorter when it would need more
    // than kMaxParts source slices. Valid until the next call.
    [[nodiscard]] std::span<const net::const_buffer> Next(size_t limit) noexcept {
        size_t count = 0;
        size_t frame_len = 0;
        while (index_ < buffers_.size() && frame_len < limit && count < parts_.size()) {
            const auto& source = buffers_[index_];
            if (offset_ >= source.size()) {
                ++index_;
                offset_ = 0;
                continue;
            }
            const size_t take = std::min(source.size() - offset_, limit - frame_len);
            parts_[count++] = net::buffer(
                static_cast<const uint8_t*>(source.data()) + offset_, take);
            frame_len += take;
            offset_ += take;
        }
        remaining_ -= frame_len;
        return {parts_.data(), count};
    }

    // Byte length of a payload returned by Next().
    [[nodiscard]] static size_t Size(std::span<const net::const_buffer> payload) noexcept {
        size_t size = 0;
        for (const auto& part : payload) size += part.size();
        return size;
    }

private:
    std::span<const net::const_buffer> buffers_;
    std::array<net::const_buffer, kMaxParts> parts_{};
    size_t index_ = 0;
    size_t offset_ = 0;
    size_t remaining_ = 0;
};

// Reserve room for a field key and the longest uint32 length varint.
inline constexpr size_t kGrpcHunkRecordPayloadLimit = kMaxGrpcHunkMessageSize - 6;

// gRPC length prefix plus the Hunk protobuf `data` field key and length of one
// message carrying `data_size` bytes (data_size <= kGrpcHunkRecordPayloadLimit).
struct GrpcHunkPrefix {
    std::array<uint8_t, 16> bytes{};
    size_t size = 0;

    explicit GrpcHunkPrefix(size_t data_size) noexcept {
        const uint64_t hunk_len = 1 + common::VarintU64Size(data_size) + data_size;
        bytes[0] = 0;
        common::StoreU32BE(bytes.data() + 1, static_cast<uint32_t>(hunk_len));
        common::ByteWriter writer(bytes.data() + 5, bytes.size() - 5);
        (void)writer.WriteU8(0x0a); // Hunk.data field, length-delimited.
        (void)writer.WriteVarintU64(data_size);
        size = 5 + writer.Position();
    }

    [[nodiscard]] net::const_buffer Buffer() const noexcept {
        return net::buffer(bytes.data(), size);
    }
};

// RFC 9113 6.9.1 send window. Signed because a SETTINGS_INITIAL_WINDOW_SIZE
// reduction may drive a stream window negative (6.9.2); no change may push it
// above 2^31-1.
class H2SendWindow {
public:
    static constexpr int64_t kDefault = 65535;
    static constexpr int64_t kMax = 0x7fff'ffff;

    H2SendWindow() noexcept = default;
    explicit H2SendWindow(int64_t size) noexcept : size_(size) {}

    [[nodiscard]] size_t Available() const noexcept {
        return size_ > 0 ? static_cast<size_t>(size_) : 0;
    }

    void Consume(size_t n) noexcept { size_ -= static_cast<int64_t>(n); }

    // False (window unchanged) when the result would exceed 2^31-1.
    [[nodiscard]] bool Adjust(int64_t delta) noexcept {
        if (delta > kMax - size_) return false;
        size_ += delta;
        return true;
    }

private:
    int64_t size_ = kDefault;
};
[[nodiscard]] inline HpackBuffer EncodeGrpcRequestHeaders(
    std::string_view authority,
    std::string_view path,
    bool tls,
    std::string_view user_agent) {
    HpackBuffer h;
    h.reserve(128 + authority.size() + path.size() + user_agent.size());
    AppendHpackIndexed(h, kHpackStaticMethodPost);
    AppendHpackIndexed(h, tls ? kHpackStaticSchemeHttps : kHpackStaticSchemeHttp);
    AppendHpackLiteralIndexedName(h, kHpackStaticPath, path);
    if (!authority.empty()) {
        AppendHpackLiteralIndexedName(h, kHpackStaticAuthority, authority);
    }
    AppendHpackLiteralIndexedName(h, kHpackStaticContentType, "application/grpc");
    AppendHpackLiteralNewName(h, "te", "trailers");
    if (!user_agent.empty()) {
        AppendHpackLiteralIndexedName(h, kHpackStaticUserAgent, user_agent);
    }
    return h;
}

// :status: 200 (indexed 8) + content-type: application/grpc (literal indexed 31).
inline constexpr std::array<uint8_t, 20> kGrpcResponseHeaderBlock{
    0x80 | kHpackStaticStatusOk, 0x0f, kHpackStaticContentType - 15, 0x10,
    'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'g', 'r', 'p', 'c',
};

// grpc-status: 0 (literal new name).
inline constexpr std::array<uint8_t, 15> kGrpcTrailerBlock{
    0x00, 0x0b,
    'g', 'r', 'p', 'c', '-', 's', 't', 'a', 't', 'u', 's',
    0x01, '0',
};
[[nodiscard]] inline bool IsConnectionSpecificHttp2Header(std::string_view key) noexcept {
    return common::EqualsAsciiCI(key, "host") ||
          common::EqualsAsciiCI(key, "connection") ||
          common::EqualsAsciiCI(key, "keep-alive") ||
          common::EqualsAsciiCI(key, "proxy-connection") ||
          common::EqualsAsciiCI(key, "transfer-encoding") ||
          common::EqualsAsciiCI(key, "upgrade");
}

[[nodiscard]] constexpr bool IsValidHttp2HeaderName(std::string_view name) noexcept {
    if (name.empty()) return false;
    for (const unsigned char ch : name) {
        if (!(ch > 0x20 && ch < 0x7f && !(ch >= 'A' && ch <= 'Z') && ch != ':')) {
            return false;
        }
    }
    return true;
}
// Decodes a complete single-frame HEADERS/PUSH_PROMISE block without
// allocating a coroutine frame (the steady-state kFlagEndHeaders path).
template <typename Visitor>
[[nodiscard]] tl::expected<void, H2Error> DecodeSingleH2HeaderBlock(
    HpackDecoder& decoder, const H2Frame& frame, Visitor&& on_field) {
    const auto fragment = H2HeaderBlockFragment(frame);
    if (!fragment) {
        // RFC 9113 6.2: padding at least as long as the payload.
        return tl::unexpected(H2Error::Protocol);
    }
    if (fragment->size() > kHttp2MaxHeaderBlockSize) {
        return tl::unexpected(H2Error::ExcessiveLoad);
    }
    // RFC 7541 2.3 / RFC 9113 4.3: undecodable block is COMPRESSION_ERROR.
    if (!decoder.Decode(*fragment, on_field)) {
        return tl::unexpected(H2Error::Compression);
    }
    return {};
}

// Reads the CONTINUATION frames completing `frame` (RFC 9113 6.10) and
// decodes the whole block. Every block is decoded, including rejected
// streams', to keep the connection-wide HPACK state in sync. Every failure
// here is a connection error: the HPACK state can no longer be trusted.
template <typename Visitor>
net::awaitable<tl::expected<void, H2Error>> ReadH2HeaderFields(
    AsyncStream& stream, HpackDecoder& decoder, H2Frame frame, Visitor&& on_field) {
    if ((frame.flags & kFlagEndHeaders) != 0) {
        co_return DecodeSingleH2HeaderBlock(
            decoder, frame, std::forward<Visitor>(on_field));
    }
    const uint32_t stream_id = frame.stream_id;
    const auto fragment = H2HeaderBlockFragment(frame);
    if (!fragment) {
        co_return tl::unexpected(H2Error::Protocol);
    }
    if (fragment->size() > kHttp2MaxHeaderBlockSize) {
        co_return tl::unexpected(H2Error::ExcessiveLoad);
    }
    std::vector<uint8_t> block(fragment->begin(), fragment->end());
    while (true) {
        auto continuation = co_await ReadH2Frame(stream);
        if (!continuation ||
            continuation->type != H2FrameType::CONTINUATION ||
            continuation->stream_id != stream_id) {
            co_return tl::unexpected(H2Error::Protocol);
        }
        const auto cont_payload = continuation->Payload();
        if (cont_payload.size() > kHttp2MaxHeaderBlockSize - block.size()) {
            co_return tl::unexpected(H2Error::ExcessiveLoad);
        }
        block.insert(block.end(), cont_payload.begin(), cont_payload.end());
        if ((continuation->flags & kFlagEndHeaders) != 0) {
            break;
        }
    }
    if (!decoder.Decode(block, on_field)) {
        co_return tl::unexpected(H2Error::Compression);
    }
    co_return tl::expected<void, H2Error>{};
}
struct H2RequestHeaders {
    std::string method;
    std::string path;
    std::string authority;
    InboundTransportMetadata metadata;
};

// RFC 9113 8.3: each request pseudo-header appears at most once, none in
// trailers, and Host must agree with :authority. Ambiguous requests are
// malformed (8.1.1) rather than resolved by field order.
[[nodiscard]] inline bool AuthorityMatchesHost(std::string_view authority,
                                        std::string_view expected_host) noexcept {
    authority = common::TrimAscii(authority);
    expected_host = common::TrimAscii(expected_host);
    if (common::EqualsAsciiCI(authority, expected_host)) {
        return true;
    }
    const auto strip_port = [](std::string_view value) noexcept {
        const auto split = common::SplitHostPort(value);
        if (!split || !split->has_port) {
            return value;
        }
        return split->bracketed
            ? value.substr(0, split->host.size() + 2)
            : split->host;
    };
    return strip_port(expected_host) == expected_host &&
           common::EqualsAsciiCI(strip_port(authority), expected_host);
}

tl::expected<std::optional<uint32_t>, H2Error> PeerInitialWindowSetting(
    std::span<const uint8_t>);
tl::expected<uint32_t, H2Error> WindowUpdateIncrement(const H2Frame&);
inline void EncodeH2FrameHeader(uint8_t* out,
                                uint32_t payload_len,
                                H2FrameType type,
                                uint8_t flags,
                                uint32_t stream_id) noexcept {
    common::StoreU24BE(out, payload_len);
    out[3] = static_cast<uint8_t>(type);
    out[4] = flags;
    common::StoreU32BE(out + 5, stream_id & 0x7fff'ffffu);
}
void EncodeWindowUpdateFrame(uint8_t* out, uint32_t stream_id, uint32_t increment) noexcept;
net::awaitable<void> SendWindowUpdates(AsyncStream&, uint32_t, uint32_t, uint32_t);
struct HttpClientRequestView;
HpackBuffer EncodeHttpRequestHeaders(
    std::string_view, bool, const HttpClientRequestView&);
std::vector<uint8_t> EncodeHttpResponseHeaders(
    const HttpHeaders& headers, std::string_view default_content_type = {});
[[nodiscard]] tl::expected<std::optional<H2RequestHeaders>, H2Error>
TryParseSingleH2RequestHeaders(
    HpackDecoder&, const H2Frame&, std::string_view, bool);
net::awaitable<tl::expected<std::optional<H2RequestHeaders>, H2Error>> ParseH2RequestHeaders(
    AsyncStream&, HpackDecoder&, H2Frame, std::string_view, bool);
[[nodiscard]] inline std::array<uint8_t, 8> EncodeGoaway(
    uint32_t last_stream, H2Error error) noexcept {
    std::array<uint8_t, 8> payload{};
    common::StoreU32BE(payload.data(), last_stream);
    common::StoreU32BE(payload.data() + 4, static_cast<uint32_t>(error));
    return payload;
}

// 两端共用的 Sans-I/O Hunk 分片游标；零额外协程帧，发送窗口与串行门仍归各物理会话所有。
class GrpcHunkCursor {
public:
    explicit GrpcHunkCursor(std::span<const uint8_t> data) noexcept
        : remaining_(data) {}

    [[nodiscard]] std::span<const net::const_buffer> Next() noexcept {
        const size_t size = std::min(remaining_.size(), kGrpcHunkRecordPayloadLimit);
        prefix_.emplace(size);
        record_[0] = prefix_->Buffer();
        record_[1] = net::buffer(remaining_.data(), size);
        remaining_ = remaining_.subspan(size);
        done_ = remaining_.empty();
        return record_;
    }

    [[nodiscard]] bool Done() const noexcept { return done_; }

private:
    std::span<const uint8_t> remaining_;
    std::optional<GrpcHunkPrefix> prefix_;
    std::array<net::const_buffer, 2> record_{};
    bool done_ = false;
};

}  // namespace transport
