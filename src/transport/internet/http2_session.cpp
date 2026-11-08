#include "http2_session.hpp"
#include "common/byte_reader.hpp"

#include "grpc_hunk.hpp"
#include "http1_handshake.hpp"
#include "http2_settings.hpp"
#include "http_path_match.hpp"
#include "xhttp_session.hpp"
#include "../../common/awaitable_task_group.hpp"
#include "app/session_group_executor.hpp"
#include "common/allocator.hpp"
#include "common/buffer_util.hpp"
#include "common/container_util.hpp"
#include "common/unsafe.hpp"
#include "infra/log.hpp"
#include "transport/internet/async_write_gate.hpp"
#include "transport/internet/http_headers.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "transport/phase_deadline.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <optional>
#include <stdexcept>

#include <tl/expected.hpp>

namespace transport::internet {
namespace {

// Capture once at the physical session entry, before native I/O can suspend.
// This executor follows group ownership without relocating the session or its
// coroutine frames. Plain io_context callers (including tests) remain valid.
net::any_io_executor CaptureHttp2Executor(net::io_context& io_context) {
    if (auto domain = ExecutionDomain::Current()) return domain->Executor();
    return io_context.get_executor();
}

constexpr size_t kHttp2FrameHeaderSize = 9;
constexpr size_t kHttp2MaxFramePayload = 16 * 1024;
constexpr size_t kHttp2MaxHeaderBlockSize = 64 * 1024;
constexpr size_t kHttp2MaxConcurrentStreams = 256;
// RFC 9113 5.2.2: keep reading control frames when a consumer stalls.
// One stream cannot occupy the whole connection window. Allocation budgets
// also cover tiny-frame capacity amplification and the gRPC assembly buffer.
constexpr size_t kHttp2MaxQueuedStreamBytes = 4 * 1024 * 1024;
// A partially consumed head and an incompletely filled tail each retain at
// most one frame allocation beyond the unread-byte window.
constexpr size_t kHttp2MaxQueuedStreamStorage =
    kHttp2MaxQueuedStreamBytes + 2 * kHttp2MaxFramePayload;
constexpr uint32_t kHttp2ConnectionReceiveWindow = 8 * 1024 * 1024;
constexpr size_t kHttp2ReceiveMemoryLimit = 16 * 1024 * 1024;
constexpr uint32_t kDefaultInitialWindow = 4 * 1024 * 1024;
constexpr uint32_t kHpackMaxDynamicTableSize = 4096;
constexpr size_t kHpackMaxHeaderFields = 256;
constexpr size_t kHpackMaxHeaderListSize = 64 * 1024;

// RFC 9113 6.x frame flags.
constexpr uint8_t kFlagEndStream = 0x1;
constexpr uint8_t kFlagAck = 0x1;
constexpr uint8_t kFlagEndHeaders = 0x4;
constexpr uint8_t kFlagPadded = 0x8;
constexpr uint8_t kFlagPriority = 0x20;

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
    uint32_t length = 0;
    H2FrameType type = H2FrameType::DATA;
    uint8_t flags = 0;
    uint32_t stream_id = 0;
    memory::ByteVector payload;
};

[[nodiscard]] uint32_t ReadU24(const uint8_t* p) noexcept {
    return (static_cast<uint32_t>(p[0]) << 16) |
           (static_cast<uint32_t>(p[1]) << 8) |
           static_cast<uint32_t>(p[2]);
}

[[noreturn]] void ThrowHttp2StreamError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

net::awaitable<bool> ReadFullFromStream(AsyncStream& stream,
                                        uint8_t* data,
                                        size_t len) {
    size_t done = 0;
    while (done < len) {
        const size_t n = co_await stream.AsyncRead(
            net::buffer(data + done, len - done));
        if (n == 0) {
            co_return false;
        }
        done += n;
    }
    co_return true;
}

// Returns nullopt only on a clean EOF at a frame boundary.
net::awaitable<std::optional<H2Frame>> ReadH2Frame(AsyncStream& stream) {
    std::array<uint8_t, kHttp2FrameHeaderSize> header{};
    size_t received = 0;
    while (received != header.size()) {
        size_t n = 0;
        try {
            n = co_await stream.AsyncRead(
                net::buffer(header.data() + received, header.size() - received));
        } catch (const IoSystemError& error) {
            if (received != 0 && error.code() == io_error::operation_aborted) {
                throw IoSystemError(io_error::connection_reset, "cancelled mid-HTTP/2 frame header");
            }
            throw;
        }
        if (n == 0) {
            if (received == 0) co_return std::nullopt;
            throw IoSystemError(io_error::connection_reset, "truncated HTTP/2 frame header");
        }
        received += n;
    }

    H2Frame frame;
    frame.length = ReadU24(header.data());
    frame.type = static_cast<H2FrameType>(header[3]);
    frame.flags = header[4];
    frame.stream_id = LoadU32BE(header.data() + 5) & 0x7fff'ffffu;

    if (frame.length > kHttp2MaxFramePayload) {
        throw IoSystemError(io_error::message_size, "HTTP/2 frame exceeds receive limit");
    }
    if (frame.length > 0) {
        try {
            size_t filled = 0;
            while (filled < frame.length) {
                if (filled == frame.payload.size()) {
                    const size_t next_size = std::min<size_t>(
                        frame.length,
                        std::max<size_t>(1024, frame.payload.size() * 2));
                    frame.payload.resize(next_size);
                }
                const size_t n = co_await stream.AsyncRead(
                    net::buffer(frame.payload.data() + filled,
                                frame.payload.size() - filled));
                if (n == 0) {
                    throw IoSystemError(
                        io_error::connection_reset, "truncated HTTP/2 frame payload");
                }
                filled += n;
            }
        } catch (const IoSystemError& error) {
            if (error.code() == io_error::operation_aborted) {
                throw IoSystemError(io_error::connection_reset, "cancelled mid-HTTP/2 frame payload");
            }
            throw;
        }
    }
    co_return frame;
}

// Writes one complete frame. Returns false for an unencodable frame; write
// failures throw after retiring the connection.
net::awaitable<bool> WriteH2FrameBuffers(
    AsyncStream& stream,
    H2FrameType type,
    uint8_t flags,
    uint32_t stream_id,
    std::span<const net::const_buffer> payloads) {
    size_t payload_len = 0;
    for (const auto& payload : payloads) {
        payload_len += payload.size();
    }
    if (payload_len > 0x00ff'ffffu) {
        co_return false;
    }

    std::array<uint8_t, kHttp2FrameHeaderSize> header{};
    header[0] = static_cast<uint8_t>((payload_len >> 16) & 0xff);
    header[1] = static_cast<uint8_t>((payload_len >> 8) & 0xff);
    header[2] = static_cast<uint8_t>(payload_len & 0xff);
    header[3] = static_cast<uint8_t>(type);
    header[4] = flags;
    StoreU32BE(header.data() + 5, stream_id & 0x7fff'ffffu);

    std::array<net::const_buffer, 8> all{};
    size_t count = 0;
    all[count++] = net::buffer(header);
    for (const auto& payload : payloads) {
        if (payload.size() > 0) {
            if (count >= all.size()) {
                co_return false;
            }
            all[count++] = payload;
        }
    }
    try {
        co_await stream.WriteBuffers(std::span<const net::const_buffer>(all.data(), count));
    } catch (...) {
        // A failed physical write may have emitted a partial frame. Retire the
        // connection before another stream can append bytes to that frame.
        stream.CloseAbortive();
        throw;
    }
    co_return true;
}

net::awaitable<bool> WriteH2Frame(
    AsyncStream& stream,
    H2FrameType type,
    uint8_t flags,
    uint32_t stream_id,
    std::span<const uint8_t> payload = {}) {
    const net::const_buffer buffer{payload.data(), payload.size()};
    co_return co_await WriteH2FrameBuffers(
        stream,
        type,
        flags,
        stream_id,
        payload.empty()
            ? std::span<const net::const_buffer>{}
            : std::span<const net::const_buffer>(&buffer, 1));
}

void AppendHpackInt(memory::ByteVector& out,
                    uint8_t prefix_bits,
                    uint8_t first_mask,
                    uint32_t value) {
    const uint8_t max_prefix = static_cast<uint8_t>((1u << prefix_bits) - 1u);
    if (value < max_prefix) {
        out.push_back(static_cast<uint8_t>(first_mask | value));
        return;
    }

    out.push_back(static_cast<uint8_t>(first_mask | max_prefix));
    value -= max_prefix;
    while (value >= 128) {
        out.push_back(static_cast<uint8_t>((value & 0x7f) | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

void AppendHpackString(memory::ByteVector& out, std::string_view value) {
    AppendHpackInt(out, 7, 0, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void AppendHpackIndexed(memory::ByteVector& out, uint32_t index) {
    AppendHpackInt(out, 7, 0x80, index);
}

void AppendHpackLiteralIndexedName(memory::ByteVector& out,
                                   uint32_t name_index,
                                   std::string_view value) {
    AppendHpackInt(out, 4, 0, name_index);
    AppendHpackString(out, value);
}

void AppendHpackLiteralNewName(memory::ByteVector& out,
                               std::string_view name,
                               std::string_view value) {
    out.push_back(0);
    AppendHpackString(out, name);
    AppendHpackString(out, value);
}

[[nodiscard]] memory::ByteVector EncodeGrpcRequestHeaders(
    std::string_view authority,
    std::string_view path,
    bool tls,
    std::string_view user_agent) {
    memory::ByteVector h;
    h.reserve(128 + authority.size() + path.size() + user_agent.size());
    AppendHpackIndexed(h, 3); // :method: POST
    AppendHpackIndexed(h, tls ? 7 : 6); // :scheme
    AppendHpackLiteralIndexedName(h, 4, path); // :path
    if (!authority.empty()) {
        AppendHpackLiteralIndexedName(h, 1, authority); // :authority
    }
    AppendHpackLiteralIndexedName(h, 31, "application/grpc");
    AppendHpackLiteralNewName(h, "te", "trailers");
    if (!user_agent.empty()) {
        AppendHpackLiteralIndexedName(h, 58, user_agent);
    }
    return h;
}

[[nodiscard]] memory::ByteVector EncodeGrpcResponseHeaders() {
    memory::ByteVector h;
    h.reserve(32);
    AppendHpackIndexed(h, 8); // :status: 200
    AppendHpackLiteralIndexedName(h, 31, "application/grpc");
    return h;
}

[[nodiscard]] memory::ByteVector EncodeGrpcTrailers() {
    memory::ByteVector h;
    h.reserve(24);
    AppendHpackLiteralNewName(h, "grpc-status", "0");
    return h;
}

[[nodiscard]] bool IsConnectionSpecificHttp2Header(std::string_view key) noexcept {
    return EqualsAsciiCI(key, "host") ||
          EqualsAsciiCI(key, "connection") ||
          EqualsAsciiCI(key, "keep-alive") ||
          EqualsAsciiCI(key, "proxy-connection") ||
          EqualsAsciiCI(key, "transfer-encoding") ||
          EqualsAsciiCI(key, "upgrade");
}

[[nodiscard]] memory::ThreadLocalString LowercaseAscii(std::string_view input) {
    memory::ThreadLocalString out(input);
    for (char& ch : out) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return out;
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

[[nodiscard]] memory::ByteVector EncodeHttpRequestHeaders(
    std::string_view authority,
    bool tls,
    const HttpConfig& cfg) {
    const std::string_view method = cfg.method.empty()
        ? std::string_view("PUT") : std::string_view(cfg.method);
    const std::string_view req_path = detail::EffectiveHttpPath(cfg.path);
    memory::ByteVector h;
    h.reserve(128 + authority.size() + req_path.size() + method.size() +
              cfg.headers.size() * 32);

    if (method == "GET") {
        AppendHpackIndexed(h, 2); // :method: GET
    } else if (method == "POST") {
        AppendHpackIndexed(h, 3); // :method: POST
    } else {
        AppendHpackLiteralIndexedName(h, 2, method); // :method
    }
    AppendHpackIndexed(h, tls ? 7 : 6); // :scheme
    if (req_path == "/") {
        AppendHpackIndexed(h, 4); // :path: /
    } else {
        AppendHpackLiteralIndexedName(h, 4, req_path); // :path
    }
    if (!authority.empty()) {
        AppendHpackLiteralIndexedName(h, 1, authority); // :authority
    }
    for (const auto& [key, value] : cfg.headers) {
        if (key.empty() || IsConnectionSpecificHttp2Header(key)) {
            continue;
        }
        const auto lower_key = LowercaseAscii(key);
        AppendHpackLiteralNewName(h, lower_key, value);
    }
    return h;
}

[[nodiscard]] memory::ByteVector EncodeHttpResponseHeaders(const HttpHeaders& headers) {
    memory::ByteVector h;
    h.reserve(64 + headers.size() * 32);
    AppendHpackIndexed(h, 8); // :status: 200
    AppendHpackLiteralNewName(h, "cache-control", "no-store");
    for (const auto& [key, value] : headers) {
        if (key.empty() || IsConnectionSpecificHttp2Header(key)) {
            continue;
        }
        const auto lower_key = LowercaseAscii(key);
        AppendHpackLiteralNewName(h, lower_key, value);
    }
    return h;
}

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

size_t WriteProtoVarint(uint8_t* out, uint64_t value) noexcept {
    size_t n = 0;
    while (value >= 0x80) {
        out[n++] = static_cast<uint8_t>((value & 0x7f) | 0x80);
        value >>= 7;
    }
    out[n++] = static_cast<uint8_t>(value);
    return n;
}

// Reserve room for a field key and the longest uint32 length varint.
constexpr size_t kGrpcHunkRecordPayloadLimit = kMaxGrpcHunkMessageSize - 6;

// gRPC length prefix plus the Hunk protobuf `data` field key and length of one
// message carrying `data_size` bytes (data_size <= kGrpcHunkRecordPayloadLimit).
struct GrpcHunkPrefix {
    std::array<uint8_t, 16> bytes{};
    size_t size = 0;

    explicit GrpcHunkPrefix(size_t data_size) noexcept {
        const uint64_t hunk_len =
            1 + ((data_size < 0x80) ? 1 :
                 (data_size < 0x4000) ? 2 :
                 (data_size < 0x20'0000) ? 3 :
                 (data_size < 0x1000'0000) ? 4 : 5) +
            data_size;
        bytes[size++] = 0;
        StoreU32BE(bytes.data() + size, static_cast<uint32_t>(hunk_len));
        size += 4;
        bytes[size++] = 0x0a; // Hunk.data field, length-delimited.
        size += WriteProtoVarint(bytes.data() + size, static_cast<uint64_t>(data_size));
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

// Last SETTINGS_INITIAL_WINDOW_SIZE in a validated non-ACK SETTINGS payload;
// a value above 2^31-1 is a FLOW_CONTROL_ERROR connection error (6.5.2).
[[nodiscard]] tl::expected<std::optional<uint32_t>, H2Error> PeerInitialWindowSetting(
    std::span<const uint8_t> payload) {
    std::optional<uint32_t> initial_window;
    for (size_t offset = 0; offset + 6 <= payload.size(); offset += 6) {
        const uint16_t id = static_cast<uint16_t>((payload[offset] << 8) | payload[offset + 1]);
        if (id != 4) continue;
        const uint32_t value = LoadU32BE(payload.data() + offset + 2);
        if (value > H2SendWindow::kMax) return tl::unexpected(H2Error::FlowControl);
        initial_window = value;
    }
    return initial_window;
}

// WINDOW_UPDATE increment (6.9): FRAME_SIZE_ERROR unless the payload is four
// octets; a zero increment is a PROTOCOL_ERROR.
[[nodiscard]] tl::expected<uint32_t, H2Error> WindowUpdateIncrement(const H2Frame& frame) {
    if (frame.payload.size() != 4) return tl::unexpected(H2Error::FrameSize);
    const uint32_t increment = LoadU32BE(frame.payload.data()) & 0x7fff'ffffu;
    if (increment == 0) return tl::unexpected(H2Error::Protocol);
    return increment;
}

net::awaitable<void> SendWindowUpdate(AsyncStream& stream,
                                      uint32_t stream_id,
                                      uint32_t increment) {
    if (increment == 0) {
        co_return;
    }
    std::array<uint8_t, 4> payload{};
    StoreU32BE(payload.data(), increment & 0x7fff'ffffu);
    (void)co_await WriteH2Frame(
        stream,
        H2FrameType::WINDOW_UPDATE,
        0,
        stream_id,
        payload);
}

// DATA payload without padding; empty when the padding length is invalid.
[[nodiscard]] std::span<const uint8_t> H2DataPayload(const H2Frame& frame) {
    if (frame.payload.empty()) {
        return {};
    }
    size_t start = 0;
    size_t end = frame.payload.size();
    if ((frame.flags & kFlagPadded) != 0) {
        const size_t pad_len = frame.payload[0];
        start = 1;
        if (pad_len > end - start) {
            return {};
        }
        end -= pad_len;
    }
    return std::span<const uint8_t>(frame.payload.data() + start, end - start);
}

[[nodiscard]] std::optional<std::span<const uint8_t>> H2HeaderBlockFragment(
    const H2Frame& frame) {
    size_t start = 0;
    size_t end = frame.payload.size();
    if ((frame.flags & kFlagPadded) != 0) {
        if (frame.payload.empty()) {
            return std::nullopt;
        }
        const size_t pad_len = frame.payload[0];
        start = 1;
        if (pad_len > end - start) {
            return std::nullopt;
        }
        end -= pad_len;
    }
    if ((frame.flags & kFlagPriority) != 0) {
        if (end - start < 5) {
            return std::nullopt;
        }
        start += 5;
    }
    return std::span<const uint8_t>(frame.payload.data() + start, end - start);
}

struct HpackHeaderField {
    memory::ThreadLocalString name;
    memory::ThreadLocalString value;
};

// Connection-scoped HPACK decoder (RFC 7541). A failed Decode leaves the
// dynamic table unusable; callers must end the connection.
class HpackDecoder final : public memory::ThreadAllocated {
public:
    using HeaderFields = memory::ThreadLocalVector<HpackHeaderField>;

    std::optional<HeaderFields> Decode(std::span<const uint8_t> block) {
        HeaderFields fields;
        size_t header_list_size = 0;
        const auto append_field = [&](HpackHeaderField field) {
            const size_t field_size =
                field.name.size() + field.value.size() + 32;
            if (fields.size() >= kHpackMaxHeaderFields ||
                field_size > kHpackMaxHeaderListSize - header_list_size) {
                return false;
            }
            header_list_size += field_size;
            fields.push_back(std::move(field));
            return true;
        };
        size_t offset = 0;
        bool allow_dynamic_resize = true;
        while (offset < block.size()) {
            const uint8_t first = block[offset];
            if ((first & 0x80) != 0) {
                allow_dynamic_resize = false;
                const auto index = ReadInteger(block, offset, 7);
                const auto field = index ? Lookup(*index) : std::nullopt;
                if (!field ||
                    !append_field(HpackHeaderField{
                        memory::ThreadLocalString(field->name),
                        memory::ThreadLocalString(field->value)})) {
                    return std::nullopt;
                }
                continue;
            }
            if ((first & 0x40) != 0) {
                allow_dynamic_resize = false;
                auto field = ReadLiteral(block, offset, 6);
                if (!field) {
                    return std::nullopt;
                }
                AddDynamic(*field);
                if (!append_field(std::move(*field))) {
                    return std::nullopt;
                }
                continue;
            }
            if ((first & 0x20) != 0) {
                if (!allow_dynamic_resize) {
                    return std::nullopt;
                }
                auto size = ReadInteger(block, offset, 5);
                if (!size || !ResizeDynamic(*size)) {
                    return std::nullopt;
                }
                continue;
            }
            allow_dynamic_resize = false;
            auto field = ReadLiteral(block, offset, 4);
            if (!field || !append_field(std::move(*field))) {
                return std::nullopt;
            }
        }
        return fields;
    }

    void Clear() noexcept {
        dynamic_table_.clear();
        dynamic_size_ = 0;
    }

private:
    struct FieldView {
        std::string_view name;
        std::string_view value;
    };

    static constexpr std::array<FieldView, 61> kStaticTable{{
        {":authority", ""},
        {":method", "GET"},
        {":method", "POST"},
        {":path", "/"},
        {":path", "/index.html"},
        {":scheme", "http"},
        {":scheme", "https"},
        {":status", "200"},
        {":status", "204"},
        {":status", "206"},
        {":status", "304"},
        {":status", "400"},
        {":status", "404"},
        {":status", "500"},
        {"accept-charset", ""},
        {"accept-encoding", "gzip, deflate"},
        {"accept-language", ""},
        {"accept-ranges", ""},
        {"accept", ""},
        {"access-control-allow-origin", ""},
        {"age", ""},
        {"allow", ""},
        {"authorization", ""},
        {"cache-control", ""},
        {"content-disposition", ""},
        {"content-encoding", ""},
        {"content-language", ""},
        {"content-length", ""},
        {"content-location", ""},
        {"content-range", ""},
        {"content-type", ""},
        {"cookie", ""},
        {"date", ""},
        {"etag", ""},
        {"expect", ""},
        {"expires", ""},
        {"from", ""},
        {"host", ""},
        {"if-match", ""},
        {"if-modified-since", ""},
        {"if-none-match", ""},
        {"if-range", ""},
        {"if-unmodified-since", ""},
        {"last-modified", ""},
        {"link", ""},
        {"location", ""},
        {"max-forwards", ""},
        {"proxy-authenticate", ""},
        {"proxy-authorization", ""},
        {"range", ""},
        {"referer", ""},
        {"refresh", ""},
        {"retry-after", ""},
        {"server", ""},
        {"set-cookie", ""},
        {"strict-transport-security", ""},
        {"transfer-encoding", ""},
        {"user-agent", ""},
        {"vary", ""},
        {"via", ""},
        {"www-authenticate", ""},
    }};

    static constexpr std::array<uint32_t, 256> kHpackHuffmanCodes{{
        0x1ff8, 0x7fffd8, 0xfffffe2, 0xfffffe3, 0xfffffe4, 0xfffffe5, 0xfffffe6, 0xfffffe7,
        0xfffffe8, 0xffffea, 0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb, 0xfffffec,
        0xfffffed, 0xfffffee, 0xfffffef, 0xffffff0, 0xffffff1, 0xffffff2, 0x3ffffffe, 0xffffff3,
        0xffffff4, 0xffffff5, 0xffffff6, 0xffffff7, 0xffffff8, 0xffffff9, 0xffffffa, 0xffffffb,
        0x14, 0x3f8, 0x3f9, 0xffa, 0x1ff9, 0x15, 0xf8, 0x7fa,
        0x3fa, 0x3fb, 0xf9, 0x7fb, 0xfa, 0x16, 0x17, 0x18,
        0x0, 0x1, 0x2, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x5c, 0xfb, 0x7ffc, 0x20, 0xffb, 0x3fc,
        0x1ffa, 0x21, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
        0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72,
        0xfc, 0x73, 0xfd, 0x1ffb, 0x7fff0, 0x1ffc, 0x3ffc, 0x22,
        0x7ffd, 0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26,
        0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2a, 0x7,
        0x2b, 0x76, 0x2c, 0x8, 0x9, 0x2d, 0x77, 0x78,
        0x79, 0x7a, 0x7b, 0x7ffe, 0x7fc, 0x3ffd, 0x1ffd, 0xffffffc,
        0xfffe6, 0x3fffd2, 0xfffe7, 0xfffe8, 0x3fffd3, 0x3fffd4, 0x3fffd5, 0x7fffd9,
        0x3fffd6, 0x7fffda, 0x7fffdb, 0x7fffdc, 0x7fffdd, 0x7fffde, 0xffffeb, 0x7fffdf,
        0xffffec, 0xffffed, 0x3fffd7, 0x7fffe0, 0xffffee, 0x7fffe1, 0x7fffe2, 0x7fffe3,
        0x7fffe4, 0x1fffdc, 0x3fffd8, 0x7fffe5, 0x3fffd9, 0x7fffe6, 0x7fffe7, 0xffffef,
        0x3fffda, 0x1fffdd, 0xfffe9, 0x3fffdb, 0x3fffdc, 0x7fffe8, 0x7fffe9, 0x1fffde,
        0x7fffea, 0x3fffdd, 0x3fffde, 0xfffff0, 0x1fffdf, 0x3fffdf, 0x7fffeb, 0x7fffec,
        0x1fffe0, 0x1fffe1, 0x3fffe0, 0x1fffe2, 0x7fffed, 0x3fffe1, 0x7fffee, 0x7fffef,
        0xfffea, 0x3fffe2, 0x3fffe3, 0x3fffe4, 0x7ffff0, 0x3fffe5, 0x3fffe6, 0x7ffff1,
        0x3ffffe0, 0x3ffffe1, 0xfffeb, 0x7fff1, 0x3fffe7, 0x7ffff2, 0x3fffe8, 0x1ffffec,
        0x3ffffe2, 0x3ffffe3, 0x3ffffe4, 0x7ffffde, 0x7ffffdf, 0x3ffffe5, 0xfffff1, 0x1ffffed,
        0x7fff2, 0x1fffe3, 0x3ffffe6, 0x7ffffe0, 0x7ffffe1, 0x3ffffe7, 0x7ffffe2, 0xfffff2,
        0x1fffe4, 0x1fffe5, 0x3ffffe8, 0x3ffffe9, 0xffffffd, 0x7ffffe3, 0x7ffffe4, 0x7ffffe5,
        0xfffec, 0xfffff3, 0xfffed, 0x1fffe6, 0x3fffe9, 0x1fffe7, 0x1fffe8, 0x7ffff3,
        0x3fffea, 0x3fffeb, 0x1ffffee, 0x1ffffef, 0xfffff4, 0xfffff5, 0x3ffffea, 0x7ffff4,
        0x3ffffeb, 0x7ffffe6, 0x3ffffec, 0x3ffffed, 0x7ffffe7, 0x7ffffe8, 0x7ffffe9, 0x7ffffea,
        0x7ffffeb, 0xffffffe, 0x7ffffec, 0x7ffffed, 0x7ffffee, 0x7ffffef, 0x7fffff0, 0x3ffffee,
    }};

    static constexpr std::array<uint8_t, 256> kHpackHuffmanCodeLen{{
        13, 23, 28, 28, 28, 28, 28, 28,
        28, 24, 30, 28, 28, 30, 28, 28,
        28, 28, 28, 28, 28, 28, 30, 28,
        28, 28, 28, 28, 28, 28, 28, 28,
        6, 10, 10, 12, 13, 6, 8, 11,
        10, 10, 8, 11, 8, 6, 6, 6,
        5, 5, 5, 6, 6, 6, 6, 6,
        6, 6, 7, 8, 15, 6, 12, 10,
        13, 6, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7,
        8, 7, 8, 13, 19, 13, 14, 6,
        15, 5, 6, 5, 6, 5, 6, 6,
        6, 5, 7, 7, 6, 6, 6, 5,
        6, 7, 6, 5, 5, 6, 7, 7,
        7, 7, 7, 15, 11, 14, 13, 28,
        20, 22, 20, 20, 22, 22, 22, 23,
        22, 23, 23, 23, 23, 23, 24, 23,
        24, 24, 22, 23, 24, 23, 23, 23,
        23, 21, 22, 23, 22, 23, 23, 24,
        22, 21, 20, 22, 22, 23, 23, 21,
        23, 22, 22, 24, 21, 22, 23, 23,
        21, 21, 22, 21, 23, 22, 23, 23,
        20, 22, 22, 22, 23, 22, 22, 23,
        26, 26, 20, 19, 22, 23, 22, 25,
        26, 26, 26, 27, 27, 26, 24, 25,
        19, 21, 26, 27, 27, 26, 27, 24,
        21, 21, 26, 26, 28, 27, 27, 27,
        20, 24, 20, 21, 22, 21, 21, 23,
        22, 22, 25, 25, 24, 24, 26, 23,
        26, 27, 26, 26, 27, 27, 27, 27,
        27, 28, 27, 27, 27, 27, 27, 26,
    }};

    struct HuffmanTrieNode {
        uint16_t child[2];
        uint16_t symbol_plus_one;
    };

    static constexpr auto kHpackHuffmanTrie = []() consteval {
        std::array<HuffmanTrieNode, 520> trie{};
        uint16_t next_node = 1;
        for (size_t sym = 0; sym < kHpackHuffmanCodes.size(); ++sym) {
            const uint32_t code = kHpackHuffmanCodes[sym];
            const uint8_t len = kHpackHuffmanCodeLen[sym];
            uint16_t node = 0;
            for (int bit = static_cast<int>(len) - 1; bit >= 0; --bit) {
                const uint8_t b = static_cast<uint8_t>((code >> bit) & 0x1u);
                if (trie[node].child[b] == 0) {
                    trie[node].child[b] = next_node++;
                }
                node = trie[node].child[b];
            }
            trie[node].symbol_plus_one = static_cast<uint16_t>(sym + 1);
        }
        return trie;
    }();

    static std::optional<uint32_t> ReadInteger(std::span<const uint8_t> block,
                                               size_t& offset,
                                               uint8_t prefix_bits) {
        if (offset >= block.size()) {
            return std::nullopt;
        }
        const uint8_t mask = static_cast<uint8_t>((1u << prefix_bits) - 1u);
        uint32_t value = block[offset++] & mask;
        if (value < mask) {
            return value;
        }
        uint32_t shift = 0;
        while (offset < block.size() && shift <= 28) {
            const uint8_t byte = block[offset++];
            const uint32_t add = static_cast<uint32_t>(byte & 0x7f) << shift;
            if (value > std::numeric_limits<uint32_t>::max() - add) {
                return std::nullopt;
            }
            value += add;
            if ((byte & 0x80) == 0) {
                return value;
            }
            shift += 7;
        }
        return std::nullopt;
    }

    static std::optional<memory::ThreadLocalString> DecodeHuffman(
        std::span<const uint8_t> data) {
        memory::ThreadLocalString out;
        out.reserve(data.size());
        uint16_t node = 0;
        uint32_t code = 0;
        uint8_t bits = 0;
        for (uint8_t byte : data) {
            for (int bit = 7; bit >= 0; --bit) {
                const uint8_t b = static_cast<uint8_t>((byte >> bit) & 0x1u);
                code = (code << 1) | b;
                ++bits;
                node = kHpackHuffmanTrie[node].child[b];
                if (node == 0) {
                    return std::nullopt;
                }
                if (kHpackHuffmanTrie[node].symbol_plus_one != 0) {
                    out.push_back(static_cast<char>(
                        kHpackHuffmanTrie[node].symbol_plus_one - 1));
                    node = 0;
                    code = 0;
                    bits = 0;
                }
            }
        }
        // RFC 7541 5.2: padding is under 8 bits of the EOS prefix (all ones).
        if (bits > 7) {
            return std::nullopt;
        }
        if (bits > 0 && code != ((1u << bits) - 1u)) {
            return std::nullopt;
        }
        return out;
    }

    static std::optional<memory::ThreadLocalString> ReadString(
        std::span<const uint8_t> block,
        size_t& offset) {
        if (offset >= block.size()) {
            return std::nullopt;
        }
        const bool huffman = (block[offset] & 0x80) != 0;
        auto len = ReadInteger(block, offset, 7);
        if (!len || *len > block.size() - offset) {
            return std::nullopt;
        }
        std::span<const uint8_t> encoded(block.data() + offset, *len);
        offset += *len;
        if (huffman) {
            return DecodeHuffman(encoded);
        }
        return memory::ThreadLocalString(
            unsafe::ptr_cast<const char>(encoded.data()),
            encoded.size());
    }

    // Static entries first, then the dynamic table newest-first (RFC 7541 2.3.3).
    std::optional<FieldView> Lookup(uint32_t index) const {
        if (index == 0) {
            return std::nullopt;
        }
        if (index <= kStaticTable.size()) {
            return kStaticTable[index - 1];
        }
        const uint32_t dynamic_index =
            index - static_cast<uint32_t>(kStaticTable.size()) - 1;
        if (dynamic_index >= dynamic_table_.size()) {
            return std::nullopt;
        }
        const auto& field = dynamic_table_[dynamic_index];
        return FieldView{field.name, field.value};
    }

    std::optional<HpackHeaderField> ReadLiteral(std::span<const uint8_t> block,
                                                size_t& offset,
                                                uint8_t prefix_bits) const {
        auto name_index = ReadInteger(block, offset, prefix_bits);
        if (!name_index) {
            return std::nullopt;
        }
        memory::ThreadLocalString name;
        if (*name_index == 0) {
            auto decoded = ReadString(block, offset);
            if (!decoded) {
                return std::nullopt;
            }
            name = std::move(*decoded);
        } else {
            const auto indexed = Lookup(*name_index);
            if (!indexed) {
                return std::nullopt;
            }
            name.assign(indexed->name);
        }
        auto value = ReadString(block, offset);
        if (!value) {
            return std::nullopt;
        }
        return HpackHeaderField{std::move(name), std::move(*value)};
    }

    void AddDynamic(const HpackHeaderField& field) {
        const size_t entry_size = field.name.size() + field.value.size() + 32;
        if (entry_size > dynamic_max_size_) {
            dynamic_table_.clear();
            dynamic_size_ = 0;
            return;
        }
        dynamic_table_.push_front(field);
        dynamic_size_ += entry_size;
        EvictDynamic();
    }

    [[nodiscard]] bool ResizeDynamic(uint32_t size) {
        if (size > kHpackMaxDynamicTableSize) {
            return false;
        }
        dynamic_max_size_ = size;
        EvictDynamic();
        return true;
    }

    void EvictDynamic() {
        while (dynamic_size_ > dynamic_max_size_ && !dynamic_table_.empty()) {
            const auto& field = dynamic_table_.back();
            dynamic_size_ -= field.name.size() + field.value.size() + 32;
            dynamic_table_.pop_back();
        }
    }

    memory::ThreadLocalDeque<HpackHeaderField> dynamic_table_;
    size_t dynamic_size_ = 0;
    size_t dynamic_max_size_ = kHpackMaxDynamicTableSize;
};

// Reads the CONTINUATION frames completing `frame` (RFC 9113 6.10) and
// decodes the whole block. Every block is decoded, including rejected
// streams', to keep the connection-wide HPACK state in sync. Every failure
// here is a connection error: the HPACK state can no longer be trusted.
net::awaitable<tl::expected<HpackDecoder::HeaderFields, H2Error>> ReadH2HeaderFields(
    AsyncStream& stream, HpackDecoder& decoder, H2Frame frame) {
    const uint32_t stream_id = frame.stream_id;
    const auto fragment = H2HeaderBlockFragment(frame);
    if (!fragment) {
        // RFC 9113 6.2: padding at least as long as the payload.
        co_return tl::unexpected(H2Error::Protocol);
    }
    if (fragment->size() > kHttp2MaxHeaderBlockSize) {
        co_return tl::unexpected(H2Error::ExcessiveLoad);
    }
    // RFC 7541 2.3 / RFC 9113 4.3: undecodable block is COMPRESSION_ERROR.
    const auto decode = [&decoder](std::span<const uint8_t> block)
        -> tl::expected<HpackDecoder::HeaderFields, H2Error> {
        auto fields = decoder.Decode(block);
        if (!fields) return tl::unexpected(H2Error::Compression);
        return std::move(*fields);
    };
    if ((frame.flags & kFlagEndHeaders) != 0) {
        co_return decode(*fragment);
    }
    memory::ByteVector block(fragment->begin(), fragment->end());
    while (true) {
        auto continuation = co_await ReadH2Frame(stream);
        if (!continuation ||
            continuation->type != H2FrameType::CONTINUATION ||
            continuation->stream_id != stream_id) {
            co_return tl::unexpected(H2Error::Protocol);
        }
        if (continuation->payload.size() > kHttp2MaxHeaderBlockSize - block.size()) {
            co_return tl::unexpected(H2Error::ExcessiveLoad);
        }
        block.insert(block.end(), continuation->payload.begin(), continuation->payload.end());
        if ((continuation->flags & kFlagEndHeaders) != 0) {
            break;
        }
    }
    co_return decode(block);
}

struct H2RequestHeaders {
    memory::ThreadLocalString method;
    memory::ThreadLocalString path;
    memory::ThreadLocalString authority;
    InboundTransportMetadata metadata;
};

// RFC 9113 8.3: each request pseudo-header appears at most once, none in
// trailers, and Host must agree with :authority. Ambiguous requests are
// malformed (8.1.1) rather than resolved by field order.
[[nodiscard]] bool AuthorityMatchesHost(std::string_view authority,
                                        std::string_view expected_host) noexcept {
    authority = TrimAscii(authority);
    expected_host = TrimAscii(expected_host);
    if (EqualsAsciiCI(authority, expected_host)) {
        return true;
    }
    const auto strip_port = [](std::string_view value) noexcept {
        if (value.starts_with('[')) {
            const size_t close = value.find(']');
            if (close != std::string_view::npos) {
                return value.substr(0, close + 1);
            }
            return value;
        }
        const size_t colon = value.find(':');
        if (colon != std::string_view::npos &&
            value.find(':', colon + 1) == std::string_view::npos) {
            return value.substr(0, colon);
        }
        return value;
    };
    return strip_port(expected_host) == expected_host &&
           EqualsAsciiCI(strip_port(authority), expected_host);
}

[[nodiscard]] std::optional<H2RequestHeaders> ParseH2RequestHeaders(
    HpackDecoder::HeaderFields fields, std::string_view real_ip_header, bool trailers) {
    H2RequestHeaders request;
    std::optional<memory::ThreadLocalString> host;
    bool has_method = false;
    bool has_path = false;
    bool has_authority = false;
    bool has_scheme = false;
    bool seen_regular = false;
    const auto take_once = [](bool& seen, memory::ThreadLocalString& out,
                              memory::ThreadLocalString& value) {
        if (seen) return false;
        seen = true;
        out = std::move(value);
        return true;
    };
    for (auto& field : fields) {
        const std::string_view name = field.name;
        if (name.starts_with(':')) {
            if (trailers || seen_regular) return std::nullopt;
            bool accepted = false;
            if (name == ":method") {
                accepted = take_once(has_method, request.method, field.value);
            } else if (name == ":path") {
                accepted = take_once(has_path, request.path, field.value);
            } else if (name == ":authority") {
                accepted = take_once(has_authority, request.authority, field.value);
            } else if (name == ":scheme") {
                if (!has_scheme && !field.value.empty()) {
                    has_scheme = true;
                    accepted = true;
                }
            }
            if (!accepted) return std::nullopt;
        } else {
            if (!IsValidHttp2HeaderName(name)) return std::nullopt;
            seen_regular = true;
            if (name == "host") {
                if (host) return std::nullopt;
                host = std::move(field.value);
            } else if (!trailers && !real_ip_header.empty() &&
                       EqualsAsciiCI(name, real_ip_header)) {
                if (request.metadata.real_ip.empty()) {
                    const std::string_view value(field.value);
                    const std::string_view real_ip =
                        TrimAscii(value.substr(0, value.find(',')));
                    if (!real_ip.empty()) {
                        request.metadata.real_ip.assign(real_ip);
                        request.metadata.real_ip_header.assign(real_ip_header);
                    }
                }
            }
        }
    }
    if (host) {
        if (has_authority && !EqualsAsciiCI(request.authority, *host)) return std::nullopt;
        if (!has_authority) request.authority = std::move(*host);
    }
    if (!trailers && (request.method.empty() || request.path.empty() || !has_scheme)) {
        return std::nullopt;
    }
    return request;
}

// Client half of one request on a dedicated connection. Frames are pulled on
// demand: the reader, or a writer short of flow-control credit, pumps one frame
// at a time while the other side waits for that pump. Received DATA is charged
// against the receive windows this client advertised and queues for the
// reader; its credit returns to the peer only when the reader takes it, so the
// queue never outgrows those windows (RFC 9113 6.9.1).
class Http2ClientStream final : public AsyncStream,
                                private transport::CancellationSubscription {
public:
    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::ShutdownPeerWrite;
    }

    Http2ClientStream(std::unique_ptr<AsyncStream> inner,
                      uint32_t stream_id,
                      H2PayloadCodec payload_codec,
                      uint32_t local_initial_window,
                      uint32_t conn_recv_window = H2SendWindow::kDefault,
                      bool write_closed = false)
        : inner_(std::move(inner))
        , stream_id_(stream_id)
        , payload_codec_(payload_codec)
        , conn_recv_window_(std::max<int64_t>(conn_recv_window, H2SendWindow::kDefault))
        , stream_recv_window_(std::max<int64_t>(local_initial_window, H2SendWindow::kDefault))
        , local_initial_window_(local_initial_window)
        , write_closed_(write_closed) {
        if (inner_) {
            (void)inner_->DeferWriteCancellation();
            Resubscribe(inner_->Cancellation());
        }
    }

    ~Http2ClientStream() noexcept override {
        Unsubscribe();
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        if (buffer.size() == 0 || !co_await EnsureReadablePayload()) {
            co_return 0;
        }
        co_return ConsumeReadablePayload(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (payload_codec_ == H2PayloadCodec::RawData) {
            co_await SendData(std::span<const net::const_buffer>(&buffer, 1));
            co_return buffer.size();
        }
        const auto* data = static_cast<const uint8_t*>(buffer.data());
        co_await SendGrpcHunkMessage(std::span<const uint8_t>(data, buffer.size()));
        co_return buffer.size();
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (!co_await EnsureReadablePayload()) {
            co_return buf::MultiBuffer{};
        }
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            throw std::bad_alloc();
        }
        const size_t n = ConsumeReadablePayload(
            net::buffer(buffer->Tail().data(), buffer->Available()));
        if (n == 0) {
            co_return buf::MultiBuffer{};
        }
        buffer->Produce(static_cast<uint32_t>(n));
        co_return buf::MultiBuffer{std::move(buffer)};
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (payload_codec_ == H2PayloadCodec::RawData) {
            ConstBufferSpanBuilder<16> payloads;
            payloads.AppendMultiBuffer(mb);
            try {
                if (!payloads.empty()) co_await SendData(payloads.Span());
            } catch (...) {
                mb.clear();
                throw;
            }
            mb.clear();
            co_return;
        }

        for (buf::Buffer*& buffer : mb) {
            if (!buffer) {
                continue;
            }
            if (!buffer->IsEmpty()) {
                try {
                    co_await SendGrpcHunkMessage(buffer->Bytes());
                } catch (...) {
                    mb.clear();
                    throw;
                }
            }
            mb.FreeSlot(buffer);
        }
        mb.clear();
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (payload_codec_ == H2PayloadCodec::RawData) {
            co_await SendData(buffers);
            co_return;
        }
        for (const auto& buffer : buffers) {
            if (buffer.size() == 0) {
                continue;
            }
            const auto* data = static_cast<const uint8_t*>(buffer.data());
            co_await SendGrpcHunkMessage(std::span<const uint8_t>(data, buffer.size()));
        }
    }

    void ShutdownRead() override {
        read_closed_ = true;
        hunk_.Clear();
        ReleaseDataFrame();
        received_.clear();
    }

    void ShutdownWrite() override {
        write_closed_ = true;
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        auto lease = write_gate_.TryAcquire();
        if (!lease) lease = co_await AcquireWrite();
        if (write_closed_) {
            co_return;
        }
        write_closed_ = true;
        (void)co_await WriteH2Frame(*inner_, H2FrameType::DATA, kFlagEndStream, stream_id_);
    }

    void Cancel() noexcept override {
        AbortPumpWaits();
        inner_->Cancel();
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return inner_->Cancellation();
    }

    void Close() override {
        Unsubscribe();
        write_gate_.Cancel();
        AbortPumpWaits();
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        hunk_.Clear();
        ReleaseDataFrame();
        received_.clear();
        inner_->Close();
    }

    void CloseAbortive() override {
        Unsubscribe();
        write_gate_.Cancel();
        AbortPumpWaits();
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        hunk_.Clear();
        ReleaseDataFrame();
        received_.clear();
        inner_->CloseAbortive();
    }

    int NativeHandle() const override {
        return inner_->NativeHandle();
    }

    bool IsOpen() const override {
        return !closed_ && inner_->IsOpen();
    }

protected:
    TcpStream* BaseTcpStream() override {
        return BaseTcpStreamOf(*inner_);
    }

    const TcpStream* BaseTcpStream() const override {
        return BaseTcpStreamOf(*inner_);
    }

private:
    // DATA payload taken off the wire; [offset, end) is body, and the whole
    // payload (padding included) is the flow-controlled length (6.1).
    struct ReceivedData {
        memory::ByteVector payload;
        size_t offset = 0;
        size_t end = 0;
        uint32_t flow_bytes = 0;
    };

    void ReleaseDataFrame() noexcept {
        memory::ByteVector{data_frame_.get_allocator()}.swap(data_frame_);
        data_offset_ = 0;
        data_end_ = 0;
    }

    [[nodiscard]] size_t ConsumeReadablePayload(net::mutable_buffer buffer) noexcept {
        auto* out = static_cast<uint8_t*>(buffer.data());
        const size_t capacity = buffer.size();
        if (payload_codec_ == H2PayloadCodec::RawData) {
            const size_t n = std::min(capacity, data_end_ - data_offset_);
            std::memcpy(out, data_frame_.data() + data_offset_, n);
            data_offset_ += n;
            if (data_offset_ >= data_end_) {
                ReleaseDataFrame();
            }
            return n;
        }
        const auto payload = hunk_.Payload();
        const size_t n = std::min(capacity, payload.size());
        std::memcpy(out, payload.data(), n);
        hunk_.Consume(n);
        return n;
    }

    net::awaitable<bool> WaitForDataFrame() {
        while (data_offset_ >= data_end_) {
            ReleaseDataFrame();
            if (!co_await TakeReceivedData()) co_return false;
        }
        co_return true;
    }

    net::awaitable<bool> EnsureReadablePayload() {
        if (payload_codec_ == H2PayloadCodec::RawData) co_return co_await WaitForDataFrame();
        while (hunk_.Payload().empty()) {
            if (!co_await WaitForDataFrame()) {
                if (!hunk_.AtMessageBoundary()) ThrowHttp2StreamError("truncated gRPC message");
                co_return false;
            }
            const auto bytes = std::span<const uint8_t>(data_frame_).subspan(
                data_offset_, data_end_ - data_offset_);
            const auto consumed = hunk_.Feed(bytes);
            if (!consumed) ThrowHttp2StreamError(consumed.error().data());
            data_offset_ += *consumed;
            if (data_offset_ >= data_end_) ReleaseDataFrame();
        }
        co_return true;
    }

    net::awaitable<AsyncWriteGate::Lease> AcquireWrite() {
        auto lease = co_await write_gate_.Acquire();
        if (!lease) {
            const auto cancellation = co_await net::this_coro::cancellation_state;
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted, "HTTP/2 write cancelled");
            }
            ThrowHttp2StreamError("HTTP/2 write cancelled");
        }
        co_return lease;
    }

    net::awaitable<void> WriteControlFrame(H2FrameType type,
                                           uint8_t flags,
                                           uint32_t stream_id,
                                           std::span<const uint8_t> payload = {}) {
        auto lease = write_gate_.TryAcquire();
        if (!lease) lease = co_await AcquireWrite();
        (void)co_await WriteH2Frame(*inner_, type, flags, stream_id, payload);
    }

    // Sends body bytes as DATA frames within the peer's connection and stream
    // windows (RFC 9113 6.9.1). The physical write gate is held per frame, so
    // a reader pumping frames can still answer SETTINGS and PING meanwhile.
    net::awaitable<void> SendData(std::span<const net::const_buffer> buffers) {
        H2DataCursor cursor(buffers);
        const auto cancellation = co_await net::this_coro::cancellation_state;
        while (cursor.Remaining() != 0) {
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            auto lease = write_gate_.TryAcquire();
            if (!lease) lease = co_await AcquireWrite();
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            if (write_closed_) ThrowHttp2StreamError("HTTP/2 write on closed stream");
            const size_t credit = std::min({cursor.Remaining(),
                                            kHttp2MaxFramePayload,
                                            conn_send_window_.Available(),
                                            stream_send_window_.Available()});
            if (credit == 0) {
                lease.Reset();
                co_await AdvanceFrames(writer_wake_, writer_waiting_);
                continue;
            }
            const auto payload = cursor.Next(credit);
            const size_t size = H2DataCursor::Size(payload);
            conn_send_window_.Consume(size);
            stream_send_window_.Consume(size);
            if (!co_await WriteH2FrameBuffers(
                    *inner_, H2FrameType::DATA, 0, stream_id_, payload)) {
                ThrowHttp2StreamError("HTTP/2 DATA write failed");
            }
        }
    }

    net::awaitable<void> SendGrpcHunkMessage(std::span<const uint8_t> data) {
        do {
            const size_t size = std::min(data.size(), kGrpcHunkRecordPayloadLimit);
            const GrpcHunkPrefix prefix(size);
            const std::array<net::const_buffer, 2> record{
                prefix.Buffer(), net::buffer(data.data(), size)};
            co_await SendData(record);
            data = data.subspan(size);
        } while (!data.empty());
    }

    // Moves the next received DATA payload to the read position and returns
    // its flow-control credit to the peer.
    net::awaitable<bool> TakeReceivedData() {
        while (received_.empty()) {
            if (read_closed_ || input_done_) co_return false;
            co_await AdvanceFrames(reader_wake_, reader_waiting_);
        }
        if (read_closed_) co_return false;
        AsyncWriteGate::Lease lease;
        if (received_.front().flow_bytes != 0) {
            lease = write_gate_.TryAcquire();
            if (!lease) lease = co_await AcquireWrite();
            if (read_closed_ || received_.empty()) co_return false;
        }
        auto& front = received_.front();
        const uint32_t credit = front.flow_bytes;
        data_frame_ = std::move(front.payload);
        data_offset_ = front.offset;
        data_end_ = front.end;
        received_.pop_front();

        if (credit != 0) {
            co_await SendWindowUpdate(*inner_, 0, credit);
            conn_recv_window_ += credit;
            // After END_STREAM the peer sends no more DATA on this stream.
            if (!input_done_) {
                co_await SendWindowUpdate(*inner_, stream_id_, credit);
                stream_recv_window_ += credit;
            }
        }
        co_return true;
    }

    // Pumps one frame, or waits for the pump another operation is running.
    net::awaitable<void> AdvanceFrames(std::optional<SignalChannel>& wake,
                                       bool& waiting) {
        if (pump_failure_) std::rethrow_exception(pump_failure_);
        if (!pumping_) {
            co_await PumpFrame();
            co_return;
        }
        const uint64_t epoch = abort_epoch_;
        if (!wake) wake.emplace(co_await net::this_coro::executor, 1);
        else wake->reset();
        waiting = true;
        struct WaitScope {
            SignalChannel& channel;
            bool& waiting;
            ~WaitScope() noexcept {
                waiting = false;
                channel.reset();
            }
        } scope{*wake, waiting};
        auto [ec] = co_await wake->async_receive(net::as_tuple(net::use_awaitable));
        if (ec || epoch != abort_epoch_) {
            throw IoSystemError(io_error::operation_aborted, "HTTP/2 frame wait aborted");
        }
        if (pump_failure_) std::rethrow_exception(pump_failure_);
    }

    // A failed pump may have consumed part of a frame, so its error is kept
    // and rethrown to every later pump user instead of reading a torn stream.
    net::awaitable<void> PumpFrame() {
        pumping_ = true;
        std::exception_ptr failure;
        std::exception_ptr stored_failure;
        bool store_failure = true;
        bool frame_read = false;
        try {
            std::optional<H2Frame> frame;
            try {
                frame = co_await ReadH2Frame(*inner_);
            } catch (const IoSystemError& error) {
                if (error.code() == io_error::operation_aborted) {
                    store_failure = false;
                }
                throw;
            }
            if (!frame) {
                throw IoSystemError(io_error::connection_reset,
                                    "HTTP/2 peer closed before END_STREAM");
            }
            frame_read = true;
            co_await DispatchFrame(std::move(*frame));
        } catch (const IoSystemError& error) {
            failure = std::current_exception();
            stored_failure = failure;
            if (store_failure || frame_read) {
                inner_->CloseAbortive();
            }
            if (frame_read && error.code() == io_error::operation_aborted) {
                stored_failure = std::make_exception_ptr(
                    IoSystemError(io_error::connection_reset,
                                  "cancelled mid-HTTP/2 frame dispatch"));
            }
        } catch (...) {
            failure = std::current_exception();
            stored_failure = failure;
            if (store_failure || frame_read) {
                inner_->CloseAbortive();
            }
        }
        pumping_ = false;
        if (failure && store_failure) pump_failure_ = stored_failure;
        WakePumpWaiters();
        if (failure) std::rethrow_exception(failure);
    }

    void WakePumpWaiters() noexcept {
        if (std::exchange(reader_waiting_, false) && reader_wake_) {
            (void)reader_wake_->try_send(IoErrorCode{});
        }
        if (std::exchange(writer_waiting_, false) && writer_wake_) {
            (void)writer_wake_->try_send(IoErrorCode{});
        }
    }

    void AbortPumpWaits() noexcept {
        ++abort_epoch_;
        WakePumpWaiters();
    }

    void OnCancellation(transport::Cancellation event) noexcept override {
        AbortPumpWaits();
        if (event.terminal) {
            write_gate_.Cancel();
        } else if (inner_) {
            Resubscribe(inner_->Cancellation());
        }
    }

    net::awaitable<void> DispatchFrame(H2Frame frame) {
        switch (frame.type) {
        case H2FrameType::SETTINGS:
            co_await ReceiveSettings(frame);
            break;
        case H2FrameType::PING:
            if (frame.stream_id != 0) {
                co_await FailConnection(H2Error::Protocol);
                ThrowHttp2StreamError("HTTP/2 PING on non-zero stream");
            }
            if (frame.payload.size() != 8) {
                co_await FailConnection(H2Error::FrameSize);
                ThrowHttp2StreamError("invalid HTTP/2 PING frame size");
            }
            if ((frame.flags & kFlagAck) == 0) {
                co_await WriteControlFrame(H2FrameType::PING, kFlagAck, 0, frame.payload);
            }
            break;
        case H2FrameType::WINDOW_UPDATE:
            co_await ReceiveWindowUpdate(frame);
            break;
        case H2FrameType::HEADERS:
            if (frame.stream_id != stream_id_) {
                co_await FailConnection(H2Error::Protocol);
                ThrowHttp2StreamError("HTTP/2 HEADERS on unexpected stream");
            }
            if (!response_headers_received_) {
                if (co_await ReadResponseHeaders(std::move(frame))) {
                    input_done_ = true;
                    response_decoder_.Clear();
                }
            } else {
                co_await ReadResponseTrailers(std::move(frame));
                input_done_ = true;
                response_decoder_.Clear();
            }
            break;
        case H2FrameType::DATA:
            co_await ReceiveData(std::move(frame));
            break;
        case H2FrameType::PRIORITY:
            if (frame.stream_id == 0) {
                co_await FailConnection(H2Error::Protocol);
                ThrowHttp2StreamError("HTTP/2 PRIORITY on stream 0");
            }
            if (frame.payload.size() != 5) {
                co_await FailConnection(H2Error::FrameSize);
                ThrowHttp2StreamError("invalid HTTP/2 PRIORITY frame size");
            }
            break;
        case H2FrameType::RST_STREAM:
            if (frame.stream_id == 0) {
                co_await FailConnection(H2Error::Protocol);
                ThrowHttp2StreamError("HTTP/2 RST_STREAM on stream 0");
            }
            if (frame.payload.size() != 4) {
                co_await FailConnection(H2Error::FrameSize);
                ThrowHttp2StreamError("invalid HTTP/2 RST_STREAM frame size");
            }
            if (frame.stream_id != stream_id_) {
                co_await FailConnection(H2Error::Protocol);
                ThrowHttp2StreamError("HTTP/2 RST_STREAM on idle stream");
            }
            ThrowHttp2StreamError("HTTP/2 stream reset by peer");
        case H2FrameType::GOAWAY:
            ThrowHttp2StreamError("HTTP/2 connection closed by peer");
        case H2FrameType::CONTINUATION:
        case H2FrameType::PUSH_PROMISE:
            co_await FailConnection(H2Error::Protocol);
            ThrowHttp2StreamError("unexpected HTTP/2 frame");
        default:
            break;
        }
    }

    // Applies SETTINGS_INITIAL_WINDOW_SIZE to the open stream (6.9.2) before
    // acknowledging. Frames never exceed the 16 KiB SETTINGS_MAX_FRAME_SIZE
    // floor, so the peer's larger limit needs no tracking.
    net::awaitable<void> ReceiveSettings(const H2Frame& frame) {
        const bool ack = (frame.flags & kFlagAck) != 0;
        if (frame.stream_id != 0) {
            co_await FailConnection(H2Error::Protocol);
            ThrowHttp2StreamError("invalid HTTP/2 SETTINGS frame");
        }
        if (frame.payload.size() % 6 != 0 || (ack && !frame.payload.empty())) {
            co_await FailConnection(H2Error::FrameSize);
            ThrowHttp2StreamError("invalid HTTP/2 SETTINGS frame");
        }
        if (ack) {
            // The peer applied this client's SETTINGS before acknowledging
            // them; DATA it sent earlier used the default stream window.
            if (!local_settings_acked_) {
                local_settings_acked_ = true;
                stream_recv_window_ += static_cast<int64_t>(local_initial_window_) -
                                       std::max<int64_t>(local_initial_window_, H2SendWindow::kDefault);
            }
            co_return;
        }
        const auto initial_window = PeerInitialWindowSetting(frame.payload);
        if (!initial_window) {
            co_await FailConnection(H2Error::FlowControl);
            ThrowHttp2StreamError("HTTP/2 initial window exceeds 2^31-1");
        }
        if (*initial_window) {
            const int64_t delta = static_cast<int64_t>(**initial_window) -
                                  static_cast<int64_t>(peer_initial_window_);
            if (!stream_send_window_.Adjust(delta)) {
                co_await FailConnection(H2Error::FlowControl);
                ThrowHttp2StreamError("HTTP/2 stream window overflow");
            }
            peer_initial_window_ = **initial_window;
        }
        co_await WriteControlFrame(H2FrameType::SETTINGS, kFlagAck, 0);
    }

    net::awaitable<void> ReceiveWindowUpdate(const H2Frame& frame) {
        if (frame.stream_id != 0 && frame.stream_id != stream_id_) {
            co_await FailConnection(H2Error::Protocol);
            ThrowHttp2StreamError("HTTP/2 WINDOW_UPDATE on idle stream");
        }
        const auto increment = WindowUpdateIncrement(frame);
        if (!increment) {
            co_await FailConnection(increment.error());
            ThrowHttp2StreamError("invalid HTTP/2 WINDOW_UPDATE");
        }
        if (frame.stream_id == 0) {
            if (!conn_send_window_.Adjust(*increment)) {
                co_await FailConnection(H2Error::FlowControl);
                ThrowHttp2StreamError("HTTP/2 connection window overflow");
            }
        } else if (frame.stream_id == stream_id_) {
            if (!stream_send_window_.Adjust(*increment)) {
                co_await FailConnection(H2Error::FlowControl);
                ThrowHttp2StreamError("HTTP/2 stream window overflow");
            }
        }
    }

    // The whole DATA payload, padding included, counts against both receive
    // windows (6.1, 6.9.1); exceeding either is a FLOW_CONTROL_ERROR
    // connection error (6.9.1, 5.4.1).
    net::awaitable<void> ReceiveData(H2Frame frame) {
        if (frame.stream_id == 0) {
            co_await FailConnection(H2Error::Protocol);
            ThrowHttp2StreamError("HTTP/2 DATA on stream 0");
        }
        if (frame.stream_id != stream_id_) {
            co_await FailConnection(H2Error::Protocol);
            ThrowHttp2StreamError("HTTP/2 DATA on unexpected stream");
        }
        const auto flow_len = static_cast<int64_t>(frame.payload.size());
        if (flow_len > conn_recv_window_ || flow_len > stream_recv_window_) {
            co_await FailConnection(H2Error::FlowControl);
            ThrowHttp2StreamError("HTTP/2 DATA exceeded the advertised receive window");
        }
        conn_recv_window_ -= flow_len;
        stream_recv_window_ -= flow_len;
        if ((frame.flags & kFlagPadded) != 0 &&
            (frame.payload.empty() || frame.payload.front() >= frame.payload.size())) {
            co_await FailConnection(H2Error::Protocol);
            ThrowHttp2StreamError("invalid HTTP/2 DATA padding");
        }
        if (!response_headers_received_) {
            co_await FailConnection(H2Error::Protocol);
            ThrowHttp2StreamError("HTTP/2 DATA arrived before response headers");
        }
        if (input_done_) {
            co_await FailConnection(H2Error::StreamClosed);
            ThrowHttp2StreamError("HTTP/2 DATA after END_STREAM");
        }
        input_done_ = (frame.flags & kFlagEndStream) != 0;
        if (read_closed_) {
            if (flow_len > 0) {
                auto lease = write_gate_.TryAcquire();
                if (!lease) lease = co_await AcquireWrite();
                conn_recv_window_ += flow_len;
                co_await SendWindowUpdate(*inner_, 0, static_cast<uint32_t>(flow_len));
            }
            co_return;
        }
        if (frame.payload.empty()) {
            co_return;
        }
        const auto data = H2DataPayload(frame);
        if (data.empty()) {
            if (!received_.empty()) {
                received_.back().flow_bytes += static_cast<uint32_t>(flow_len);
            } else if (flow_len > 0) {
                auto lease = write_gate_.TryAcquire();
                if (!lease) lease = co_await AcquireWrite();
                conn_recv_window_ += flow_len;
                co_await SendWindowUpdate(*inner_, 0, static_cast<uint32_t>(flow_len));
                if (!input_done_) {
                    stream_recv_window_ += flow_len;
                    co_await SendWindowUpdate(*inner_, stream_id_, static_cast<uint32_t>(flow_len));
                }
            }
            co_return;
        }
        const size_t offset = static_cast<size_t>(data.data() - frame.payload.data());
        received_.push_back(ReceivedData{
            .payload = std::move(frame.payload),
            .offset = offset,
            .end = offset + data.size(),
            .flow_bytes = static_cast<uint32_t>(flow_len),
        });
    }

    // Reports a connection error to the peer (5.4.1); the caller then fails
    // the stream. Only stream 1 exists, and the peer opens none.
    net::awaitable<void> FailConnection(H2Error error) {
        std::array<uint8_t, 8> payload{};
        StoreU32BE(payload.data() + 4, static_cast<uint32_t>(error));
        co_await WriteControlFrame(H2FrameType::GOAWAY, 0, 0, payload);
    }

    // Returns true when the response already ended the stream.
    net::awaitable<bool> ReadResponseHeaders(H2Frame frame) {
        const bool end_stream = (frame.flags & kFlagEndStream) != 0;
        const auto fields = co_await ReadH2HeaderFields(
            *inner_, response_decoder_, std::move(frame));
        if (!fields) {
            co_await FailConnection(fields.error());
            ThrowHttp2StreamError("invalid HTTP/2 response header block");
        }
        std::string_view status;
        bool has_status = false;
        bool seen_regular = false;
        for (const auto& field : *fields) {
            const std::string_view name = field.name;
            if (name.starts_with(':')) {
                if (seen_regular || name != ":status" || has_status) {
                    co_await FailConnection(H2Error::Protocol);
                    ThrowHttp2StreamError("invalid HTTP/2 response pseudo-headers");
                }
                has_status = true;
                status = field.value;
            } else {
                if (!IsValidHttp2HeaderName(name)) {
                    co_await FailConnection(H2Error::Protocol);
                    ThrowHttp2StreamError("invalid HTTP/2 response header name");
                }
                seen_regular = true;
            }
        }
        const auto is_digit = [](char ch) noexcept {
            return ch >= '0' && ch <= '9';
        };
        if (!has_status || status.size() != 3 ||
            !is_digit(status[0]) || !is_digit(status[1]) || !is_digit(status[2])) {
            co_await FailConnection(H2Error::Protocol);
            ThrowHttp2StreamError("invalid HTTP/2 :status header");
        }
        if (status.front() == '1') {
            if (status == "101" || end_stream) {
                co_await FailConnection(H2Error::Protocol);
                ThrowHttp2StreamError("invalid HTTP/2 informational response");
            }
            co_return false;
        }
        if (status.front() != '2') {
            ThrowHttp2StreamError("HTTP/2 server rejected request");
        }
        response_headers_received_ = true;
        co_return end_stream;
    }

    net::awaitable<void> ReadResponseTrailers(H2Frame frame) {
        if ((frame.flags & kFlagEndStream) == 0 || input_done_) {
            co_await FailConnection(H2Error::Protocol);
            ThrowHttp2StreamError("invalid HTTP/2 response trailers");
        }
        const auto fields = co_await ReadH2HeaderFields(
            *inner_, response_decoder_, std::move(frame));
        if (!fields) {
            co_await FailConnection(fields.error());
            ThrowHttp2StreamError("invalid HTTP/2 trailer header block");
        }
        for (const auto& field : *fields) {
            if (field.name.starts_with(':')) {
                co_await FailConnection(H2Error::Protocol);
                ThrowHttp2StreamError("pseudo-header in HTTP/2 response trailers");
            }
            if (!IsValidHttp2HeaderName(field.name)) {
                co_await FailConnection(H2Error::Protocol);
                ThrowHttp2StreamError("invalid HTTP/2 trailer header name");
            }
        }
    }
    std::unique_ptr<AsyncStream> inner_;
    AsyncWriteGate write_gate_;
    uint32_t stream_id_ = 1;
    H2PayloadCodec payload_codec_ = H2PayloadCodec::GrpcHunk;
    HpackDecoder response_decoder_;
    // Received DATA the reader has not taken yet.
    memory::ThreadLocalDeque<ReceivedData> received_;
    // Current DATA frame payload; [data_offset_, data_end_) is unread body.
    memory::ByteVector data_frame_;
    size_t data_offset_ = 0;
    size_t data_end_ = 0;
    GrpcHunkDecoder hunk_;
    H2SendWindow conn_send_window_;
    H2SendWindow stream_send_window_;
    uint32_t peer_initial_window_ = H2SendWindow::kDefault;
    // Receive windows this client advertised. The connection window stays at
    // the default; the stream window takes local_initial_window_ once the
    // peer acknowledges the SETTINGS carrying it (6.9.2). Signed: a smaller
    // setting may leave the stream window negative until credit returns.
    int64_t conn_recv_window_ = H2SendWindow::kDefault;
    int64_t stream_recv_window_ = H2SendWindow::kDefault;
    uint32_t local_initial_window_ = H2SendWindow::kDefault;
    bool local_settings_acked_ = false;
    // Frame pump: one reader of inner_ at a time; the other side waits on its
    // own channel. Abort bumps the epoch so pending waits fail instead of
    // re-checking a stream that Cancel()/Close() ended.
    std::optional<SignalChannel> reader_wake_;
    std::optional<SignalChannel> writer_wake_;
    std::exception_ptr pump_failure_;
    uint64_t abort_epoch_ = 0;
    bool reader_waiting_ = false;
    bool writer_waiting_ = false;
    bool pumping_ = false;
    bool read_closed_ = false;
    bool write_closed_ = false;
    bool closed_ = false;
    bool response_headers_received_ = false;
    bool input_done_ = false;
};

class Http2ServerSession;

// Shared between the session (frame demultiplexer) and the logical stream
// owner. The session keeps it while the stream id is open; the owner keeps it
// until its Http2ServerSubStream is destroyed.
class Http2ServerSubStreamState final : public memory::ThreadAllocated {
public:
    Http2ServerSubStreamState(net::io_context& io_context,
                              std::shared_ptr<Http2ServerSession> session,
                              uint32_t stream_id,
                              H2PayloadCodec payload_codec,
                              int64_t initial_send_window);
    ~Http2ServerSubStreamState() noexcept { DropQueuedData(); }

    transport::CancellationSource& Cancellation() noexcept { return cancellation_; }
    [[nodiscard]] std::shared_ptr<Http2ServerSession> LockSession() const noexcept {
        return session_.lock();
    }
    [[nodiscard]] net::io_context& IoContext() const noexcept {
        if (auto domain = ExecutionDomain::Current()) return domain->Reactor();
        return io_context_;
    }
    void SetUploadBudget(const std::shared_ptr<XHttpPacketUpSession>& budget) noexcept {
        upload_budget_ = budget;
    }

    // Queues a received DATA payload. False asks the session to reset the
    // stream: the per-stream or XHTTP session budget is exhausted.
    bool EnqueueData(memory::ByteVector frame_payload, size_t offset, size_t size);
    void CloseInput();
    void CancelFromSession(IoErrorCode error = io_error::operation_aborted) noexcept;
    [[nodiscard]] bool InputEnded() const noexcept { return input_done_ && !cancelled_; }
    void CancelPendingOperations() noexcept;
    void CloseLocal() noexcept;
    void AbortLocal() noexcept;
    void ShutdownRead() noexcept;
    void ShutdownWrite() noexcept;

    // RFC 9113 6.9 send window of this stream; only the session adjusts it.
    [[nodiscard]] H2SendWindow& SendWindow() noexcept { return send_window_; }
    [[nodiscard]] int64_t& ReceiveWindow() noexcept { return receive_window_; }
    [[nodiscard]] uint32_t& ConsumedCredit() noexcept { return consumed_credit_; }
    [[nodiscard]] bool AcceptsData() const noexcept {
        return !input_done_ && !read_closed_ && !cancelled_;
    }
    // Waits until the session changes a send window this stream depends on.
    // Cancel() aborts the wait; stream teardown wakes it for a re-check.
    net::awaitable<void> WaitSendCredit();
    void WakeSendWaiter() noexcept {
        if (!IoContext().stopped()) (void)credit_signal_.try_send(IoErrorCode{});
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer);
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer);
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer();
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb);
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers);
    net::awaitable<void> AsyncShutdownWrite();

    void ReleaseOwner() noexcept {
        owner_released_ = true;
        (void)owner_signal_.try_send(IoErrorCode{});
    }
    static net::awaitable<void> JoinOwner(
        std::shared_ptr<Http2ServerSubStreamState> state,
        std::shared_ptr<XHttpPacketUpSession> upload_session = {});

private:
    struct QueuedDataFrame {
        memory::ByteVector payload;
        size_t offset = 0;
        size_t end = 0;
    };

    void WakeInputReader() noexcept {
        if (IoContext().stopped()) {
            return;
        }
        (void)input_signal_.try_send(IoErrorCode{});
    }

    net::awaitable<bool> EnsureReadablePayload();
    net::awaitable<bool> WaitForDataFrame();
    [[nodiscard]] size_t ConsumeReadablePayload(net::mutable_buffer buffer) noexcept;
    void PopFrontDataFrame() noexcept;
    void DropQueuedData() noexcept;
    void ConsumeData(size_t size) noexcept;
    void ReleaseDecoderStorage() noexcept;
    [[nodiscard]] std::shared_ptr<Http2ServerSession> LockWritableSession() const;

    net::io_context& io_context_;
    SignalChannel input_signal_;
    SignalChannel owner_signal_;
    SignalChannel credit_signal_;
    H2SendWindow send_window_;
    int64_t receive_window_ = H2SendWindow::kDefault;
    uint32_t consumed_credit_ = 0;
    // Cancel() bumps these so pending read/send-credit waits fail.
    uint64_t read_abort_epoch_ = 0;
    uint64_t write_abort_epoch_ = 0;
    bool owner_released_ = false;
    IoErrorCode terminal_error_ = io_error::operation_aborted;
    std::weak_ptr<Http2ServerSession> session_;
    transport::CancellationSource cancellation_;
    std::weak_ptr<XHttpPacketUpSession> upload_budget_;
    size_t upload_reserved_ = 0;
    uint32_t stream_id_ = 0;
    H2PayloadCodec payload_codec_ = H2PayloadCodec::GrpcHunk;
    memory::ThreadLocalDeque<QueuedDataFrame> data_frames_;
    // Read position inside data_frames_.front().
    size_t read_offset_ = 0;
    size_t queued_bytes_ = 0;
    size_t queued_storage_ = 0;
    size_t decoder_reserved_ = 0;
    GrpcHunkDecoder hunk_;
    bool input_done_ = false;
    bool read_closed_ = false;
    bool write_closed_ = false;
    bool trailers_sent_ = false;
    bool closing_local_ = false;
    bool cancelled_ = false;
};

class Http2ServerSubStream final : public AsyncStream {
public:
    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::ShutdownPeerWrite;
    }

    explicit Http2ServerSubStream(std::shared_ptr<Http2ServerSubStreamState> state)
        : state_(std::move(state)), deadline_(state_->IoContext(), *this) {}

    transport::CancellationSource& Cancellation() noexcept override {
        return state_->Cancellation();
    }

    ~Http2ServerSubStream() noexcept override {
        Close();
        state_->ReleaseOwner();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        return state_->AsyncRead(buffer);
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (closed_) {
            ThrowHttp2StreamError("gRPC write on closed stream");
        }
        return state_->AsyncWrite(buffer);
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        return state_->ReadMultiBuffer();
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
        if (closed_) {
            mb.clear();
            ThrowHttp2StreamError("gRPC WriteMultiBuffer on closed stream");
        }
        return state_->WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (closed_) {
            ThrowHttp2StreamError("gRPC WriteBuffers on closed stream");
        }
        return state_->WriteBuffers(buffers);
    }

    void ShutdownRead() override {
        if (!closed_) {
            state_->ShutdownRead();
        }
    }

    void ShutdownWrite() override {
        if (!closed_) {
            state_->ShutdownWrite();
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        return state_->AsyncShutdownWrite();
    }

    void Cancel() noexcept override {
        state_->CancelPendingOperations();
    }

    void Close() override {
        deadline_.Clear();
        if (closed_) {
            return;
        }
        closed_ = true;
        state_->CloseLocal();
    }

    void CloseAbortive() override {
        deadline_.Clear();
        if (closed_) {
            return;
        }
        closed_ = true;
        state_->AbortLocal();
    }

    int NativeHandle() const override;
    bool IsOpen() const override;

protected:
    StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &deadline_; }
    TcpStream* BaseTcpStream() override;
    const TcpStream* BaseTcpStream() const override;

private:
    // Never null: constructed from a live state and never reset.
    std::shared_ptr<Http2ServerSubStreamState> state_;
    StreamPhaseDeadline deadline_;
    bool closed_ = false;
};

[[nodiscard]] memory::ThreadLocalString ResolveGrpcRequestPath(const GrpcConfig& cfg) {
    if (!cfg.request_path.empty()) {
        return memory::ThreadLocalString(cfg.request_path);
    }
    if (!cfg.service_name.empty() && cfg.service_name.front() == '/') {
        return memory::ThreadLocalString(cfg.service_name);
    }
    memory::ThreadLocalString path;
    path.reserve(cfg.service_name.size() + 10);
    path.push_back('/');
    path.append(cfg.service_name);
    path.append(cfg.multi_mode ? "/TunMulti" : "/Tun");
    return path;
}

class Http2ServerSession final
    : public memory::ThreadAllocated
    , public std::enable_shared_from_this<Http2ServerSession>
    , private transport::CancellationSubscription {
public:
    struct RequestScope {
        size_t& count;
        explicit RequestScope(size_t& count) : count(count) { ++count; }
        ~RequestScope() { --count; }
    };

    // `http_config` (required for RawData) and `xhttp_config` are borrowed
    // from the handshake caller, which awaits Run() to completion.
    Http2ServerSession(net::io_context& io_context,
                       std::unique_ptr<AsyncStream> stream,
                       std::shared_ptr<InboundTransportStreamHandler> stream_handler,
                       H2PayloadCodec payload_codec,
                       uint64_t conn_id,
                       const HttpConfig* http_config,
                       const XHttpConfig* xhttp_config,
                       const GrpcConfig* grpc_config,
                       uint32_t initial_receive_window,
                       net::any_io_executor executor)
        : io_context_(io_context)
        , executor_(std::move(executor))
        , stream_(std::move(stream))
        , stream_handler_(std::move(stream_handler))
        , payload_codec_(payload_codec)
        , http_config_(http_config)
        , xhttp_config_(xhttp_config)
        , grpc_config_(grpc_config)
        , conn_id_(conn_id) {
        initial_receive_window_ = initial_receive_window;
        if (!stream_ || !stream_->DeferWriteCancellation()) {
            throw std::invalid_argument("HTTP/2 requires a physical transport with deferred write cancellation");
        }
        if (payload_codec_ == H2PayloadCodec::RawData) {
            if (!http_config_) {
                throw std::invalid_argument("HTTP/2 raw session requires an HTTP config");
            }
            response_header_block_ = EncodeHttpResponseHeaders(http_config_->headers);
        } else {
            if (grpc_config_) {
                grpc_request_path_ = ResolveGrpcRequestPath(*grpc_config_);
            }
            response_header_block_ = EncodeGrpcResponseHeaders();
            trailer_block_ = EncodeGrpcTrailers();
        }
        Resubscribe(stream_->Cancellation());
    }

    ~Http2ServerSession() noexcept {
        Unsubscribe();
        CancelAll();
    }

    Http2ServerSession(const Http2ServerSession&) = delete;
    Http2ServerSession& operator=(const Http2ServerSession&) = delete;

    net::awaitable<void> Run() {
        try {
            co_await RunAwaitableTaskGroup(executor_,
                [this](AwaitableTaskGroup& tasks) {
                    tasks_ = &tasks;
                    tasks.Spawn(RunReadLoop());
                });
        } catch (...) {
            tasks_ = nullptr;
            CancelAll();
            throw;
        }
        tasks_ = nullptr;
        CancelAll();
    }

    net::awaitable<void> FinishStream(uint32_t id, bool reset) {
        try {
            if (reset) {
                (void)co_await ResetStream(id, H2Error::Cancel);
            } else if (payload_codec_ == H2PayloadCodec::RawData) {
                (void)co_await WriteFrameSerialized(H2FrameType::DATA, kFlagEndStream, id);
            } else {
                (void)co_await WriteTrailersSerialized(id);
            }
        } catch (...) {
            CancelAll();
        }
        RemoveStream(id);
    }

    void Spawn(net::awaitable<void> task) {
        if (cancelled_ || !tasks_) throw IoSystemError(io_error::operation_aborted);
        tasks_->Spawn(std::move(task));
    }
    // No per-frame task queue: consumption coalesces into a single writer.
    // Discarded input returns connection credit too, but never resurrects a
    // reset/half-closed stream's receive window (RFC 9113 6.9).
    void ReturnReceiveCredit(uint32_t stream_id, size_t size) noexcept {
        if (size == 0 || cancelled_) return;
        consumed_connection_credit_ += static_cast<uint32_t>(size);
        if (auto it = streams_.find(stream_id);
            it != streams_.end() && it->second->AcceptsData()) {
            it->second->ConsumedCredit() += static_cast<uint32_t>(size);
        }
        if (credit_flush_running_) return;
        credit_flush_running_ = true;
        try {
            Spawn(FlushReceiveCredit());
        } catch (...) {
            credit_flush_running_ = false;
            CancelAll();
        }
    }

    [[nodiscard]] bool ReserveReceiveMemory(size_t size) noexcept {
        if (size > kHttp2ReceiveMemoryLimit - receive_memory_) return false;
        receive_memory_ += size;
        return true;
    }

    void ReleaseReceiveMemory(size_t size) noexcept {
        receive_memory_ -= size;
    }

    void RejectReceiveBudget(uint32_t stream_id) noexcept {
        RemoveStream(stream_id, io_error::no_buffer_space);
        try {
            Spawn(SendReceiveBudgetReset(stream_id));
        } catch (...) {
            CancelAll();
        }
    }

    [[nodiscard]] const AsyncStream* InnerStream() const noexcept {
        return stream_.get();
    }

    [[nodiscard]] AsyncStream* InnerStream() noexcept {
        return stream_.get();
    }

    void RemoveStream(uint32_t stream_id, IoErrorCode error = io_error::operation_aborted) noexcept {
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        auto sub = std::move(it->second);
        streams_.erase(it);
        MaybeShrinkHashContainer(streams_, 8);
        if (sub) {
            sub->CancelFromSession(error);
        }
    }

    void CancelAll(IoErrorCode error = io_error::operation_aborted) noexcept {
        if (cancelled_) {
            return;
        }
        cancelled_ = true;
        write_gate_.Cancel();
        auto streams = std::move(streams_);
        for (auto& [stream_id, sub] : streams) {
            (void)stream_id;
            if (sub) {
                sub->CancelFromSession(error);
            }
        }
        streams_.clear();
        if (stream_) {
            stream_->CloseAbortive();
        }
    }

    net::awaitable<bool> WriteFrameSerialized(
        H2FrameType type,
        uint8_t flags,
        uint32_t stream_id,
        std::span<const uint8_t> payload = {}) {
        auto write_lease = write_gate_.TryAcquire();
        if (!write_lease) write_lease = co_await write_gate_.Acquire();
        // RST_STREAM may target a stream that was already removed.
        if (!write_lease ||
            (stream_id == 0 || type == H2FrameType::RST_STREAM
                 ? !ConnectionWritable() : !StreamWritable(stream_id))) {
            co_return false;
        }
        co_return co_await WriteH2Frame(*stream_, type, flags, stream_id, payload);
    }

    net::awaitable<bool> WriteGrpcMessageSerialized(
        uint32_t stream_id,
        std::span<const uint8_t> data) {
        do {
            const size_t size = std::min(data.size(), kGrpcHunkRecordPayloadLimit);
            const GrpcHunkPrefix prefix(size);
            const std::array<net::const_buffer, 2> record{
                prefix.Buffer(), net::buffer(data.data(), size)};
            if (!co_await WriteDataSerialized(stream_id, record)) co_return false;
            data = data.subspan(size);
        } while (!data.empty());
        co_return true;
    }

    // Sends DATA within the connection and stream send windows (RFC 9113
    // 6.9.1). The physical gate is held per frame, so other streams and the
    // read loop's control frames proceed while this stream waits for credit.
    net::awaitable<bool> WriteDataSerialized(
        uint32_t stream_id,
        std::span<const net::const_buffer> buffers) {
        H2DataCursor cursor(buffers);
        const auto cancellation = co_await net::this_coro::cancellation_state;
        while (cursor.Remaining() != 0) {
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            auto write_lease = write_gate_.TryAcquire();
            if (!write_lease) write_lease = co_await write_gate_.Acquire();
            if (cancellation.cancelled() != net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            const auto it = streams_.find(stream_id);
            if (!write_lease || !ConnectionWritable() || it == streams_.end()) {
                co_return false;
            }
            auto& send_window = it->second->SendWindow();
            const size_t credit = std::min({cursor.Remaining(),
                                            kHttp2MaxFramePayload,
                                            conn_send_window_.Available(),
                                            send_window.Available()});
            if (credit == 0) {
                write_lease.Reset();
                const auto sub = it->second;
                co_await sub->WaitSendCredit();
                continue;
            }
            const auto payload = cursor.Next(credit);
            const size_t size = H2DataCursor::Size(payload);
            conn_send_window_.Consume(size);
            send_window.Consume(size);
            if (!co_await WriteH2FrameBuffers(
                    *stream_, H2FrameType::DATA, 0, stream_id, payload)) {
                co_return false;
            }
        }
        co_return true;
    }

    net::awaitable<bool> WriteTrailersSerialized(uint32_t stream_id) {
        return WriteFrameSerialized(
            H2FrameType::HEADERS, kFlagEndHeaders | kFlagEndStream, stream_id, trailer_block_);
    }

    net::awaitable<void> RunReadLoop() {
        try {
            while (!cancelled_ && stream_) {
                auto frame = co_await ReadH2Frame(*stream_);
                if (!frame) {
                    const bool ended = std::all_of(streams_.begin(), streams_.end(),
                        [](const auto& entry) { return entry.second->InputEnded(); });
                    if (ended) co_return;
                    throw IoSystemError(io_error::connection_reset, "HTTP/2 missing END_STREAM");
                }

                if (!co_await DispatchFrame(std::move(*frame))) break;
            }
        } catch (const IoSystemError& error) {
            CancelAll(error.code());
            co_return;
        } catch (const std::exception& e) {
            LOG_CONN_DEBUG(conn_id_, "HTTP/2 server read loop failed > {}", e.what());
        } catch (...) {
            LOG_CONN_DEBUG(conn_id_, "HTTP/2 server read loop failed > unknown exception");
        }
        CancelAll();
    }

private:
    net::awaitable<void> FlushReceiveCredit() {
        try {
            while (!cancelled_) {
                auto lease = write_gate_.TryAcquire();
                if (!lease) lease = co_await write_gate_.Acquire();
                if (!lease || !ConnectionWritable()) break;
                uint32_t id = 0;
                uint32_t increment = std::exchange(consumed_connection_credit_, 0);
                if (increment != 0) {
                    connection_receive_window_ += increment;
                } else {
                    // Do not retain an unordered_map iterator over an await.
                    for (auto& [stream_id, sub] : streams_) {
                        if (!sub->AcceptsData()) {
                            sub->ConsumedCredit() = 0;
                            continue;
                        }
                        if (sub->ConsumedCredit() == 0) continue;
                        id = stream_id;
                        increment = std::exchange(sub->ConsumedCredit(), 0);
                        sub->ReceiveWindow() += increment;
                        break;
                    }
                }
                if (increment == 0) break;
                std::array<uint8_t, 4> payload{};
                StoreU32BE(payload.data(), increment);
                if (!co_await WriteH2Frame(
                        *stream_, H2FrameType::WINDOW_UPDATE, 0, id, payload)) {
                    CancelAll();
                    break;
                }
            }
        } catch (...) {
            CancelAll();
        }
        credit_flush_running_ = false;
    }

    [[nodiscard]] bool ConnectionWritable() const noexcept {
        return !cancelled_ && stream_;
    }

    [[nodiscard]] bool StreamWritable(uint32_t stream_id) const noexcept {
        return ConnectionWritable() && streams_.contains(stream_id);
    }

    net::awaitable<void> RunPacketUpload(
        std::unique_ptr<AsyncStream> stream,
        std::shared_ptr<XHttpPacketUpSession> session, uint64_t seq) {
        RequestScope active(active_requests_);
        try {
            XHttpPacketUpSession::Upload upload(*session, *stream);
            buf::MultiBuffer payload;
            while (co_await upload.Read(payload, buf::Buffer::kSize) != 0) {
            }
            if (!upload.Commit(seq, std::move(payload)))
                throw IoSystemError(io_error::no_buffer_space);
            if (!session->DownlinkAttached() &&
                !co_await session->AwaitDownlink(stream->Cancellation())) {
                throw IoSystemError(io_error::timed_out);
            }
            session.reset();
            co_await stream->AsyncShutdownWrite();
            stream->Close();
        } catch (...) {
            stream->CloseAbortive();
        }
    }

    net::awaitable<void> RunRequest(
        std::unique_ptr<AsyncStream> stream, InboundTransportMetadata metadata) {
        RequestScope active(active_requests_);
        try {
            co_await stream_handler_->OnInboundTransportStream(
                std::move(stream), std::move(metadata));
        } catch (const std::exception& error) {
            LOG_CONN_DEBUG(conn_id_, "HTTP/2 logical request failed > {}", error.what());
        } catch (...) {
            LOG_CONN_DEBUG(conn_id_, "HTTP/2 logical request failed > unknown exception");
        }
    }

    // Hands the logical stream to the request sink, optionally joined to an
    // XHTTP session as its downlink. Without a sink the stream ends cleanly.
    void DeliverRequest(std::shared_ptr<Http2ServerSubStreamState> sub,
                        std::shared_ptr<XHttpPacketUpSession> split_session,
                        InboundTransportMetadata metadata) {
        if (!stream_handler_) {
            if (split_session) split_session->Close();
            sub->CloseLocal();
            return;
        }
        try {
            std::unique_ptr<AsyncStream> stream =
                std::make_unique<Http2ServerSubStream>(sub);
            if (split_session) {
                stream = MakeXHttpSplitStream(split_session, std::move(stream));
            }
            if (cancelled_ || !tasks_) throw IoSystemError(io_error::operation_aborted);
            auto& source = stream->Cancellation();
            // Bind before the proxy handshake, which can write (and wait for the
            // physical gate) before the dispatcher installs its read subscription.
            tasks_->Spawn(RunRequest(std::move(stream), std::move(metadata)), &source);
        } catch (...) {
            if (split_session) split_session->Close();
            sub->AbortLocal();
            throw;
        }
    }

    // 200 response headers, then the request's own END_STREAM, if any.
    net::awaitable<bool> AcceptStream(uint32_t stream_id,
                                      bool end_stream,
                                      Http2ServerSubStreamState& sub) {
        if (!ready_) {
            if (stream_handler_) stream_handler_->OnInboundTransportReady(*stream_);
            ready_ = true;
        }
        if (!co_await WriteFrameSerialized(
                H2FrameType::HEADERS, kFlagEndHeaders, stream_id, response_header_block_)) {
            co_return false;
        }
        if (end_stream) {
            sub.CloseInput();
        }
        co_return true;
    }

    net::awaitable<bool> ResetStream(uint32_t stream_id, H2Error error) {
        RemoveStream(stream_id, error == H2Error::ExcessiveLoad ||
            error == H2Error::RefusedStream ? IoErrorCode(io_error::no_buffer_space) :
            IoErrorCode(io_error::operation_aborted));
        std::array<uint8_t, 4> payload{};
        StoreU32BE(payload.data(), static_cast<uint32_t>(error));
        co_return co_await WriteFrameSerialized(H2FrameType::RST_STREAM, 0, stream_id, payload);
    }

    net::awaitable<void> SendReceiveBudgetReset(uint32_t stream_id) {
        if (!co_await ResetStream(stream_id, H2Error::ExcessiveLoad)) CancelAll();
    }

    net::awaitable<bool> FailConnection(H2Error error) {
        std::array<uint8_t, 8> payload{};
        StoreU32BE(payload.data(), last_remote_stream_id_);
        StoreU32BE(payload.data() + 4, static_cast<uint32_t>(error));
        (void)co_await WriteFrameSerialized(H2FrameType::GOAWAY, 0, 0, payload);
        CancelAll();
        co_return false;
    }

    [[nodiscard]] bool IsKnownClientStream(uint32_t stream_id) const noexcept {
        return stream_id != 0 && (stream_id & 1u) != 0 && stream_id <= last_remote_stream_id_;
    }

    // Returns false once the connection must stop reading.
    net::awaitable<bool> DispatchFrame(H2Frame frame) {
        switch (frame.type) {
        case H2FrameType::SETTINGS:
            if (frame.stream_id != 0) co_return co_await FailConnection(H2Error::Protocol);
            if (frame.payload.size() % 6 != 0 ||
                ((frame.flags & kFlagAck) && !frame.payload.empty())) {
                co_return co_await FailConnection(H2Error::FrameSize);
            }
            if (!(frame.flags & kFlagAck)) {
                if (const auto error = ApplyPeerSettings(frame.payload)) {
                    co_return co_await FailConnection(*error);
                }
                co_return co_await WriteFrameSerialized(H2FrameType::SETTINGS, kFlagAck, 0);
            }
            if (!local_settings_acked_) {
                local_settings_acked_ = true;
                // Before ACK, allow DATA sent with the old default window.
                const int64_t delta = static_cast<int64_t>(initial_receive_window_) -
                    std::max<int64_t>(initial_receive_window_, H2SendWindow::kDefault);
                for (auto& [id, sub] : streams_) {
                    (void)id;
                    sub->ReceiveWindow() += delta;
                }
            }
            break;
        case H2FrameType::PING:
            if (frame.stream_id != 0) co_return co_await FailConnection(H2Error::Protocol);
            if (frame.payload.size() != 8) co_return co_await FailConnection(H2Error::FrameSize);
            if (!(frame.flags & kFlagAck)) {
                co_return co_await WriteFrameSerialized(
                    H2FrameType::PING, kFlagAck, 0, frame.payload);
            }
            break;
        case H2FrameType::WINDOW_UPDATE:
            co_return co_await ReceiveWindowUpdate(frame);
        case H2FrameType::HEADERS: {
            const auto id = frame.stream_id;
            bool exhausted = false;
            try {
                co_return co_await ReceiveHeaders(std::move(frame));
            } catch (const std::bad_alloc&) {
                if (cancelled_) throw;
                exhausted = true;
            }
            if (exhausted) co_return co_await ResetStream(id, H2Error::RefusedStream);
            co_return false;
        }
        case H2FrameType::DATA:
            if (!IsKnownClientStream(frame.stream_id)) {
                co_return co_await FailConnection(H2Error::Protocol);
            }
            co_await ReceiveData(std::move(frame));
            break;
        case H2FrameType::PRIORITY:
            if (frame.stream_id == 0) co_return co_await FailConnection(H2Error::Protocol);
            if (frame.payload.size() != 5) co_return co_await FailConnection(H2Error::FrameSize);
            break;
        case H2FrameType::RST_STREAM:
            if (frame.payload.size() != 4) co_return co_await FailConnection(H2Error::FrameSize);
            if (!IsKnownClientStream(frame.stream_id)) {
                co_return co_await FailConnection(H2Error::Protocol);
            }
            RemoveStream(frame.stream_id, io_error::connection_reset);
            break;
        case H2FrameType::GOAWAY:
            CancelAll();
            co_return false;
        case H2FrameType::CONTINUATION:
        case H2FrameType::PUSH_PROMISE:
            co_return co_await FailConnection(H2Error::Protocol);
        default:
            break;
        }
        co_return !cancelled_;
    }

    // SETTINGS_INITIAL_WINDOW_SIZE moves every open stream window by the
    // change (RFC 9113 6.9.2); overflow is a FLOW_CONTROL_ERROR.
    [[nodiscard]] std::optional<H2Error> ApplyPeerSettings(std::span<const uint8_t> payload) {
        const auto initial_window = PeerInitialWindowSetting(payload);
        if (!initial_window) return initial_window.error();
        if (!*initial_window) return std::nullopt;
        const int64_t delta = static_cast<int64_t>(**initial_window) -
                              static_cast<int64_t>(peer_initial_window_);
        for (auto& [stream_id, sub] : streams_) {
            (void)stream_id;
            if (!sub->SendWindow().Adjust(delta)) return H2Error::FlowControl;
        }
        peer_initial_window_ = **initial_window;
        for (auto& [stream_id, sub] : streams_) {
            (void)stream_id;
            sub->WakeSendWaiter();
        }
        return std::nullopt;
    }

    // RFC 9113 6.9: connection-level faults fail the connection; stream-level
    // ones reset only that stream. Closed streams may still receive updates.
    net::awaitable<bool> ReceiveWindowUpdate(const H2Frame& frame) {
        const auto increment = WindowUpdateIncrement(frame);
        if (frame.stream_id == 0) {
            if (!increment) co_return co_await FailConnection(increment.error());
            if (!conn_send_window_.Adjust(*increment)) {
                co_return co_await FailConnection(H2Error::FlowControl);
            }
            for (auto& [stream_id, sub] : streams_) {
                (void)stream_id;
                sub->WakeSendWaiter();
            }
            co_return true;
        }
        if (!IsKnownClientStream(frame.stream_id)) {
            co_return co_await FailConnection(H2Error::Protocol);
        }
        if (!increment && increment.error() == H2Error::FrameSize) {
            co_return co_await FailConnection(H2Error::FrameSize);
        }
        const auto it = streams_.find(frame.stream_id);
        if (it == streams_.end()) co_return true;
        if (!increment) co_return co_await ResetStream(frame.stream_id, increment.error());
        if (!it->second->SendWindow().Adjust(*increment)) {
            co_return co_await ResetStream(frame.stream_id, H2Error::FlowControl);
        }
        it->second->WakeSendWaiter();
        co_return true;
    }

    // A new request, or trailers ending an open one.
    net::awaitable<bool> ReceiveHeaders(H2Frame frame) {
        // RFC 9113 6.2: HEADERS on stream 0 is a connection error.
        if (frame.stream_id == 0) {
            co_return co_await FailConnection(H2Error::Protocol);
        }

        const bool end_stream = (frame.flags & kFlagEndStream) != 0;
        const uint32_t stream_id = frame.stream_id;
        const bool trailers = streams_.contains(stream_id);
        const std::string_view real_ip_header = http_config_
            ? std::string_view(http_config_->real_ip_header) : std::string_view{};
        tl::expected<HpackDecoder::HeaderFields, H2Error> fields;
        try {
            fields = co_await ReadH2HeaderFields(*stream_, hpack_decoder_, std::move(frame));
        } catch (const std::bad_alloc&) {
            CancelAll();
            throw;
        }
        if (!fields) {
            co_return co_await FailConnection(fields.error());
        }
        const bool closed_client_stream =
            !trailers && (stream_id & 1u) != 0 && stream_id <= last_remote_stream_id_;
        auto request = ParseH2RequestHeaders(
            std::move(*fields), real_ip_header, trailers || closed_client_stream);
        if (closed_client_stream) {
            if (end_stream && request.has_value()) {
                co_return true;
            }
            co_return co_await FailConnection(H2Error::Protocol);
        }
        if (trailers) {
            // RFC 9113 8.1: trailers end this request, not its connection;
            // malformed trailers are a stream error (8.1.1).
            auto it = streams_.find(stream_id);
            if (it != streams_.end() && it->second->InputEnded())
                co_return co_await ResetStream(stream_id, H2Error::StreamClosed);
            if (!request || !end_stream)
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            if (it != streams_.end()) it->second->CloseInput();
            co_return true;
        }
        if ((stream_id & 1u) == 0 || stream_id <= last_remote_stream_id_) {
            co_return co_await FailConnection(H2Error::Protocol);
        }
        last_remote_stream_id_ = stream_id;
        if (!request) {
            // RFC 9113 8.1.1: a malformed request is a stream error of type
            // PROTOCOL_ERROR; the connection and its other streams continue.
            co_return co_await ResetStream(stream_id, H2Error::Protocol);
        }
        if (streams_.size() >= kHttp2MaxConcurrentStreams ||
            active_requests_ >= kHttp2MaxConcurrentStreams) {
            co_return co_await ResetStream(stream_id, H2Error::RefusedStream);
        }
        if (payload_codec_ == H2PayloadCodec::RawData && !xhttp_config_ && http_config_) {
            if (!detail::PathPrefixMatchesSegment(http_config_->path, request->path) ||
                (!http_config_->method.empty() &&
                 !EqualsAsciiCI(request->method, http_config_->method))) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            if (const std::string_view expected_host = TrimAscii(ExpectedHttpHost(*http_config_));
                !expected_host.empty() &&
                !AuthorityMatchesHost(request->authority, expected_host)) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
        }
        if (payload_codec_ == H2PayloadCodec::GrpcHunk && grpc_config_) {
            if (!EqualsAsciiCI(request->method, "POST") ||
                !detail::PathMatchesExactly(grpc_request_path_, request->path)) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            if (const std::string_view expected_authority = TrimAscii(grpc_config_->authority);
                !expected_authority.empty() &&
                !AuthorityMatchesHost(request->authority, expected_authority)) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
        }
        auto sub = memory::AllocateShared<Http2ServerSubStreamState>(
            io_context_, shared_from_this(), stream_id, payload_codec_, peer_initial_window_);
        sub->ReceiveWindow() = local_settings_acked_ ? initial_receive_window_ :
            std::max<int64_t>(initial_receive_window_, H2SendWindow::kDefault);
        streams_.emplace(stream_id, sub);

        if (xhttp_config_ && payload_codec_ == H2PayloadCodec::RawData) {
            co_return co_await RouteXHttpRequest(
                stream_id, end_stream, std::move(*request), std::move(sub));
        }
        if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
            co_return false;
        }

        LOG_CONN_DEBUG(conn_id_,
            "{} server accepted logical stream_id={}",
            payload_codec_ == H2PayloadCodec::RawData ? "HTTP/2" : "gRPC",
            stream_id);
        DeliverRequest(std::move(sub), nullptr, std::move(request->metadata));
        co_return true;
    }

    net::awaitable<bool> RouteXHttpRequest(
        uint32_t stream_id,
        bool end_stream,
        H2RequestHeaders request,
        std::shared_ptr<Http2ServerSubStreamState> sub) {
        if (const std::string_view expected_host = TrimAscii(ExpectedHttpHost(*http_config_));
            !expected_host.empty() &&
            !AuthorityMatchesHost(request.authority, expected_host)) {
            LOG_CONN_DEBUG(conn_id_,
                "XHTTP server H2 host mismatch expected='{}' actual='{}'",
                PublicHttpTargetForLog(expected_host),
                PublicHttpTargetForLog(request.authority));
            co_return co_await ResetStream(stream_id, H2Error::Protocol);
        }

        const auto meta = ParseXHttpRequestMeta(
            http_config_->path,
            request.path,
            request.method);
        switch (meta.kind) {
        case XHttpRequestMeta::Kind::StreamOne: {
            if (!xhttp_config_->AcceptsStreamOne()) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
                co_return false;
            }
            LOG_CONN_DEBUG(conn_id_, "XHTTP server H2 stream-one ready stream_id={}",
                          stream_id);
            DeliverRequest(std::move(sub), nullptr, std::move(request.metadata));
            co_return true;
        }
        case XHttpRequestMeta::Kind::PacketDown: {
            if (!xhttp_config_->AcceptsPacketUp() &&
                !xhttp_config_->AcceptsStreamUp()) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            auto xsession = co_await GetXHttpPacketSession(
                io_context_, xhttp_config_->session_namespace,
                meta.session_id, XHttpSessionAccess::Open);
            if (!xsession || !xsession->AttachDownlink()) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            bool attached = true;
            struct DownlinkGuard {
                XHttpPacketUpSession* session;
                bool& active;
                ~DownlinkGuard() {
                    if (active) session->Close();
                }
            } guard{xsession.get(), attached};
            if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
                co_return false;
            }
            LOG_CONN_DEBUG(conn_id_, "XHTTP server H2 split downlink ready session={} stream_id={} mode={}",
                          meta.session_id,
                          stream_id,
                          xhttp_config_->AcceptsStreamUp() ? "stream-up" : "packet-up");
            attached = false;
            DeliverRequest(std::move(sub), std::move(xsession), std::move(request.metadata));
            co_return true;
        }
        case XHttpRequestMeta::Kind::StreamUp: {
            if (!xhttp_config_->AcceptsStreamUp()) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            auto xsession = co_await GetXHttpPacketSession(
                io_context_, xhttp_config_->session_namespace,
                meta.session_id, XHttpSessionAccess::Open);
            if (!xsession) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            if (!xsession->CanAttachStream()) {
                LOG_CONN_DEBUG(conn_id_,
                    "XHTTP server rejected concurrent H2 stream-up session={}",
                    meta.session_id);
                constexpr std::array<uint8_t, 1> kBadRequestStatus{0x8c}; // :status: 400
                const bool ok = co_await WriteFrameSerialized(
                    H2FrameType::HEADERS, kFlagEndHeaders | kFlagEndStream,
                    stream_id, kBadRequestStatus);
                RemoveStream(stream_id);
                co_return ok;
            }
            bool accepting = true;
            struct StreamUpGuard {
                XHttpPacketUpSession* session;
                bool& active;
                ~StreamUpGuard() {
                    if (active && session->CanAttachStream()) session->Close();
                }
            } guard{xsession.get(), accepting};
            if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
                co_return false;
            }
            accepting = false;
            LOG_CONN_DEBUG(conn_id_, "XHTTP server H2 stream-up upload ready session={} stream_id={}",
                          meta.session_id,
                          stream_id);
            sub->SetUploadBudget(xsession);
            auto upload = std::make_unique<Http2ServerSubStream>(sub);
            if (!xsession->AttachStream(std::move(upload))) {
                LOG_CONN_DEBUG(conn_id_,
                    "XHTTP server rejected concurrent H2 stream-up session={}",
                    meta.session_id);
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            auto* raw_xsession = xsession.get();
            try {
                Spawn(Http2ServerSubStreamState::JoinOwner(std::move(sub), std::move(xsession)));
            } catch (...) {
                raw_xsession->Close();
                throw;
            }
            co_return true;
        }
        case XHttpRequestMeta::Kind::PacketUp: {
            if (!xhttp_config_->AcceptsPacketUp()) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            auto xsession = co_await GetXHttpPacketSession(
                io_context_, xhttp_config_->session_namespace,
                meta.session_id, XHttpSessionAccess::Upload);
            if (!xsession) {
                co_return co_await ResetStream(stream_id, H2Error::Protocol);
            }
            if (!co_await AcceptStream(stream_id, end_stream, *sub)) {
                co_return false;
            }
            sub->SetUploadBudget(xsession);
            auto upload = std::make_unique<Http2ServerSubStream>(std::move(sub));
            bool spawn_failed = false;
            try {
                Spawn(RunPacketUpload(std::move(upload), std::move(xsession), meta.seq));
            } catch (...) {
                spawn_failed = true;
            }
            if (spawn_failed) {
                co_return co_await ResetStream(stream_id, H2Error::Cancel);
            }
            co_return true;
        }
        case XHttpRequestMeta::Kind::Unknown:
            break;
        }
        LOG_CONN_DEBUG(conn_id_, "XHTTP server received unknown H2 request method='{}' path='{}'",
                      PublicHttpMethodForLog(request.method),
                      PublicHttpTargetForLog(request.path));
        co_return co_await ResetStream(stream_id, H2Error::Protocol);
    }

    net::awaitable<void> ReceiveData(H2Frame frame) {
        // The complete DATA payload consumes credit, including Pad Length and
        // padding (RFC 9113 6.1). Closed/reset streams still consume connection
        // credit, and discarding those bytes returns it exactly once.
        const size_t flow_size = frame.payload.size();
        if (static_cast<int64_t>(flow_size) > connection_receive_window_) {
            (void)co_await FailConnection(H2Error::FlowControl);
            co_return;
        }
        connection_receive_window_ -= static_cast<int64_t>(flow_size);
        auto it = streams_.find(frame.stream_id);
        if (it == streams_.end()) {
            ReturnReceiveCredit(0, flow_size);
            co_return;
        }
        const auto sub = it->second;
        if (flow_size != 0 && static_cast<int64_t>(flow_size) > sub->ReceiveWindow()) {
            ReturnReceiveCredit(0, flow_size);
            (void)co_await ResetStream(frame.stream_id, H2Error::FlowControl);
            co_return;
        }
        sub->ReceiveWindow() -= static_cast<int64_t>(flow_size);
        if (sub->InputEnded()) {
            ReturnReceiveCredit(0, flow_size);
            (void)co_await ResetStream(frame.stream_id, H2Error::StreamClosed);
            co_return;
        }
        if ((frame.flags & kFlagPadded) != 0 &&
            (frame.payload.empty() || frame.payload.front() >= frame.payload.size())) {
            (void)co_await FailConnection(H2Error::Protocol);
            co_return;
        }
        if (!sub->AcceptsData()) {
            if ((frame.flags & kFlagEndStream) != 0) sub->CloseInput();
            ReturnReceiveCredit(0, flow_size);
            co_return;
        }
        const auto data = H2DataPayload(frame);
        const size_t data_size = data.size();
        const size_t offset = data_size == 0 ? 0 :
            static_cast<size_t>(data.data() - frame.payload.data());
        bool queued = data_size == 0;
        try {
            if (data_size != 0) {
                queued = sub->EnqueueData(std::move(frame.payload), offset, data_size);
            }
        } catch (const std::bad_alloc&) {
            queued = false;
        }
        if (!queued) {
            ReturnReceiveCredit(0, flow_size);
            if (!co_await ResetStream(frame.stream_id, H2Error::ExcessiveLoad)) CancelAll();
            co_return;
        }
        if ((frame.flags & kFlagEndStream) != 0) sub->CloseInput();
        // Padding is consumed by the framing layer; body credit belongs to the
        // logical reader, not to this demultiplexer.
        ReturnReceiveCredit(frame.stream_id, flow_size - data_size);
    }

    void OnCancellation(transport::Cancellation) noexcept override {
        CancelAll();
    }

    net::io_context& io_context_;
    net::any_io_executor executor_;
    std::unique_ptr<AsyncStream> stream_;
    std::shared_ptr<InboundTransportStreamHandler> stream_handler_;
    AsyncWriteGate write_gate_;
    memory::ThreadLocalUnorderedMap<uint32_t, std::shared_ptr<Http2ServerSubStreamState>>
        streams_;
    H2PayloadCodec payload_codec_ = H2PayloadCodec::GrpcHunk;
    const HttpConfig* http_config_ = nullptr;
    const XHttpConfig* xhttp_config_ = nullptr;
    const GrpcConfig* grpc_config_ = nullptr;
    memory::ThreadLocalString grpc_request_path_;
    // HPACK blocks encoded once per connection; neither uses the dynamic table.
    memory::ByteVector response_header_block_;
    memory::ByteVector trailer_block_;
    HpackDecoder hpack_decoder_;
    uint64_t conn_id_ = 0;
    uint32_t last_remote_stream_id_ = 0;
    AwaitableTaskGroup* tasks_ = nullptr;
    size_t active_requests_ = 0;
    bool ready_ = false;
    bool cancelled_ = false;
    H2SendWindow conn_send_window_;
    uint32_t peer_initial_window_ = H2SendWindow::kDefault;
    int64_t connection_receive_window_ = kHttp2ConnectionReceiveWindow;
    uint32_t initial_receive_window_ = H2SendWindow::kDefault;
    uint32_t consumed_connection_credit_ = 0;
    size_t receive_memory_ = 0;
    bool local_settings_acked_ = false;
    bool credit_flush_running_ = false;
};

net::awaitable<void> Http2ServerSubStreamState::JoinOwner(
    std::shared_ptr<Http2ServerSubStreamState> state,
    std::shared_ptr<XHttpPacketUpSession> upload_session) {
    bool cancelled = false;
    try {
        if (!state->owner_released_)
            co_await state->owner_signal_.async_receive(net::use_awaitable);
    } catch (...) {
        cancelled = true;
        if (upload_session) upload_session->Close();
        if (auto session = state->LockSession()) session->CancelAll();
    }
    if (cancelled) {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        if (!state->owner_released_)
            co_await state->owner_signal_.async_receive(net::use_awaitable);
    }
}

Http2ServerSubStreamState::Http2ServerSubStreamState(
    net::io_context& io_context,
    std::shared_ptr<Http2ServerSession> session,
    uint32_t stream_id,
    H2PayloadCodec payload_codec,
    int64_t initial_send_window)
    : io_context_(io_context)
    , input_signal_(ExecutionDomain::Current()
          ? ExecutionDomain::Current()->Executor()
          : net::any_io_executor(io_context.get_executor()), 1)
    , owner_signal_(ExecutionDomain::Current()
          ? ExecutionDomain::Current()->Executor()
          : net::any_io_executor(io_context.get_executor()), 1)
    , credit_signal_(ExecutionDomain::Current()
          ? ExecutionDomain::Current()->Executor()
          : net::any_io_executor(io_context.get_executor()), 1)
    , send_window_(initial_send_window)
    , session_(std::move(session))
    , stream_id_(stream_id)
    , payload_codec_(payload_codec) {}

net::awaitable<void> Http2ServerSubStreamState::WaitSendCredit() {
    const uint64_t epoch = write_abort_epoch_;
    auto [ec] = co_await credit_signal_.async_receive(net::as_tuple(net::use_awaitable));
    if (ec || epoch != write_abort_epoch_) {
        throw IoSystemError(io_error::operation_aborted, "HTTP/2 send window wait aborted");
    }
}

bool Http2ServerSubStreamState::EnqueueData(
    memory::ByteVector frame_payload,
    size_t offset,
    size_t size) {
    if (!AcceptsData()) return false;
    if (offset > frame_payload.size() || size > frame_payload.size() - offset) return false;
    if (size > kHttp2MaxQueuedStreamBytes - queued_bytes_) return false;
    // Pack small/split DATA frames into the tail, including a prefix of a
    // larger successor. Otherwise legal fragmentation leaves an 8 KiB hole
    // per tiny frame and exhausts storage before the advertised byte window.
    size_t coalesced = 0;
    if (!data_frames_.empty()) {
        auto& tail = data_frames_.back();
        if (size <= tail.payload.capacity() - tail.end) {
            tail.payload.resize(tail.end + size);
            std::memcpy(tail.payload.data() + tail.end, frame_payload.data() + offset, size);
            tail.end += size;
            queued_bytes_ += size;
            WakeInputReader();
            return true;
        }
        coalesced = tail.payload.capacity() - tail.end;
    }
    if (frame_payload.capacity() < buf::Buffer::kSize) frame_payload.reserve(buf::Buffer::kSize);
    const size_t storage = frame_payload.capacity();
    const auto session = LockSession();
    if (!session || storage > kHttp2MaxQueuedStreamStorage - queued_storage_ ||
        !session->ReserveReceiveMemory(storage)) return false;
    const auto upload_budget = upload_budget_.lock();
    if (upload_budget && !upload_budget->Reserve(storage)) {
        session->ReleaseReceiveMemory(storage);
        return false;
    }
    try {
        data_frames_.push_back(QueuedDataFrame{
            .payload = std::move(frame_payload),
            .offset = offset,
            .end = offset + size,
        });
    } catch (...) {
        session->ReleaseReceiveMemory(storage);
        if (upload_budget) upload_budget->Release(storage);
        throw;
    }
    if (coalesced != 0) {
        // Do not modify the old tail until the new allocation and deque entry
        // are committed: rejection must leave every input byte unqueued.
        auto& tail = data_frames_[data_frames_.size() - 2];
        auto& added = data_frames_.back();
        tail.payload.resize(tail.end + coalesced);
        std::memcpy(tail.payload.data() + tail.end,
                    added.payload.data() + offset, coalesced);
        tail.end += coalesced;
        const size_t remaining = size - coalesced;
        std::memmove(added.payload.data(),
                     added.payload.data() + offset + coalesced, remaining);
        added.payload.resize(remaining);
        added.offset = 0;
        added.end = remaining;
    }
    if (upload_budget) upload_reserved_ += storage;
    queued_storage_ += storage;
    queued_bytes_ += size;
    WakeInputReader();
    return true;
}

void Http2ServerSubStreamState::CloseInput() {
    if (input_done_) {
        return;
    }
    input_done_ = true;
    WakeInputReader();
}

void Http2ServerSubStreamState::CancelFromSession(IoErrorCode error) noexcept {
    if (cancelled_) {
        return;
    }
    cancelled_ = true;
    terminal_error_ = error;
    input_done_ = true;
    read_closed_ = true;
    write_closed_ = true;
    trailers_sent_ = true;
    closing_local_ = true;
    DropQueuedData();
    hunk_.Clear();
    cancellation_.Stop();
    WakeInputReader();
    WakeSendWaiter();
}

void Http2ServerSubStreamState::CancelPendingOperations() noexcept {
    cancellation_.CancelPending();
    if (cancelled_) {
        return;
    }
    ++read_abort_epoch_;
    ++write_abort_epoch_;
    WakeInputReader();
    WakeSendWaiter();
}

void Http2ServerSubStreamState::AbortLocal() noexcept {
    if (cancelled_) return;
    auto session = LockSession();
    if (!session) {
        CancelFromSession();
        return;
    }
    const auto stream_id = stream_id_;
    session->RemoveStream(stream_id);
    try {
        session->Spawn(session->FinishStream(stream_id, true));
    } catch (...) {
        session->CancelAll();
    }
}

void Http2ServerSubStreamState::CloseLocal() noexcept {
    cancellation_.Stop();
    if (cancelled_ || closing_local_) {
        return;
    }
    closing_local_ = true;
    read_closed_ = true;
    DropQueuedData();
    hunk_.Clear();
    WakeInputReader();

    auto session = session_.lock();
    if (!session) {
        CancelFromSession();
        return;
    }

    const uint32_t stream_id = stream_id_;
    if (!trailers_sent_) {
        trailers_sent_ = true;
        write_closed_ = true;
        try {
            session->Spawn(session->FinishStream(stream_id, false));
        } catch (...) {
            session->RemoveStream(stream_id);
            session->CancelAll();
        }
    } else {
        session->RemoveStream(stream_id);
    }
}

void Http2ServerSubStreamState::ShutdownRead() noexcept {
    read_closed_ = true;
    DropQueuedData();
    hunk_.Clear();
    WakeInputReader();
}

void Http2ServerSubStreamState::ShutdownWrite() noexcept {
    write_closed_ = true;
}

std::shared_ptr<Http2ServerSession> Http2ServerSubStreamState::LockWritableSession() const {
    if (write_closed_ || cancelled_) {
        ThrowHttp2StreamError("gRPC write on closed server stream");
    }
    auto session = session_.lock();
    if (!session) {
        ThrowHttp2StreamError("gRPC write without server session");
    }
    return session;
}

net::awaitable<size_t> Http2ServerSubStreamState::AsyncRead(
    net::mutable_buffer buffer) {
    if (buffer.size() == 0 || !co_await EnsureReadablePayload()) {
        co_return 0;
    }
    co_return ConsumeReadablePayload(buffer);
}

net::awaitable<size_t> Http2ServerSubStreamState::AsyncWrite(
    net::const_buffer buffer) {
    auto session = LockWritableSession();
    if (payload_codec_ == H2PayloadCodec::RawData) {
        if (!co_await session->WriteDataSerialized(
                stream_id_, std::span<const net::const_buffer>(&buffer, 1))) {
            ThrowHttp2StreamError("HTTP/2 raw server stream write failed");
        }
        co_return buffer.size();
    }
    const auto* data = static_cast<const uint8_t*>(buffer.data());
    if (!co_await session->WriteGrpcMessageSerialized(
            stream_id_, std::span<const uint8_t>(data, buffer.size()))) {
        ThrowHttp2StreamError("gRPC server stream write failed");
    }
    co_return buffer.size();
}

net::awaitable<buf::MultiBuffer> Http2ServerSubStreamState::ReadMultiBuffer() {
    if (!co_await EnsureReadablePayload()) {
        co_return buf::MultiBuffer{};
    }
    buf::BufferGuard buffer{buf::Buffer::New()};
    if (!buffer) {
        throw std::bad_alloc();
    }
    const size_t n = ConsumeReadablePayload(
        net::buffer(buffer->Tail().data(), buffer->Available()));
    if (n == 0) {
        co_return buf::MultiBuffer{};
    }
    buffer->Produce(static_cast<uint32_t>(n));
    co_return buf::MultiBuffer{std::move(buffer)};
}

net::awaitable<void> Http2ServerSubStreamState::WriteMultiBuffer(
    buf::MultiBuffer mb) {
    if (payload_codec_ == H2PayloadCodec::RawData) {
        ConstBufferSpanBuilder<16> payloads;
        payloads.AppendMultiBuffer(mb);

        try {
            if (!payloads.empty()) {
                auto session = LockWritableSession();
                if (!co_await session->WriteDataSerialized(stream_id_, payloads.Span())) {
                    ThrowHttp2StreamError("HTTP/2 raw server stream WriteMultiBuffer failed");
                }
            }
        } catch (...) {
            mb.clear();
            throw;
        }

        mb.clear();
        co_return;
    }

    for (buf::Buffer*& buffer : mb) {
        if (!buffer) {
            continue;
        }
        if (!buffer->IsEmpty()) {
            const auto bytes = buffer->Bytes();
            try {
                (void)co_await AsyncWrite(net::buffer(bytes.data(), bytes.size()));
            } catch (...) {
                mb.FreeSlot(buffer);
                mb.clear();
                throw;
            }
        }
        mb.FreeSlot(buffer);
    }
    mb.clear();
}

net::awaitable<void> Http2ServerSubStreamState::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (payload_codec_ == H2PayloadCodec::RawData) {
        const bool has_data = std::any_of(buffers.begin(), buffers.end(),
            [](const net::const_buffer& buffer) { return buffer.size() > 0; });
        if (!has_data) {
            co_return;
        }
        auto session = LockWritableSession();
        if (!co_await session->WriteDataSerialized(stream_id_, buffers)) {
            ThrowHttp2StreamError("HTTP/2 raw server stream WriteBuffers failed");
        }
        co_return;
    }

    for (const auto& buffer : buffers) {
        if (buffer.size() == 0) {
            continue;
        }
        (void)co_await AsyncWrite(buffer);
    }
}

net::awaitable<void> Http2ServerSubStreamState::AsyncShutdownWrite() {
    if (trailers_sent_) {
        co_return;
    }
    write_closed_ = true;
    trailers_sent_ = true;
    if (auto session = session_.lock()) {
        const bool sent = payload_codec_ == H2PayloadCodec::RawData
            ? co_await session->WriteFrameSerialized(
                  H2FrameType::DATA, kFlagEndStream, stream_id_)
            : co_await session->WriteTrailersSerialized(stream_id_);
        if (!sent) {
            trailers_sent_ = false;
        }
    }
}

void Http2ServerSubStreamState::PopFrontDataFrame() noexcept {
    const auto& front = data_frames_.front();
    const size_t storage = front.payload.capacity();
    queued_storage_ -= storage;
    if (auto session = LockSession()) session->ReleaseReceiveMemory(storage);
    if (upload_reserved_ != 0) {
        if (auto budget = upload_budget_.lock()) {
            budget->Release(storage);
        }
        upload_reserved_ -= std::min(upload_reserved_, storage);
    }
    data_frames_.pop_front();
    read_offset_ = 0;
}

void Http2ServerSubStreamState::DropQueuedData() noexcept {
    const size_t discarded = std::exchange(queued_bytes_, 0);
    const size_t upload_reserved = std::exchange(upload_reserved_, 0);
    if (upload_reserved != 0) {
        if (auto budget = upload_budget_.lock()) {
            budget->Release(upload_reserved);
        }
    }
    upload_budget_.reset();
    data_frames_.clear();
    read_offset_ = 0;
    ReleaseDecoderStorage();
    if (auto session = LockSession()) {
        session->ReleaseReceiveMemory(std::exchange(queued_storage_, 0));
        session->ReturnReceiveCredit(0, discarded);
    }
}

void Http2ServerSubStreamState::ConsumeData(size_t size) noexcept {
    queued_bytes_ -= size;
    if (auto session = LockSession()) session->ReturnReceiveCredit(stream_id_, size);
}

void Http2ServerSubStreamState::ReleaseDecoderStorage() noexcept {
    if (auto session = LockSession()) {
        session->ReleaseReceiveMemory(std::exchange(decoder_reserved_, 0));
    }
}

net::awaitable<bool> Http2ServerSubStreamState::WaitForDataFrame() {
    while (!cancelled_) {
        while (!data_frames_.empty()) {
            const auto& front = data_frames_.front();
            if (read_offset_ < front.offset) {
                read_offset_ = front.offset;
            }
            if (read_offset_ < front.end) {
                co_return true;
            }
            PopFrontDataFrame();
        }

        if (input_done_ || read_closed_) {
            co_return false;
        }

        const uint64_t epoch = read_abort_epoch_;
        auto [ec] = co_await input_signal_.async_receive(
            net::as_tuple(net::use_awaitable));
        if (ec || epoch != read_abort_epoch_) {
            throw IoSystemError(io_error::operation_aborted, "HTTP/2 raw read cancelled");
        }
    }
    throw IoSystemError(terminal_error_, "HTTP/2 stream terminated");
}

net::awaitable<bool> Http2ServerSubStreamState::EnsureReadablePayload() {
    if (payload_codec_ == H2PayloadCodec::RawData) co_return co_await WaitForDataFrame();
    while (hunk_.Payload().empty()) {
        if (!co_await WaitForDataFrame()) {
            if (!hunk_.AtMessageBoundary()) {
                ReleaseDecoderStorage();
                AbortLocal();
                ThrowHttp2StreamError("truncated gRPC message");
            }
            co_return false;
        }
        const auto& front = data_frames_.front();
        auto bytes = std::span<const uint8_t>(front.payload).subspan(
            read_offset_, front.end - read_offset_);
        const size_t limit = std::min(bytes.size(), hunk_.NextFeedLimit());
        bytes = bytes.subspan(0, limit);
        // The decoder is a bounded internal consumer: fragmented gRPC
        // messages may exceed the peer's stream window, so credit must advance
        // while assembling them. Its vector grows by at most 1.5x, with a
        // 256-byte floor; charge a conservative 2x bound before Feed allocates.
        // This prevents 256 partial messages bypassing the connection budget.
        const size_t reserve = 2 * bytes.size() + (decoder_reserved_ == 0 ? 256 : 0);
        const auto session = LockSession();
        if (!session || !session->ReserveReceiveMemory(reserve)) {
            if (session) session->RejectReceiveBudget(stream_id_);
            else AbortLocal();
            throw IoSystemError(io_error::no_buffer_space, "HTTP/2 gRPC receive budget exhausted");
        }
        decoder_reserved_ += reserve;
        const auto consumed = hunk_.Feed(bytes);
        if (!consumed) {
            ReleaseDecoderStorage();
            AbortLocal();
            ThrowHttp2StreamError(consumed.error().data());
        }
        const size_t unused_reservation = 2 * (bytes.size() - *consumed);
        session->ReleaseReceiveMemory(unused_reservation);
        decoder_reserved_ -= unused_reservation;
        read_offset_ += *consumed;
        if (read_offset_ == front.end) PopFrontDataFrame();
        if (hunk_.Payload().empty() && hunk_.AtMessageBoundary()) ReleaseDecoderStorage();
        ConsumeData(*consumed);
    }
    co_return true;
}

size_t Http2ServerSubStreamState::ConsumeReadablePayload(
    net::mutable_buffer buffer) noexcept {
    auto* out = static_cast<uint8_t*>(buffer.data());
    const size_t capacity = buffer.size();
    if (payload_codec_ == H2PayloadCodec::RawData) {
        const auto& front = data_frames_.front();
        const size_t n = std::min(capacity, front.end - read_offset_);
        std::memcpy(out, front.payload.data() + read_offset_, n);
        read_offset_ += n;
        if (read_offset_ == front.end) {
            PopFrontDataFrame();
        }
        ConsumeData(n);
        return n;
    }
    const auto payload = hunk_.Payload();
    const size_t n = std::min(capacity, payload.size());
    std::memcpy(out, payload.data(), n);
    hunk_.Consume(n);
    if (hunk_.Payload().empty()) ReleaseDecoderStorage();
    return n;
}

int Http2ServerSubStream::NativeHandle() const {
    if (closed_) {
        return -1;
    }
    auto session = state_->LockSession();
    const auto* inner = session ? session->InnerStream() : nullptr;
    return inner ? inner->NativeHandle() : -1;
}

bool Http2ServerSubStream::IsOpen() const {
    if (closed_) {
        return false;
    }
    auto session = state_->LockSession();
    const auto* inner = session ? session->InnerStream() : nullptr;
    return inner && inner->IsOpen();
}

TcpStream* Http2ServerSubStream::BaseTcpStream() {
    if (closed_) {
        return nullptr;
    }
    auto session = state_->LockSession();
    auto* inner = session ? session->InnerStream() : nullptr;
    return inner ? BaseTcpStreamOf(*inner) : nullptr;
}

const TcpStream* Http2ServerSubStream::BaseTcpStream() const {
    if (closed_) {
        return nullptr;
    }
    auto session = state_->LockSession();
    const auto* inner = session ? session->InnerStream() : nullptr;
    return inner ? BaseTcpStreamOf(*inner) : nullptr;
}

net::awaitable<TransportBuildResult> StartHttp2ServerSession(
    std::unique_ptr<AsyncStream> stream,
    uint32_t initial_window,
    H2PayloadCodec payload_codec,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id,
    const HttpConfig* http_config,
    const XHttpConfig* xhttp_config,
    const GrpcConfig* grpc_config,
    net::any_io_executor executor) {
    // SETTINGS is a receiver-selected limit, not a promise to allocate an
    // arbitrarily large configured window.
    initial_window = std::min<uint32_t>(initial_window, kHttp2MaxQueuedStreamBytes);
    auto session = memory::AllocateShared<Http2ServerSession>(
        io_context, std::move(stream), std::move(stream_handler), payload_codec,
        conn_id, http_config, xhttp_config, grpc_config, initial_window, std::move(executor));
    auto settings = EncodeInitialWindowSetting(initial_window);
    settings.resize(12);
    settings[6] = 0;
    settings[7] = 3; // SETTINGS_MAX_CONCURRENT_STREAMS
    StoreU32BE(settings.data() + 8, kHttp2MaxConcurrentStreams);
    if (!co_await session->WriteFrameSerialized(H2FrameType::SETTINGS, 0, 0, settings)) {
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
    std::array<uint8_t, 4> connection_credit{};
    StoreU32BE(connection_credit.data(),
               kHttp2ConnectionReceiveWindow - H2SendWindow::kDefault);
    if (!co_await session->WriteFrameSerialized(
            H2FrameType::WINDOW_UPDATE, 0, 0, connection_credit)) {
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
    co_await session->Run();
    co_return std::unique_ptr<AsyncStream>{};
}

// Client preface, SETTINGS and the request HEADERS on stream 1.
net::awaitable<bool> SendHttp2ClientRequest(AsyncStream& stream,
                                            uint32_t initial_window,
                                            uint32_t conn_window,
                                            std::span<const uint8_t> header_block,
                                            bool end_stream) {
    if (!co_await WriteFullToStream(stream, kHttp2ClientPreface)) {
        co_return false;
    }
    const auto settings = EncodeInitialWindowSetting(initial_window);
    if (!co_await WriteH2Frame(stream, H2FrameType::SETTINGS, 0, 0, settings)) {
        co_return false;
    }
    if (conn_window > H2SendWindow::kDefault) {
        std::array<uint8_t, 4> connection_credit{};
        StoreU32BE(connection_credit.data(),
                   conn_window - static_cast<uint32_t>(H2SendWindow::kDefault));
        if (!co_await WriteH2Frame(
                stream, H2FrameType::WINDOW_UPDATE, 0, 0, connection_credit)) {
            co_return false;
        }
    }
    co_return co_await WriteH2Frame(
        stream,
        H2FrameType::HEADERS,
        static_cast<uint8_t>(kFlagEndHeaders | (end_stream ? kFlagEndStream : 0)),
        1,
        header_block);
}

}  // namespace

net::awaitable<TransportBuildResult> DoGrpcServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id) {
    auto executor = CaptureHttp2Executor(io_context);
    std::array<uint8_t, kHttp2ClientPreface.size()> preface{};
    if (!co_await ReadFullFromStream(*stream, preface.data(), preface.size()) ||
        std::string_view(unsafe::ptr_cast<const char>(preface.data()), preface.size()) !=
            kHttp2ClientPreface) {
        LOG_CONN_DEBUG(conn_id, "gRPC server received invalid HTTP/2 client preface");
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    co_return co_await StartHttp2ServerSession(
        std::move(stream),
        cfg.initial_window_size.value_or(kDefaultInitialWindow),
        H2PayloadCodec::GrpcHunk,
        io_context,
        std::move(stream_handler),
        conn_id,
        nullptr,
        nullptr,
        &cfg,
        std::move(executor));
}

net::awaitable<TransportBuildResult> RunHttp2ServerSession(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    const XHttpConfig* xhttp_cfg,
    net::io_context& io_context,
    std::shared_ptr<InboundTransportStreamHandler> stream_handler,
    uint64_t conn_id) {
    co_return co_await StartHttp2ServerSession(
        std::move(stream),
        cfg.initial_window_size.value_or(kDefaultInitialWindow),
        H2PayloadCodec::RawData,
        io_context,
        std::move(stream_handler),
        conn_id,
        &cfg,
        xhttp_cfg,
        nullptr,
        CaptureHttp2Executor(io_context));
}

net::awaitable<TransportBuildResult> DoGrpcClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const GrpcConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id) {
    memory::ThreadLocalString fallback_path;
    std::string_view path = cfg.request_path;
    if (path.empty()) {
        fallback_path = ResolveGrpcRequestPath(cfg);
        path = fallback_path;
    }
    const uint32_t initial_window = std::min<uint32_t>(
        cfg.initial_window_size.value_or(kDefaultInitialWindow),
        kHttp2MaxQueuedStreamBytes);
    const uint32_t conn_window = std::min<uint32_t>(
        cfg.initial_window_size.value_or(H2SendWindow::kDefault),
        kHttp2MaxQueuedStreamBytes);
    const auto headers = EncodeGrpcRequestHeaders(
        authority,
        path,
        tls,
        cfg.user_agent.empty() ? std::string_view("grpc-go/1.0")
                               : std::string_view(cfg.user_agent));
    if (!co_await SendHttp2ClientRequest(
            *stream,
            initial_window,
            conn_window,
            headers,
            false)) {
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    LOG_CONN_DEBUG(conn_id,
        "gRPC client handshake sent authority={} path={}",
        authority.empty() ? std::string_view("-") : PublicHttpTargetForLog(authority),
        PublicHttpTargetForLog(path));
    co_return std::make_unique<Http2ClientStream>(
        std::move(stream),
        1,
        H2PayloadCodec::GrpcHunk,
        initial_window,
        conn_window);
}

net::awaitable<TransportBuildResult> DoHttp2ClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view authority,
    bool tls,
    uint64_t conn_id) {
    const auto headers = EncodeHttpRequestHeaders(authority, tls, cfg);
    const uint32_t initial_window = std::min<uint32_t>(
        cfg.initial_window_size.value_or(kDefaultInitialWindow),
        kHttp2MaxQueuedStreamBytes);
    const uint32_t conn_window = std::min<uint32_t>(
        cfg.initial_window_size.value_or(H2SendWindow::kDefault),
        kHttp2MaxQueuedStreamBytes);
    const bool request_body_expected = !EqualsAsciiCI(cfg.method, "GET");
    if (!co_await SendHttp2ClientRequest(
            *stream,
            initial_window,
            conn_window,
            headers,
            !request_body_expected)) {
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    LOG_CONN_DEBUG(conn_id,
        "HTTP/2 client handshake sent authority={} path={}",
        authority.empty() ? std::string_view("-") : PublicHttpTargetForLog(authority),
        PublicHttpTargetForLog(detail::EffectiveHttpPath(cfg.path)));
    co_return std::make_unique<Http2ClientStream>(
        std::move(stream),
        1,
        H2PayloadCodec::RawData,
        initial_window,
        conn_window,
        !request_body_expected);
}

}  // namespace transport::internet
