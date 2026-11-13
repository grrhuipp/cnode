#pragma once

#include "common/multi_buffer.hpp"
#include "common/const_buffer_span.hpp"
#include "transport/async_stream.hpp"
#include "transport/stream_settings.hpp"
#include "transport/transport_build_result.hpp"

#include <tl/expected.hpp>

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace transport {

// HTTP/1 message head starts in one Buffer; explicit larger budgets may grow
// owned storage only for bytes received. Bytes past the blank line are read-ahead.
struct Http1MessageHead {
    common::BufferGuard storage;
    std::string extended_storage;
    const uint8_t* bytes = nullptr;
    size_t header_end = 0;
    size_t size = 0;

    // Start line and header fields through the terminating blank line.
    [[nodiscard]] std::string_view Text() const noexcept {
        return {reinterpret_cast<const char*>(bytes), header_end};
    }
    [[nodiscard]] std::span<const uint8_t> ReadAhead() const noexcept {
        return {bytes + header_end, size - header_end};
    }
    [[nodiscard]] common::MultiBuffer TakeReadAheadMultiBuffer() {
        if (size <= header_end) {
            return {};
        }
        const size_t total_size = size;
        if (storage && bytes == storage->data) {
            size = header_end;
            storage->Reset();
            storage->Produce(static_cast<uint32_t>(total_size));
            storage->Advance(static_cast<uint32_t>(header_end));
            return common::MultiBuffer{std::move(storage)};
        }
        // Expanded heads retain their own storage; copy only the read-ahead.
        common::MultiBuffer mb;
        const auto read_ahead = ReadAhead();
        size = header_end;
        if (!mb.AppendSpan(read_ahead)) {
            throw std::bad_alloc();
        }
        return mb;
    }
};

struct Http1HeadReadLimits {
    // Zero keeps the ordinary transport's single-Buffer limit.
    size_t max_head_bytes = 0;
    // Content bytes, excluding CRLF; zero adds no separate line limit.
    size_t max_line_bytes = 0;
};

// `initial` holds bytes already consumed while sniffing the protocol.
[[nodiscard]] net::awaitable<tl::expected<void, common::ErrorCode>>
ReadHttp1MessageHead(AsyncStream& stream,
                     Http1MessageHead& head,
                     std::span<const uint8_t> initial = {},
                     Http1HeadReadLimits limits = {});
[[nodiscard]] net::awaitable<tl::expected<Http1MessageHead, common::ErrorCode>>
ReadHttp1MessageHead(AsyncStream& stream, std::span<const uint8_t> initial = {},
                     Http1HeadReadLimits limits = {});

[[nodiscard]] std::string_view ExtractStartLine(std::string_view head);
struct Http1RequestLine {
    std::string_view method;
    std::string_view target;
    std::string_view version;
};
// Preserves the transport's space-delimited target semantics; ignores trailing
// tokens. Log validation does not change which requests the protocol accepts.
[[nodiscard]] Http1RequestLine ParseHttp1RequestLine(std::string_view request_line);
[[nodiscard]] std::string_view ExtractHeaderValueCI(std::string_view head,
                                                    std::string_view name);
[[nodiscard]] size_t CountHeadersCI(std::string_view head, std::string_view name);
[[nodiscard]] bool HeaderContainsTokenCI(std::string_view value, std::string_view token);
// RFC 9110 5.3: repeated `name` field lines form one list; true when `token`
// is a member of any of them.
[[nodiscard]] bool HeaderListContainsTokenCI(std::string_view head,
                                             std::string_view name,
                                             std::string_view token);
[[nodiscard]] bool HasStatusCode(std::string_view status_line, std::string_view code);
void RecordExtractedRealIp(std::string_view head,
                           std::string_view header_name,
                           InboundTransportMetadata* metadata);

// Origin paths, absolute URLs and authorities share this log-only projection.
// Removes URL credentials/query/fragment; ambiguous URLs and control bytes are
// replaced with a fixed marker, never repaired into a plausible authority.
[[nodiscard]] std::string_view PublicHttpTargetForLog(std::string_view value);
[[nodiscard]] std::string_view PublicHttpMethodForLog(std::string_view value);
[[nodiscard]] std::string SanitizeHttpRequestLineForLog(const Http1RequestLine& line);

// 服务端收到的一个 HTTP/1 请求头。视图借用 head 的存储块（地址固定），在该块
// 存活期间有效，包括经 TakeReadAheadMultiBuffer 移交给后续读取方之后。
struct Http1Request {
    Http1MessageHead head;
    std::string_view start_line;
    Http1RequestLine line;
    // Host 字段值，已去除首尾空白。
    std::string_view host;
};

// HTTP、HTTPUpgrade、WebSocket 与 XHTTP 服务端共用的请求头前导：读取请求头、解析
// 请求行与 Host，并以 `scope`（如 "HTTP server"）为日志前缀记录读失败原因与脱敏后的
// 请求行。失败语义同 ReadHttp1MessageHead。
[[nodiscard]] net::awaitable<tl::expected<Http1Request, common::ErrorCode>> ReadHttp1Request(
    AsyncStream& stream,
    std::string_view scope,
    uint64_t conn_id,
    std::span<const uint8_t> initial = {});

// 配置了 `expected_host` 时，请求 Host 必须与之 ASCII 大小写无关相等；不符时记录
// DEBUG 并返回 true。
[[nodiscard]] bool RejectHostMismatch(std::string_view scope,
                                      uint64_t conn_id,
                                      std::string_view expected_host,
                                      std::string_view host);

// 握手直接运行在 TCP 或 TLS 之上：头部之后已读到的字节按序退回同一字节层，
// TLS 明文绝不进入 TCP 密文队列。
void MoveReadAhead(AsyncStream& stream, Http1MessageHead& head);

void AppendRequestStart(std::string& request,
                        std::string_view method,
                        std::string_view path,
                        std::string_view host);
void AppendHeaderLine(std::string& out,
                      std::string_view name,
                      std::string_view value);

using Http1ChunkPrefixBuffer = std::array<char, sizeof(size_t) * 2 + 2>;

template <size_t StackCapacity>
[[nodiscard]] inline bool AppendHttp1Chunk(
    common::ConstBufferSpanBuilder<StackCapacity>& out,
    Http1ChunkPrefixBuffer& prefix,
    std::span<const net::const_buffer> payloads,
    size_t payload_len) {
    static constexpr std::array<char, 2> kChunkTail{'\r', '\n'};
    auto [ptr, ec] = std::to_chars(
        prefix.data(),
        prefix.data() + prefix.size() - 2,
        payload_len,
        16);
    if (ec != std::errc{}) {
        return false;
    }
    *ptr++ = '\r';
    *ptr++ = '\n';
    out.Append(net::buffer(prefix.data(), static_cast<size_t>(ptr - prefix.data())));
    out.AppendBuffers(payloads);
    out.Append(net::buffer(kChunkTail.data(), kChunkTail.size()));
    return true;
}
[[nodiscard]] net::awaitable<tl::expected<Http1MessageHead, common::ErrorCode>>
ExecuteHttp1UpgradeClientHandshake(
    AsyncStream& stream,
    std::string_view scope,
    uint64_t conn_id,
    std::string_view host,
    std::string_view path,
    const HttpHeaders* headers = nullptr,
    std::string_view ws_key = {});

// Writes all of `bytes`. False when the write fails; the caller maps it to
// SOCKET_WRITE_FAILED.
[[nodiscard]] net::awaitable<bool> WriteFullToStream(AsyncStream& stream,
                                                     std::string_view bytes);
// Fills `out` completely. False when the peer closes first; I/O errors throw.
[[nodiscard]] net::awaitable<bool> ReadFullFromStream(AsyncStream& stream,
                                                      std::span<uint8_t> out);

// How a received HTTP/1 message body ends (RFC 9112 6.3).
struct Http1BodyUntilClose {};
struct Http1BodyChunked {};
struct Http1BodyContentLength {
    uint64_t bytes = 0;
};
using Http1ReadFraming =
    std::variant<Http1BodyUntilClose, Http1BodyChunked, Http1BodyContentLength>;

struct Http1ResponseHead {
    Http1MessageHead head;
    int status = 0;
    Http1ReadFraming framing = Http1BodyUntilClose{};
    size_t header_bytes = 0; // Includes all interim heads and the final head.
};

// Reads the final response, consuming bounded interim heads. Applies RFC 9112
// message-length precedence and rejects unsupported transfer codings.
[[nodiscard]] net::awaitable<tl::expected<Http1ResponseHead, common::ErrorCode>>
ReadHttp1ResponseHead(AsyncStream& stream, Http1HeadReadLimits limits = {});

struct Http1BodyReadOptions {
    uint64_t max_body_bytes = std::numeric_limits<uint64_t>::max();
    size_t max_line_bytes = 8192 - 2; // Chunk/trailer line content, excluding CRLF.
    size_t max_trailer_lines = 128;
    size_t max_trailer_bytes = 64 * 1024;
    bool count_trailer_terminator = false;
    bool reject_trailing_read_ahead = false;
};

// HTTP/1 message body over an established connection; `read_ahead` is body
// data already read with the message head. Bytes past a chunked or
// Content-Length body never reach the reader.
// One-shot consumers may reject already-buffered bytes beyond that boundary;
// no extra socket read is performed to look for a following message.
[[nodiscard]] std::unique_ptr<AsyncStream> MakeHttp1BodyStream(
    std::unique_ptr<AsyncStream> inner,
    Http1ReadFraming read_framing,
    bool write_chunked,
    common::MultiBuffer&& read_ahead = {},
    Http1BodyReadOptions read_options = {});

[[nodiscard]] net::awaitable<TransportBuildResult> DoHttp1ServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata,
    std::span<const uint8_t> initial);

[[nodiscard]] net::awaitable<TransportBuildResult> DoHttp1ClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    std::string_view host,
    uint64_t conn_id);

[[nodiscard]] net::awaitable<TransportBuildResult> DoHttpUpgradeServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpUpgradeConfig& cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata);

[[nodiscard]] net::awaitable<TransportBuildResult> DoHttpUpgradeClientHandshake(
    std::unique_ptr<AsyncStream> stream,
    const HttpUpgradeConfig& cfg,
    std::string_view host,
    uint64_t conn_id);

[[nodiscard]] net::awaitable<TransportBuildResult> DoWsServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const WsConfig& ws_cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata);

}  // namespace transport
