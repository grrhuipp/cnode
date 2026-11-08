#pragma once

#include "common/buf/multi_buffer.hpp"
#include "common/unsafe.hpp"
#include "transport/internet/transport_stack.hpp"

#include <tl/expected.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace transport::internet {

// HTTP/1 message head read into one pooled Buffer. Bytes past the blank line
// are read-ahead that the caller must hand to the next reader in order.
struct Http1MessageHead {
    buf::BufferGuard storage;
    const uint8_t* bytes = nullptr;
    size_t header_end = 0;
    size_t size = 0;

    // Start line and header fields through the terminating blank line.
    [[nodiscard]] std::string_view Text() const noexcept {
        return {unsafe::ptr_cast<const char>(bytes), header_end};
    }
    [[nodiscard]] std::span<const uint8_t> ReadAhead() const noexcept {
        return {bytes + header_end, size - header_end};
    }
};

// `initial` holds bytes already consumed while sniffing the protocol. Fails
// with SOCKET_EOF on peer close and PROTOCOL_DECODE_FAILED when the head does
// not fit one Buffer.
[[nodiscard]] net::awaitable<tl::expected<void, ErrorCode>>
ReadHttp1MessageHead(AsyncStream& stream,
                     Http1MessageHead& head,
                     std::span<const uint8_t> initial = {});
[[nodiscard]] net::awaitable<tl::expected<Http1MessageHead, ErrorCode>>
ReadHttp1MessageHead(AsyncStream& stream, std::span<const uint8_t> initial = {});

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

[[nodiscard]] std::string SanitizeForLog(std::string_view value, size_t max_len = 160);
// Origin paths, absolute URLs and authorities share this log-only projection.
// Removes URL credentials/query/fragment; ambiguous URLs and control bytes are
// replaced with a fixed marker, never repaired into a plausible authority.
[[nodiscard]] std::string_view PublicHttpTargetForLog(std::string_view value);
[[nodiscard]] std::string_view PublicHttpMethodForLog(std::string_view value);
[[nodiscard]] std::string SanitizeHttpRequestLineForLog(const Http1RequestLine& line);
[[nodiscard]] std::string_view ExpectedHttpHost(const HttpConfig& cfg);
[[nodiscard]] std::string_view ResolveHttpUpgradeHost(
    std::string_view fallback_host,
    std::string_view configured_host,
    const HttpHeaders* headers) noexcept;
[[nodiscard]] net::awaitable<tl::expected<Http1MessageHead, ErrorCode>>
ExecuteHttp1UpgradeClientHandshake(
    AsyncStream& stream,
    std::string_view scope,
    uint64_t conn_id,
    std::string_view host,
    std::string_view path,
    const HttpHeaders* headers = nullptr,
    std::string_view ws_key = {});

// Returns false instead of throwing; the caller maps it to SOCKET_WRITE_FAILED.
[[nodiscard]] net::awaitable<bool> WriteFullToStream(AsyncStream& stream,
                                                     std::string_view bytes);

// How a received HTTP/1 message body ends (RFC 9112 6.3).
struct Http1BodyUntilClose {};
struct Http1BodyChunked {};
struct Http1BodyContentLength {
    uint64_t bytes = 0;
};
using Http1ReadFraming =
    std::variant<Http1BodyUntilClose, Http1BodyChunked, Http1BodyContentLength>;

// HTTP/1 message body over an established connection; `read_ahead` is body
// data already read with the message head. Bytes past a chunked or
// Content-Length body never reach the reader.
[[nodiscard]] std::unique_ptr<AsyncStream> MakeHttp1BodyStream(
    std::unique_ptr<AsyncStream> inner,
    Http1ReadFraming read_framing,
    bool write_chunked,
    std::span<const uint8_t> read_ahead = {});

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

}  // namespace transport::internet
