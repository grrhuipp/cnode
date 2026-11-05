#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/unsafe.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"

#include <tl/expected.hpp>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace acpp::transport::internet {

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
[[nodiscard]] net::awaitable<tl::expected<Http1MessageHead, ErrorCode>>
ReadHttp1MessageHead(AsyncStream& stream, std::span<const uint8_t> initial = {});

[[nodiscard]] std::string_view ExtractStartLine(std::string_view head);
[[nodiscard]] std::string_view ExtractRequestMethod(std::string_view request_line);
[[nodiscard]] std::string_view ExtractRequestTarget(std::string_view request_line);
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
// Removes URL credentials, query and fragment without changing protocol input.
[[nodiscard]] std::string_view PublicHttpTargetForLog(std::string_view value);
[[nodiscard]] std::string SanitizeHttpRequestLineForLog(std::string_view value);
[[nodiscard]] std::string_view ExpectedHttpHost(const HttpConfig& cfg);

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

}  // namespace acpp::transport::internet
