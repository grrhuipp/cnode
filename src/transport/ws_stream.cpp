#include "acppnode/transport/ws_stream.hpp"
#include "acppnode/common/base64.hpp"
#include "acppnode/common/unsafe.hpp"

#include <openssl/rand.h>
#include <cctype>

namespace acpp {

namespace {

[[nodiscard]] std::string ComputeWsAccept(std::string_view ws_key) {
    constexpr std::string_view kWsGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::string accept_src;
    accept_src.reserve(ws_key.size() + kWsGuid.size());
    accept_src.append(ws_key);
    accept_src.append(kWsGuid);

    uint8_t sha1[20];
    SHA1(unsafe::ptr_cast<const uint8_t>(accept_src.data()), accept_src.size(), sha1);
    return Base64Encode(sha1, sizeof(sha1));
}

[[nodiscard]] std::string_view ExtractHttpHeader(std::string_view response, std::string_view name) {
    const size_t pos = response.find(name);
    if (pos == std::string_view::npos) {
        return {};
    }

    size_t start = pos + name.size();
    while (start < response.size() && (response[start] == ' ' || response[start] == '\t')) {
        ++start;
    }
    const size_t end = response.find("\r\n", start);
    if (end == std::string_view::npos) {
        return {};
    }
    return response.substr(start, end - start);
}

}  // namespace

cobalt::task<WsHandshakeResult> WsClientStream::Handshake(
    const std::string& host,
    const std::string& path,
    const std::unordered_map<std::string, std::string>* headers) {
    // RFC 6455 §4.1: 密钥必须是随机生成的 16 字节 base64 编码
    uint8_t raw_key[16];
    if (RAND_bytes(raw_key, sizeof(raw_key)) != 1) [[unlikely]] {
        LOG_ACCESS_DEBUG("[conn={}] WS client: RAND_bytes failed", conn_id_);
        co_return std::unexpected(ErrorCode::INTERNAL);
    }
    std::string ws_key = Base64Encode(raw_key, sizeof(raw_key));

    const std::string_view req_path = path.empty() ? "/" : std::string_view(path);
    auto is_host_header = [](std::string_view key) {
        if (key.size() != 4) return false;
        return std::tolower(static_cast<unsigned char>(key[0])) == 'h' &&
               std::tolower(static_cast<unsigned char>(key[1])) == 'o' &&
               std::tolower(static_cast<unsigned char>(key[2])) == 's' &&
               std::tolower(static_cast<unsigned char>(key[3])) == 't';
    };

    size_t reserve_size = 256 + req_path.size() + host.size() + ws_key.size();
    if (headers) {
        for (const auto& [k, v] : *headers) {
            if (!is_host_header(k)) {
                reserve_size += k.size() + v.size() + 4; // ": " + "\r\n"
            }
        }
    }

    std::string request;
    request.reserve(reserve_size);
    request.append("GET ");
    request.append(req_path);
    request.append(" HTTP/1.1\r\n");
    request.append("Host: ");
    request.append(host);
    request.append("\r\n");
    request.append("Upgrade: websocket\r\n");
    request.append("Connection: Upgrade\r\n");
    request.append("Sec-WebSocket-Key: ");
    request.append(ws_key);
    request.append("\r\n");
    request.append("Sec-WebSocket-Version: 13\r\n");
    if (headers) {
        for (const auto& [k, v] : *headers) {
            if (is_host_header(k)) continue;
            request.append(k);
            request.append(": ");
            request.append(v);
            request.append("\r\n");
        }
    }
    request.append("\r\n");

    if (!co_await WriteFull(unsafe::ptr_cast<const uint8_t>(request.data()),
                            request.size())) {
        LOG_ACCESS_DEBUG("[conn={}] WS client: failed to send upgrade request", conn_id_);
        co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }

    std::array<char, 4096> response_buf{};
    size_t response_len = 0;
    bool found_end = false;
    size_t header_end = 0;

    while (!found_end && response_len < response_buf.size()) {
        size_t n = co_await inner_->AsyncRead(
            net::buffer(response_buf.data() + response_len, response_buf.size() - response_len));
        if (n == 0) {
            LOG_ACCESS_DEBUG("[conn={}] WS client: peer closed during upgrade response read", conn_id_);
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }

        response_len += n;
        std::string_view response(response_buf.data(), response_len);
        size_t pos = response.find("\r\n\r\n");
        if (pos != std::string_view::npos) {
            found_end = true;
            header_end = pos + 4;
        }
    }

    if (!found_end) {
        LOG_ACCESS_DEBUG("[conn={}] WS client: incomplete upgrade response", conn_id_);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view response(response_buf.data(), response_len);
    if (response.find("HTTP/1.1 101") == std::string_view::npos) {
        auto crlf = response.find("\r\n");
        std::string_view first_line = crlf != std::string_view::npos
            ? response.substr(0, crlf)
            : response.substr(0, std::min<size_t>(response.size(), 64));
        LOG_ACCESS_DEBUG("[conn={}] WS client: server rejected upgrade: {}",
                  conn_id_,
                  first_line);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view accept = ExtractHttpHeader(response, "Sec-WebSocket-Accept:");
    if (accept.empty()) {
        LOG_ACCESS_DEBUG("[conn={}] WS client: missing Sec-WebSocket-Accept", conn_id_);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string expected_accept = ComputeWsAccept(ws_key);
    if (accept != expected_accept) {
        LOG_ACCESS_DEBUG("[conn={}] WS client: invalid Sec-WebSocket-Accept", conn_id_);
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    if (header_end < response_len) {
        SetPendingData(unsafe::ptr_cast<const uint8_t>(response_buf.data() + header_end),
                       response_len - header_end);
    }

    LOG_ACCESS_DEBUG("[conn={}] WS client: handshake ok (host={} path={})", conn_id_, host, path);
    co_return {};
}

std::unique_ptr<AsyncStream> CreateWsServerStream(
    std::unique_ptr<AsyncStream> inner,
    uint64_t conn_id) {
    return std::make_unique<WsServerStream>(std::move(inner), conn_id);
}

std::unique_ptr<AsyncStream> CreateWsClientStream(
    std::unique_ptr<AsyncStream> inner,
    uint64_t conn_id) {
    return std::make_unique<WsClientStream>(std::move(inner), conn_id);
}

}  // namespace acpp
