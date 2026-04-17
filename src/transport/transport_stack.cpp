#include "acppnode/transport/transport_stack.hpp"
#include "acppnode/transport/tcp_stream.hpp"
#include "acppnode/transport/tls_stream.hpp"
#include "acppnode/transport/ws_stream.hpp"
#include "acppnode/common/base64.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"

#include <openssl/sha.h>
#include <array>
#include <atomic>
#include <cctype>
#include <format>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

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

std::string MakeTlsCacheKey(std::string_view role, const TlsConfig& config) {
    std::string key;
    key.reserve(256);
    key.append(role);
    key.push_back('|');
    key.append(config.cert_file);
    key.push_back('|');
    key.append(config.key_file);
    key.push_back('|');
    key.append(config.ca_file);
    key.push_back('|');
    key.append(config.server_name);
    key.push_back('|');
    key.append(config.allow_insecure ? "1" : "0");
    key.push_back('|');
    key.append(config.min_version);
    key.push_back('|');
    key.append(config.max_version);

    for (const auto& suite : config.cipher_suites) {
        key.push_back('|');
        key.append(suite);
    }
    for (const auto& proto : config.alpn) {
        key.push_back('|');
        key.append(proto);
    }

    return key;
}

std::shared_ptr<SslContext> AcquireServerTlsContext(const TlsConfig& config) {
    static std::mutex cache_mu;
    static std::unordered_map<std::string, std::shared_ptr<SslContext>> cache;

    const std::string key = config.IsServer()
        ? MakeTlsCacheKey("server", config)
        : MakeTlsCacheKey("server-auto-sign", config);

    std::lock_guard lock(cache_mu);
    if (auto it = cache.find(key); it != cache.end()) {
        return it->second;
    }

    std::shared_ptr<SslContext> ctx;
    if (config.IsServer()) {
        ctx = SslContext::CreateServer(config);
    } else {
        ctx = SslContext::CreateServerAutoSign(config);
    }

    if (ctx) {
        cache.emplace(key, ctx);
    }
    return ctx;
}

std::shared_ptr<SslContext> AcquireClientTlsContext(const TlsConfig& config) {
    static std::mutex cache_mu;
    static std::unordered_map<std::string, std::shared_ptr<SslContext>> cache;

    const std::string key = MakeTlsCacheKey("client", config);

    std::lock_guard lock(cache_mu);
    if (auto it = cache.find(key); it != cache.end()) {
        return it->second;
    }

    std::shared_ptr<SslContext> ctx = SslContext::CreateClient(config);
    if (ctx) {
        cache.emplace(key, ctx);
    }
    return ctx;
}

[[nodiscard]] std::string_view ExtractHeaderValue(std::string_view request,
                                                  std::string_view name) {
    const size_t pos = request.find(name);
    if (pos == std::string_view::npos) {
        return {};
    }

    size_t start = pos + name.size();
    while (start < request.size() &&
           (request[start] == ' ' || request[start] == '\t')) {
        ++start;
    }

    const size_t end = request.find("\r\n", start);
    if (end == std::string_view::npos) {
        return {};
    }
    return request.substr(start, end - start);
}

[[nodiscard]] std::string_view ExtractHeaderValueAny(
    std::string_view request,
    std::initializer_list<std::string_view> names) {
    for (auto name : names) {
        auto value = ExtractHeaderValue(request, name);
        if (!value.empty()) {
            return value;
        }
    }
    return {};
}

[[nodiscard]] std::string_view ExtractRequestLine(std::string_view request) {
    const size_t end = request.find("\r\n");
    if (end == std::string_view::npos) {
        return request;
    }
    return request.substr(0, end);
}

[[nodiscard]] std::string_view ExtractRequestPath(std::string_view request_line) {
    constexpr std::string_view kGet = "GET ";
    if (!request_line.starts_with(kGet)) {
        return {};
    }

    const size_t start = kGet.size();
    const size_t end = request_line.find(' ', start);
    if (end == std::string_view::npos || end <= start) {
        return {};
    }
    return request_line.substr(start, end - start);
}

[[nodiscard]] std::string_view TrimAscii(std::string_view value) {
    while (!value.empty() &&
           (value.front() == ' ' || value.front() == '\t' ||
            value.front() == '\r' || value.front() == '\n')) {
        value.remove_prefix(1);
    }
    while (!value.empty() &&
           (value.back() == ' ' || value.back() == '\t' ||
            value.back() == '\r' || value.back() == '\n')) {
        value.remove_suffix(1);
    }
    return value;
}

[[nodiscard]] std::string SanitizeForLog(std::string_view value, size_t max_len = 160) {
    value = TrimAscii(value);
    if (value.empty()) {
        return "-";
    }

    const size_t limit = std::min(value.size(), max_len);
    std::string out;
    out.reserve(limit + 4);

    for (size_t i = 0; i < limit; ++i) {
        unsigned char ch = static_cast<unsigned char>(value[i]);
        if (ch == '\r' || ch == '\n' || ch == '\t') {
            out.push_back(' ');
        } else if (std::isprint(ch)) {
            out.push_back(static_cast<char>(ch));
        } else {
            out.push_back('?');
        }
    }

    if (value.size() > limit) {
        out.append("...");
    }
    return out;
}

// WebSocket 服务端握手（从原始流读 HTTP 请求，回复 101，返回 WsServerStream）
cobalt::task<TransportBuildResult> DoWsServerHandshake(
    std::unique_ptr<AsyncStream> stream,
    const WsConfig& ws_cfg,
    uint64_t conn_id,
    std::string* out_real_ip)
{
    std::array<uint8_t, 4096> buf{};
    size_t total = 0;

    // 读取直到找到 \r\n\r\n
    bool found = false;
    while (!found && total < buf.size()) {
        size_t n = co_await stream->AsyncRead(
            net::buffer(buf.data() + total, buf.size() - total));
        if (n == 0) {
            LOG_ACCESS_DEBUG("[WS:{}] server: peer closed during HTTP upgrade read", conn_id);
            co_return std::unexpected(ErrorCode::SOCKET_EOF);
        }
        total += n;
        std::string_view sv(unsafe::ptr_cast<char>(buf.data()), total);
        if (sv.find("\r\n\r\n") != std::string_view::npos) found = true;
    }
    if (!found) {
        std::string_view partial(unsafe::ptr_cast<char>(buf.data()), total);
        LOG_ACCESS_DEBUG("[WS:{}] server: HTTP upgrade request too large or incomplete", conn_id);
        LOG_ACCESS_TRACE("[WS:{}] server: incomplete upgrade bytes={} first_line='{}'",
                         conn_id,
                         total,
                         SanitizeForLog(ExtractRequestLine(partial)));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    const std::string_view request(unsafe::ptr_cast<char>(buf.data()), total);
    const std::string_view request_line = ExtractRequestLine(request);
    const std::string_view request_path = ExtractRequestPath(request_line);
    const std::string_view host = ExtractHeaderValueAny(request, {"Host:", "host:"});
    const std::string_view upgrade = ExtractHeaderValueAny(request, {"Upgrade:", "upgrade:"});
    const std::string_view connection = ExtractHeaderValueAny(request, {"Connection:", "connection:"});
    const std::string_view version = ExtractHeaderValueAny(
        request, {"Sec-WebSocket-Version:", "sec-websocket-version:"});
    const std::string_view user_agent = ExtractHeaderValueAny(request, {"User-Agent:", "user-agent:"});
    const std::string_view origin = ExtractHeaderValueAny(request, {"Origin:", "origin:"});
    const std::string_view subprotocol = ExtractHeaderValueAny(
        request, {"Sec-WebSocket-Protocol:", "sec-websocket-protocol:"});

    LOG_ACCESS_TRACE(
        "[WS:{}] server: upgrade request line='{}' path='{}' host='{}' upgrade='{}' connection='{}' version='{}' ua='{}' origin='{}' proto='{}' bytes={}",
        conn_id,
        SanitizeForLog(request_line),
        SanitizeForLog(request_path),
        SanitizeForLog(host),
        SanitizeForLog(upgrade),
        SanitizeForLog(connection),
        SanitizeForLog(version),
        SanitizeForLog(user_agent),
        SanitizeForLog(origin),
        SanitizeForLog(subprotocol),
        total);

    // 验证 Upgrade 头
    bool has_upgrade =
        request.find("Upgrade: websocket")  != std::string::npos ||
        request.find("Upgrade: Websocket")  != std::string::npos ||
        request.find("upgrade: websocket")  != std::string::npos;
    if (!has_upgrade) {
        LOG_ACCESS_DEBUG("[WS:{}] server: missing 'Upgrade: websocket' header", conn_id);
        LOG_ACCESS_TRACE("[WS:{}] server: reject missing upgrade line='{}' host='{}' upgrade='{}' connection='{}'",
                         conn_id,
                         SanitizeForLog(request_line),
                         SanitizeForLog(host),
                         SanitizeForLog(upgrade),
                         SanitizeForLog(connection));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // 验证路径（如果配置了非根路径）
    if (ws_cfg.path != "/" && !ws_cfg.path.empty()) {
        std::string get_line = "GET " + ws_cfg.path + " ";
        if (request.find(get_line) == std::string::npos) {
            LOG_ACCESS_DEBUG("[WS:{}] server: path mismatch, expected '{}'", conn_id, ws_cfg.path);
            LOG_ACCESS_TRACE("[WS:{}] server: reject path mismatch expected='{}' actual='{}' line='{}'",
                             conn_id,
                             ws_cfg.path,
                             SanitizeForLog(request_path),
                             SanitizeForLog(request_line));
            co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
    }

    // 提取单个 HTTP header 值（找不到则返回空串）
    // 提取 Sec-WebSocket-Key
    std::string_view ws_key = ExtractHeaderValue(request, "Sec-WebSocket-Key:");
    if (ws_key.empty()) {
        ws_key = ExtractHeaderValue(request, "sec-websocket-key:");
    }
    if (ws_key.empty()) {
        LOG_ACCESS_DEBUG("[WS:{}] server: missing Sec-WebSocket-Key header", conn_id);
        LOG_ACCESS_TRACE("[WS:{}] server: reject missing key line='{}' host='{}' version='{}'",
                         conn_id,
                         SanitizeForLog(request_line),
                         SanitizeForLog(host),
                         SanitizeForLog(version));
        co_return std::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // 提取真实客户端 IP（CDN 透传头）
    if (out_real_ip && !ws_cfg.real_ip_header.empty()) {
        std::string_view val = ExtractHeaderValue(request, ws_cfg.real_ip_header + ":");
        if (val.empty()) {
            // 大小写不敏感退路：转小写后再找一次
            std::string lower_name = ws_cfg.real_ip_header;
            for (auto& c : lower_name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            val = ExtractHeaderValue(request, lower_name + ":");
        }
        if (!val.empty()) {
            // X-Forwarded-For 可能是逗号分隔列表，取第一个
            auto comma = val.find(',');
            if (comma != std::string_view::npos) val = val.substr(0, comma);
            val = TrimAscii(val);
            if (!val.empty()) *out_real_ip = std::string(val);
        }
    }

    // 计算 Sec-WebSocket-Accept
    std::string accept = ComputeWsAccept(ws_key);

    // 发送 101
    std::string resp = std::format(
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: {}\r\n"
        "\r\n",
        accept);
    size_t sent = 0;
    while (sent < resp.size()) {
        size_t n = co_await stream->AsyncWrite(
            net::buffer(resp.data() + sent, resp.size() - sent));
        if (n == 0) {
            LOG_ACCESS_DEBUG("[WS:{}] server: failed to send 101 response", conn_id);
            co_return std::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
        sent += n;
    }

    // 创建 WsServerStream，将 HTTP 头后的数据作为 pending data
    auto ws = std::make_unique<WsServerStream>(std::move(stream), conn_id);
    size_t header_end = request.find("\r\n\r\n") + 4;
    if (header_end < total) {
        ws->SetPendingData(buf.data() + header_end, total - header_end);
    }
    LOG_ACCESS_TRACE(
        "[WS:{}] server: handshake accepted path='{}' host='{}' key_len={} pending={} real_ip_header='{}' real_ip='{}'",
        conn_id,
        ws_cfg.path.empty() ? "/" : ws_cfg.path,
        SanitizeForLog(host),
        TrimAscii(ws_key).size(),
        header_end < total ? (total - header_end) : 0,
        ws_cfg.real_ip_header.empty() ? "-" : ws_cfg.real_ip_header,
        (out_real_ip && !out_real_ip->empty()) ? *out_real_ip : std::string("-"));
    LOG_ACCESS_DEBUG("[WS:{}] server: handshake ok (path={})", conn_id, ws_cfg.path);
    co_return std::unique_ptr<AsyncStream>(std::move(ws));
}

}  // namespace

// ============================================================================
// TransportStack::BuildInbound
// ============================================================================
cobalt::task<TransportBuildResult> TransportStack::BuildInbound(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    std::string* out_real_ip,
    uint64_t trace_conn_id)
{
    std::unique_ptr<AsyncStream> stream = std::move(raw);

    // 1. TLS 层（服务端）
    if (s.IsTls()) {
        auto ctx = AcquireServerTlsContext(s.tls);
        if (!ctx) {
            LOG_ERROR("[TransportStack] BuildInbound: failed to create TLS server context");
            co_return std::unexpected(ErrorCode::TLS_CERT_INVALID);
        }

        auto* tcp_raw = dynamic_cast<TcpStream*>(stream.get());
        if (!tcp_raw) {
            LOG_ERROR("[TransportStack] BuildInbound: TLS requested but base stream is not TcpStream");
            co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        stream.release();
        auto tcp = std::unique_ptr<TcpStream>(tcp_raw);
        auto tls = co_await WrapTlsServer(std::move(tcp), *ctx);
        if (!tls) {
            LOG_ACCESS_DEBUG("[TransportStack] BuildInbound: TLS server handshake failed");
            co_return std::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
        }
        LOG_ACCESS_DEBUG("[TransportStack] BuildInbound: TLS handshake ok");
        stream = std::move(tls);
    }

    // 2. WebSocket 层（服务端）
    if (s.IsWs()) {
        uint64_t conn_id = trace_conn_id;
        if (conn_id == 0) {
            // 兜底：无上层连接号时使用本地自增计数器
            static std::atomic<uint64_t> s_conn_counter{1};
            conn_id = s_conn_counter.fetch_add(1, std::memory_order_relaxed);
        }
        auto ws_result = co_await DoWsServerHandshake(std::move(stream), s.ws, conn_id, out_real_ip);
        if (!ws_result) {
            LOG_ACCESS_DEBUG("[TransportStack] BuildInbound: WS server handshake failed ({})",
                             ErrorCodeToString(ws_result.error()));
            co_return std::unexpected(ws_result.error());
        }
        stream = std::move(*ws_result);
    }

    co_return stream;
}

// ============================================================================
// TransportStack::BuildOutbound
// ============================================================================
cobalt::task<TransportBuildResult> TransportStack::BuildOutbound(
    std::unique_ptr<AsyncStream> raw,
    const StreamSettings& s,
    const std::string& server_name)
{
    std::unique_ptr<AsyncStream> stream = std::move(raw);

    // 1. TLS 层（客户端）
    if (s.IsTls()) {
        auto ctx = AcquireClientTlsContext(s.tls);
        if (!ctx) {
            LOG_ERROR("[TransportStack] BuildOutbound: failed to create TLS client context");
            co_return std::unexpected(ErrorCode::TLS_CERT_INVALID);
        }

        std::string sni = server_name.empty() ? s.tls.server_name : server_name;
        auto* tcp_raw = dynamic_cast<TcpStream*>(stream.get());
        if (!tcp_raw) {
            LOG_ERROR("[TransportStack] BuildOutbound: TLS requested but base stream is not TcpStream");
            co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
        }
        stream.release();
        auto tcp = std::unique_ptr<TcpStream>(tcp_raw);
        auto tls = co_await WrapTlsClient(std::move(tcp), *ctx, sni, s.tls.alpn);
        if (!tls) {
            LOG_ACCESS_DEBUG("[TransportStack] BuildOutbound: TLS client handshake failed (sni={})", sni);
            co_return std::unexpected(ErrorCode::TLS_HANDSHAKE_FAILED);
        }
        LOG_ACCESS_DEBUG("[TransportStack] BuildOutbound: TLS handshake ok (sni={})", sni);
        stream = std::move(tls);
    }

    // 2. WebSocket 层（客户端）
    if (s.IsWs()) {
        static std::atomic<uint64_t> s_conn_counter_out{1};
        uint64_t conn_id = s_conn_counter_out.fetch_add(1, std::memory_order_relaxed);
        std::string host = server_name.empty() ? s.tls.server_name : server_name;
        auto ws = std::make_unique<WsClientStream>(std::move(stream), conn_id);
        auto ws_result = co_await ws->Handshake(
            host,
            s.ws.path.empty() ? "/" : s.ws.path,
            &s.ws.headers);
        if (!ws_result) {
            LOG_ACCESS_DEBUG("[TransportStack] BuildOutbound: WS client handshake failed ({})",
                             ErrorCodeToString(ws_result.error()));
            co_return std::unexpected(ws_result.error());
        }
        stream = std::move(ws);
    }

    co_return stream;
}

}  // namespace acpp
