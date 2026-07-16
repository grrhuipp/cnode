#pragma once

#include "acppnode/core/constants.hpp"
#include "acppnode/infra/json.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"
#include "acppnode/transport/internet/http_headers.hpp"
#include "acppnode/transport/internet/tls_config.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace acpp {

struct XHttpDownloadSettings;

// ============================================================================
// 传输模式缓存（初始化期归一化，运行时零字符串比较）
// ============================================================================
enum class NetworkMode : uint8_t {
    Tcp = 0,
    Ws  = 1,
    HttpUpgrade = 2,
    Grpc = 3,
    Http = 4,
    XHttp = 5,
    Unsupported = 255,
};

enum class SecurityMode : uint8_t {
    None = 0,
    Tls  = 1,
    Reality = 2,
    Unsupported = 255,
};

enum StreamFlags : uint8_t {
    kFlagNone        = 0,
    kFlagWs          = 1 << 0,
    kFlagTls         = 1 << 1,
    kFlagHttpUpgrade = 1 << 2,
    kFlagGrpc        = 1 << 3,
    kFlagHttp        = 1 << 4,
    kFlagXHttp       = 1 << 5,
    kFlagReality     = 1 << 6,
};

// ============================================================================
// WebSocket 传输配置
// ============================================================================
struct WsConfig {
    std::string path = std::string(constants::binding::kRootPath);
    transport::internet::HttpHeaders headers;

    // 若非空，从该 HTTP header 提取真实客户端 IP（覆盖 TCP 层地址）。
    // 典型值："CF-Connecting-IP"、"X-Real-IP"、"X-Forwarded-For"。
    // 留空则禁用（不信任任何 header）。
    std::string real_ip_header;

    static WsConfig FromJson(const json::object& j);
};

// ============================================================================
// HTTPUpgrade 传输配置
// ============================================================================
struct HttpUpgradeConfig {
    std::string path = std::string(constants::binding::kRootPath);
    std::string host;
    transport::internet::HttpHeaders headers;

    // 与 WS 相同，只在明确配置后信任指定 header。
    std::string real_ip_header;

    // Xray httpupgradeSettings 字段；cnode 的 PROXY protocol 已在 receiver
    // 层处理，这里只保留归一化结果，避免 transport 再次读取连接前缀。
    bool accept_proxy_protocol = false;

    static HttpUpgradeConfig FromJson(const json::object& j);
};

// ============================================================================
// V2Ray HTTP / h2 传输配置
// ============================================================================
struct HttpConfig {
    std::string path = std::string(constants::binding::kRootPath);
    std::string host;
    std::string method;
    transport::internet::HttpHeaders headers;

    // 明确配置后才信任指定 header 覆盖 TCP 层源地址。
    std::string real_ip_header;

    // network == "h2" 时强制使用 HTTP/2；network == "http" 时按生态习惯：
    // TLS 默认 HTTP/2，显式 ALPN=http/1.1 时使用 HTTP/1.1，明文使用 HTTP/1.1。
    bool force_http2 = false;

    std::optional<uint32_t> initial_window_size;

    static HttpConfig FromJson(const json::object& j);
};

// ============================================================================
// gRPC 传输配置
// ============================================================================
struct GrpcConfig {
    std::string authority;
    std::string service_name;
    std::string user_agent;
    bool multi_mode = false;
    std::optional<uint32_t> initial_window_size;

    static GrpcConfig FromJson(const json::object& j);
    [[nodiscard]] std::string RequestPath() const;
};

// ============================================================================
// XHTTP / SplitHTTP 传输配置
// ============================================================================
struct XHttpConfig {
    std::string path = std::string(constants::binding::kRootPath);
    std::string host;
    std::string mode;
    transport::internet::HttpHeaders headers;
    std::shared_ptr<const XHttpDownloadSettings> download_settings;

    bool no_grpc_header = false;
    bool no_sse_header = false;

    static XHttpConfig FromJson(const json::object& j);
    [[nodiscard]] std::string NormalizedPath() const;
    [[nodiscard]] bool IsStreamOne() const noexcept;
    [[nodiscard]] bool AcceptsStreamOne() const noexcept;
    [[nodiscard]] bool AcceptsPacketUp() const noexcept;
    [[nodiscard]] bool AcceptsStreamUp() const noexcept;
};

// ============================================================================
// REALITY 安全层配置
// ============================================================================
struct RealityConfig {
    // 服务端字段
    bool show = false;
    std::string type;
    std::string dest;
    uint8_t xver = 0;
    std::vector<std::string> server_names;
    std::string private_key;
    std::vector<std::string> short_ids;
    std::string min_client_ver;
    std::string max_client_ver;
    uint64_t max_time_diff = 0;
    std::string mldsa65_seed;

    // 客户端字段
    std::string fingerprint;
    std::string server_name;
    std::string public_key;
    std::string short_id;
    std::string spider_x;
    std::string mldsa65_verify;

    // 调试/兼容字段
    std::string master_key_log;

    [[nodiscard]] bool IsServer() const noexcept { return !private_key.empty(); }
    [[nodiscard]] bool IsClient() const noexcept { return !public_key.empty(); }

    static RealityConfig FromJson(const json::object& j);
};

// ============================================================================
// StreamSettings - 传输层 + 安全层组合配置
//
// 实现 Xray 式「传输层自由组合」：
//   network (raw/tcp | ws/websocket | http/http2/h2 | httpupgrade | grpc | xhttp/splithttp)
//     × security (none | tls)
//   REALITY 按 Xray 生态约束只支持 raw/tcp、grpc、xhttp/splithttp。
//
// 示例：
//   { "network": "ws", "security": "tls" }          → WS over TLS
//   { "network": "httpupgrade", "security": "tls" } → HTTPUpgrade over TLS
//   { "network": "tcp", "security": "none" }        → 明文 TCP
// ============================================================================
struct StreamSettings {
    std::string network  = std::string(constants::protocol::kTcp);
    std::string security = std::string(constants::protocol::kNone);

    TlsConfig tls;             // 当 security == "tls" 时生效
    RealityConfig reality;     // 当 security == "reality" 时生效
    WsConfig  ws;              // 当 network  == "ws" / "websocket" 时生效
    HttpUpgradeConfig http_upgrade; // 当 network == "httpupgrade" 时生效
    HttpConfig http;            // 当 network == "http" / "h2" 时生效
    GrpcConfig grpc;           // 当 network == "grpc" 时生效
    XHttpConfig xhttp;          // 当 network == "xhttp" / "splithttp" 时生效

    // 归一化后的缓存字段（热路径使用）
    NetworkMode  network_mode  = NetworkMode::Tcp;
    SecurityMode security_mode = SecurityMode::None;
    uint8_t      flags         = kFlagNone;

    bool IsTls() const noexcept { return (flags & kFlagTls) != 0; }
    bool IsReality() const noexcept { return (flags & kFlagReality) != 0; }
    bool IsTlsLike() const noexcept { return IsTls() || IsReality(); }
    bool IsWs()  const noexcept { return (flags & kFlagWs)  != 0; }
    bool IsHttpUpgrade() const noexcept { return (flags & kFlagHttpUpgrade) != 0; }
    bool IsHttp() const noexcept { return (flags & kFlagHttp) != 0; }
    bool IsGrpc() const noexcept { return (flags & kFlagGrpc) != 0; }
    bool IsXHttp() const noexcept { return (flags & kFlagXHttp) != 0; }
    bool IsUnsupported() const noexcept {
        return network_mode == NetworkMode::Unsupported ||
               security_mode == SecurityMode::Unsupported;
    }
    bool NeedsHttpRealIpExtraction() const noexcept {
        return (IsWs() && !ws.real_ip_header.empty()) ||
               (IsHttpUpgrade() && !http_upgrade.real_ip_header.empty()) ||
               (IsHttp() && !http.real_ip_header.empty());
    }

    // 供手动赋值场景调用（如面板动态配置构建）
    void RecomputeModes() noexcept;

    static StreamSettings FromJson(const json::object& j);
};

struct XHttpDownloadSettings {
    std::string address;
    uint16_t port = 0;
    OutboundBind send_through;
    StreamSettings stream_settings;
};

}  // namespace acpp
