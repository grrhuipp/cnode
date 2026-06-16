#pragma once

#include "acppnode/core/constants.hpp"
#include "acppnode/infra/json.hpp"
#include "acppnode/transport/internet/http_headers.hpp"
#include "acppnode/transport/internet/tls_config.hpp"
#include <cstdint>
#include <string>

namespace acpp {

// ============================================================================
// 传输模式缓存（初始化期归一化，运行时零字符串比较）
// ============================================================================
enum class NetworkMode : uint8_t {
    Tcp = 0,
    Ws  = 1,
    HttpUpgrade = 2,
    Grpc = 3,
    XHttp = 4,
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
    kFlagXHttp       = 1 << 4,
    kFlagReality     = 1 << 5,
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
// gRPC 传输配置
// ============================================================================
struct GrpcConfig {
    std::string authority;
    std::string service_name;
    std::string user_agent;
    bool multi_mode = false;
    int initial_window_size = 0;

    static GrpcConfig FromJson(const json::object& j);
    [[nodiscard]] std::string RequestPath() const;
};

// ============================================================================
// StreamSettings - 传输层 + 安全层组合配置
//
// 实现 Xray 式「传输层自由组合」：
//   network (raw/tcp | ws/websocket | httpupgrade | grpc | xhttp)
//     × security (none | tls | reality)
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
    WsConfig  ws;              // 当 network  == "ws" / "websocket" 时生效
    HttpUpgradeConfig http_upgrade; // 当 network == "httpupgrade" 时生效
    GrpcConfig grpc;           // 当 network == "grpc" 时生效

    // 归一化后的缓存字段（热路径使用）
    NetworkMode  network_mode  = NetworkMode::Tcp;
    SecurityMode security_mode = SecurityMode::None;
    uint8_t      flags         = kFlagNone;

    bool IsTls() const noexcept { return (flags & kFlagTls) != 0; }
    bool IsReality() const noexcept { return (flags & kFlagReality) != 0; }
    bool IsWs()  const noexcept { return (flags & kFlagWs)  != 0; }
    bool IsHttpUpgrade() const noexcept { return (flags & kFlagHttpUpgrade) != 0; }
    bool IsGrpc() const noexcept { return (flags & kFlagGrpc) != 0; }
    bool IsXHttp() const noexcept { return (flags & kFlagXHttp) != 0; }
    bool IsUnsupported() const noexcept {
        return network_mode == NetworkMode::Unsupported ||
               security_mode == SecurityMode::Unsupported;
    }
    bool NeedsHttpRealIpExtraction() const noexcept {
        return (IsWs() && !ws.real_ip_header.empty()) ||
               (IsHttpUpgrade() && !http_upgrade.real_ip_header.empty());
    }

    // 供手动赋值场景调用（如面板动态配置构建）
    void RecomputeModes() noexcept;

    static StreamSettings FromJson(const json::object& j);
};

}  // namespace acpp
