#pragma once

#include "acppnode/transport/tls_stream.hpp"  // TlsConfig
#include <boost/json.hpp>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace acpp {

// ============================================================================
// 传输模式缓存（初始化期归一化，运行时零字符串比较）
// ============================================================================
enum class NetworkMode : uint8_t {
    Tcp = 0,
    Ws  = 1,
};

enum class SecurityMode : uint8_t {
    None = 0,
    Tls  = 1,
};

enum StreamFlags : uint8_t {
    kFlagNone = 0,
    kFlagWs   = 1 << 0,
    kFlagTls  = 1 << 1,
};

// ============================================================================
// WebSocket 传输配置
// ============================================================================
struct WsConfig {
    std::string path = "/";
    std::unordered_map<std::string, std::string> headers;

    // 若非空，从该 HTTP header 提取真实客户端 IP（覆盖 TCP 层地址）。
    // 典型值："CF-Connecting-IP"、"X-Real-IP"、"X-Forwarded-For"。
    // 留空则禁用（不信任任何 header）。
    std::string real_ip_header;

    static WsConfig FromJson(const boost::json::object& j);
};

// ============================================================================
// StreamSettings - 传输层 + 安全层组合配置
//
// 实现 Xray 式「传输层自由组合」：
//   network (tcp | ws)  ×  security (none | tls)
//
// 示例：
//   { "network": "ws",  "security": "tls" }  → WS over TLS
//   { "network": "tcp", "security": "tls" }  → TCP + TLS
//   { "network": "tcp", "security": "none" } → 明文 TCP
// ============================================================================
struct StreamSettings {
    std::string network  = "tcp";   // "tcp" | "ws"
    std::string security = "none";  // "none" | "tls"

    TlsConfig tls;  // 当 security == "tls" 时生效
    WsConfig  ws;   // 当 network  == "ws"  时生效

    // 归一化后的缓存字段（热路径使用）
    NetworkMode  network_mode  = NetworkMode::Tcp;
    SecurityMode security_mode = SecurityMode::None;
    uint8_t      flags         = kFlagNone;

    bool IsTls() const noexcept { return (flags & kFlagTls) != 0; }
    bool IsWs()  const noexcept { return (flags & kFlagWs)  != 0; }

    // 供手动赋值场景调用（如面板动态配置构建）
    void RecomputeModes() noexcept;

    static StreamSettings FromJson(const boost::json::object& j);
};

}  // namespace acpp
