#pragma once

#include "acppnode/handlers/udp_inbound_handler.hpp"
#include "acppnode/protocol/shadowsocks/shadowsocks_protocol.hpp"
#include "acppnode/app/rate_limiter.hpp"

#include <memory>

namespace acpp::ss {

// ============================================================================
// SsUdpInboundHandler — Shadowsocks AEAD UDP 入站协议处理器（无虚接口）
//
// 将 SS 协议逻辑完全封装在协议层：
//
//   Decode():
//     1. ban 检查（IsBanned，只读，不增加连接计数）
//     2. 多用户 HKDF+AEAD 解密（遍历所有用户尝试）
//     3. 认证失败记录（OnAuthFail → 触发 IP 封禁计数）
//     4. 构建 encode_reply（值捕获匹配用户密钥 + 密码套件）
//
// Worker 的 UDP 接收循环对 SS 协议细节完全无感知。
// ============================================================================
class SsUdpInboundHandler final {
public:
    SsUdpInboundHandler(SsUserManager&       user_manager,
                        SsCipherInfo         cipher_info,
                        ConnectionLimiterPtr limiter);

    [[nodiscard]] std::optional<UdpInboundDecodeResult> Decode(
        std::string_view tag,
        std::string_view client_ip,
        const uint8_t*   data,
        size_t           len);

    [[nodiscard]] std::string_view Protocol() const noexcept {
        return "shadowsocks";
    }

private:
    SsUserManager&       user_manager_;
    SsCipherInfo         cipher_info_;
    ConnectionLimiterPtr limiter_;
};

[[nodiscard]] std::unique_ptr<SsUdpInboundHandler> CreateSsUdpInboundHandler(
    SsUserManager&       user_manager,
    SsCipherInfo         cipher_info,
    ConnectionLimiterPtr limiter);

}  // namespace acpp::ss
