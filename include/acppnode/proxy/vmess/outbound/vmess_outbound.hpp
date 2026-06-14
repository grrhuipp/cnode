#pragma once

#include "acppnode/common/defaults.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/proxy/vmess/account.hpp"
#include "acppnode/proxy/vmess/types.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace acpp {

namespace app::dns {
class DNS;
}  // namespace app::dns

// ============================================================================
// VMess Outbound 配置
// ============================================================================
struct VMessOutboundConfig {
    std::string tag;
    std::string address;           // 服务器地址
    std::optional<net::ip::address> literal_address; // 冷路径解析的 IP 字面量
    uint16_t port = 443;           // 服务器端口
    std::string uuid;              // 用户 UUID
    vmess::Security security = vmess::Security::AES_128_GCM;

    // 可选配置
    int alter_id = 0;              // AlterID (现代客户端通常为 0)

    // 传输层配置（JSON 格式保持不变）
    StreamSettings stream_settings;

    // 传输层拨号/握手超时
    std::chrono::seconds timeout{defaults::kDialTimeout};
};

// ============================================================================
// VMess Outbound（传输层：TCP + 可选 WS）
// ============================================================================
namespace proxy::vmess::outbound {

class Handler final : public ::acpp::Outbound {
public:
    Handler(const ::acpp::VMessOutboundConfig& config,
            ::acpp::app::dns::DNS& dns_service);

    // Outbound 接口
    ::acpp::net::awaitable<::acpp::OutboundProcessResult> Process(
        ::acpp::net::io_context& io_context,
        const ::acpp::tcp::endpoint* inbound_local_addr,
        ::acpp::session::Context& ctx,
        const ::acpp::TimeoutsConfig& timeouts,
        ::acpp::transport::Link inbound,
        ::acpp::StatsShard& stats,
        const ::acpp::RelayConfig& relay_config,
        std::span<const uint8_t> initial_payload,
        ::acpp::buf::MultiBuffer& first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;
    std::string_view Tag() const noexcept override { return config_.tag; }

private:
    ::acpp::VMessOutboundConfig config_;
    std::optional<::acpp::vmess::MemoryAccount> user_;
    ::acpp::app::dns::DNS& dns_service_;
};

}  // namespace proxy::vmess::outbound

}  // namespace acpp
