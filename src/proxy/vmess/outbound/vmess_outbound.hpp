#pragma once

#include "acppnode/common/defaults.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "../account.hpp"
#include "../types.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/transport/internet/transport_security.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"

#include <openssl/aes.h>

#include <chrono>
#include <cstdint>
#include <memory>
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
    std::string address;           // 服务器地址
    std::optional<net::ip::address> literal_address; // 冷路径解析的 IP 字面量
    uint16_t port = 443;           // 服务器端口
    vmess::Security security = vmess::Security::AES_128_GCM;

    // 传输层配置（JSON 格式保持不变）
    StreamSettings stream_settings;
    OutboundBind send_through;

};

// ============================================================================
// VMess Outbound（传输层：TCP + 可选 WS）
// ============================================================================
namespace proxy::vmess::outbound {

struct PreparedSettings {
    VMessOutboundConfig config;
    ::acpp::vmess::MemoryAccount user;
    AES_KEY auth_id_key{};  // Encrypt schedule of user.auth_key, built on prepare.
};

class Handler final : public ::acpp::Outbound {
public:
    Handler(std::string_view tag,
            std::shared_ptr<const PreparedSettings> prepared,
            ::acpp::app::dns::DNS& dns_service,
            std::chrono::seconds dial_timeout);

    // Outbound 接口
    ::acpp::net::awaitable<::acpp::OutboundProcessResult> Process(
        ::acpp::net::io_context& io_context,
        const ::acpp::tcp::endpoint* inbound_local_addr,
        ::acpp::session::Context& ctx,
        const ::acpp::TimeoutsConfig& timeouts,
        ::acpp::transport::Link inbound,
        ::acpp::StatsShard& stats,
        const ::acpp::RelayConfig& relay_config,
        ::acpp::buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;
    std::string_view Tag() const noexcept override { return tag_; }

private:
    memory::ThreadLocalString tag_;
    std::shared_ptr<const PreparedSettings> prepared_;
    ::acpp::TransportSecurity security_;  // This Worker's contexts for prepared_->config.stream_settings.
    std::chrono::seconds dial_timeout_;
    ::acpp::app::dns::DNS& dns_service_;
};

}  // namespace proxy::vmess::outbound

}  // namespace acpp
