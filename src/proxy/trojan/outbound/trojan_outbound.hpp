#pragma once

#include "../credentials.hpp"

#include "acppnode/proxy/outbound.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/transport/internet/transport_security.hpp"
#include "acppnode/transport/internet/outbound_bind.hpp"

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
// Trojan Outbound 配置
// ============================================================================
struct TrojanOutboundConfig {
    std::string address;            // 服务器地址
    std::optional<net::ip::address> literal_address; // 冷路径解析的 IP 字面量
    uint16_t port = 443;            // 服务器端口
    trojan::PasswordHash password_hash{};

    // 传输层配置（保持现有 streamSettings JSON）
    StreamSettings stream_settings;
    OutboundBind send_through;


};

// ============================================================================
// Trojan Outbound 实现
// ============================================================================
namespace proxy::trojan::outbound {

class Handler final : public ::acpp::Outbound {
public:
    Handler(std::string_view tag,
            std::shared_ptr<const ::acpp::TrojanOutboundConfig> config,
            ::acpp::app::dns::DNS& dns_service,
            std::chrono::seconds dial_timeout);

    ~Handler() override;

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
    std::shared_ptr<const ::acpp::TrojanOutboundConfig> config_;
    ::acpp::TransportSecurity security_;  // This Worker's contexts for config_->stream_settings.
    std::chrono::seconds dial_timeout_;
    ::acpp::app::dns::DNS& dns_service_;
};

}  // namespace proxy::trojan::outbound

}  // namespace acpp
