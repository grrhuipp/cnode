#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/proxy/shadowsocks/shadowsocks_protocol.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {
class UDPSession;
class UDPSessionManager;

namespace app::dns {
class DNS;
}  // namespace app::dns

// ============================================================================
// SS Outbound 配置
// ============================================================================
struct SsOutboundConfig {
    std::string            tag;
    std::string            address;
    std::optional<net::ip::address> literal_address;
    uint16_t               port    = 8388;
    std::string            password;
    std::string            method  = std::string(constants::protocol::kAes256Gcm);
    StreamSettings         stream_settings;
    std::string            send_through;
    std::chrono::seconds   timeout{10};
    uint8_t                uot_version = 0;
};

// ============================================================================
// SsOutbound — 出站编排（握手、初始 payload、relay、收尾）
// 协议加密状态由 shadowsocks_protocol.cpp 承担。
// ============================================================================
namespace proxy::shadowsocks::outbound {

class Handler final : public ::acpp::Outbound {
public:
    Handler(const ::acpp::SsOutboundConfig& config,
            ::acpp::app::dns::DNS& dns_service,
            ::acpp::UDPSessionManager* udp_session_manager);

    ~Handler() noexcept override = default;

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

    [[nodiscard]] std::string_view Tag() const noexcept override { return config_.tag; }

private:
    ::acpp::SsOutboundConfig config_;
    ::acpp::app::dns::DNS& dns_service_;
    ::acpp::UDPSessionManager* udp_session_manager_ = nullptr;
    ::acpp::ss::SsCipherInfo cipher_info_;
    ::acpp::ss::KeyBytes master_key_;
    std::vector<::acpp::ss::KeyBytes> psk_chain_;
    ::acpp::StreamSettings stream_settings_;
};

}  // namespace proxy::shadowsocks::outbound

}  // namespace acpp
