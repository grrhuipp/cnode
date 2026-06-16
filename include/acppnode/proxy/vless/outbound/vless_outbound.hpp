#pragma once

#include "acppnode/core/constants.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <array>
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

namespace vless {
struct VlessEncryptionConfig;
}  // namespace vless

struct VlessOutboundConfig {
    std::string tag;
    std::string address;
    std::optional<net::ip::address> literal_address;
    uint16_t port = 443;
    std::string uuid;
    std::array<uint8_t, 16> uuid_bytes{};
    std::string encryption = std::string(constants::protocol::kNone);
    std::string flow;
    bool packet_xudp = true;
    bool packet_addr = false;

    StreamSettings stream_settings;
    std::string send_through;
    std::chrono::seconds timeout{10};
};

namespace proxy::vless::outbound {

class Handler final : public ::acpp::Outbound {
public:
    Handler(const ::acpp::VlessOutboundConfig& config,
            ::acpp::app::dns::DNS& dns_service);

    ~Handler() override;

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
    ::acpp::VlessOutboundConfig config_;
    ::acpp::app::dns::DNS& dns_service_;
    std::shared_ptr<const ::acpp::vless::VlessEncryptionConfig> encryption_;
    bool config_valid_ = false;
};

}  // namespace proxy::vless::outbound

}  // namespace acpp
