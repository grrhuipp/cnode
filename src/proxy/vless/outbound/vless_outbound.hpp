#pragma once

#include "acppnode/proxy/outbound.hpp"
#include "acppnode/transport/internet/outbound_sender.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace acpp {
class ExecutionDomain;

namespace vless {
struct VlessEncryptionConfig;
struct VlessEncryptionClientTicketCache;
}  // namespace vless

// 传输层与 sendThrough 属于 Handler 的 sender settings。
struct VlessOutboundConfig {
    OutboundServer server;
    std::array<uint8_t, 16> uuid_bytes{};
    std::shared_ptr<const vless::VlessEncryptionConfig> encryption;
    std::string flow;
    bool packet_xudp = true;
    bool packet_addr = false;
};

namespace proxy::vless::outbound {

class Handler final : public ::acpp::Outbound {
public:
    explicit Handler(std::shared_ptr<const ::acpp::VlessOutboundConfig> config);

    ~Handler() override;

    ::acpp::net::awaitable<::acpp::OutboundProcessResult> Process(
        ::acpp::session::Context& ctx,
        ::acpp::transport::Link inbound,
        ::acpp::OutboundDialer& dialer,
        const ::acpp::TimeoutsConfig& timeouts,
        ::acpp::StatsShard& stats,
        const ::acpp::RelayConfig& relay_config,
        ::acpp::buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

private:
    std::shared_ptr<const ::acpp::VlessOutboundConfig> config_;
    std::shared_ptr<::acpp::vless::VlessEncryptionClientTicketCache> encryption_tickets_;
    std::weak_ptr<ExecutionDomain> ticket_domain_;
};

}  // namespace proxy::vless::outbound

}  // namespace acpp
