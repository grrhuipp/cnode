#pragma once

#include "proxy/outbound.hpp"
#include "transport/internet/outbound_sender.hpp"

#include <array>
#include "common/unsafe.hpp"
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

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

    VlessOutboundConfig() = default;
    VlessOutboundConfig(const VlessOutboundConfig&) = default;
    VlessOutboundConfig& operator=(const VlessOutboundConfig&) = default;
    VlessOutboundConfig(VlessOutboundConfig&&) noexcept = default;
    VlessOutboundConfig& operator=(VlessOutboundConfig&&) noexcept = default;
    ~VlessOutboundConfig() noexcept {
        ::SecureZeroMemory(uuid_bytes.data(), uuid_bytes.size());
    }
};

namespace proxy::vless::outbound {

class Handler final : public ::Outbound {
public:
    explicit Handler(std::shared_ptr<const ::VlessOutboundConfig> config);

    ~Handler() override;

    ::net::awaitable<::OutboundProcessResult> Process(
        ::session::Context& ctx,
        ::transport::Link inbound,
        ::OutboundDialer& dialer,
        const ::TimeoutsConfig& timeouts,
        ::StatsShard& stats,
        const ::RelayConfig& relay_config,
        ::buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout) override;

private:
    std::shared_ptr<const ::VlessOutboundConfig> config_;
    std::shared_ptr<::vless::VlessEncryptionClientTicketCache> encryption_tickets_;
    std::weak_ptr<ExecutionDomain> ticket_domain_;
    bool has_ticket_domain_ = false;
};

}  // namespace proxy::vless::outbound

