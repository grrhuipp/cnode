#pragma once

#include "../credentials.hpp"

#include "acppnode/proxy/outbound.hpp"
#include "acppnode/transport/internet/outbound_sender.hpp"

#include <chrono>
#include <memory>

namespace acpp {

// ============================================================================
// Trojan Outbound 配置（传输层与 sendThrough 属于 Handler 的 sender settings）
// ============================================================================
struct TrojanOutboundConfig {
    OutboundServer server;
    trojan::PasswordHash password_hash{};
};

// ============================================================================
// Trojan Outbound 实现
// ============================================================================
namespace proxy::trojan::outbound {

class Handler final : public ::acpp::Outbound {
public:
    explicit Handler(std::shared_ptr<const ::acpp::TrojanOutboundConfig> config);

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
    std::shared_ptr<const ::acpp::TrojanOutboundConfig> config_;
};

}  // namespace proxy::trojan::outbound

}  // namespace acpp
