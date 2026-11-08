#pragma once

#include "../credentials.hpp"

#include "proxy/outbound.hpp"
#include "transport/internet/outbound_sender.hpp"

#include <chrono>
#include "common/unsafe.hpp"
#include <memory>


// ============================================================================
// Trojan Outbound 配置（传输层与 sendThrough 属于 Handler 的 sender settings）
// ============================================================================
struct TrojanOutboundConfig {
    OutboundServer server;
    trojan::PasswordHash password_hash{};

    TrojanOutboundConfig() = default;
    TrojanOutboundConfig(const TrojanOutboundConfig&) = default;
    TrojanOutboundConfig& operator=(const TrojanOutboundConfig&) = default;
    TrojanOutboundConfig(TrojanOutboundConfig&&) noexcept = default;
    TrojanOutboundConfig& operator=(TrojanOutboundConfig&&) noexcept = default;
    ~TrojanOutboundConfig() noexcept {
        ::SecureZeroMemory(password_hash.data(), password_hash.size());
    }
};

// ============================================================================
// Trojan Outbound 实现
// ============================================================================
namespace proxy::trojan::outbound {

class Handler final : public ::Outbound {
public:
    explicit Handler(std::shared_ptr<const ::TrojanOutboundConfig> config);

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
    std::shared_ptr<const ::TrojanOutboundConfig> config_;
};

}  // namespace proxy::trojan::outbound

