#pragma once

#include "proxy/outbound.hpp"
#include "ss_outbound_credentials.hpp"
#include "transport/internet/outbound_sender.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>


// ============================================================================
// SS Outbound 配置
// ============================================================================
enum class SsUotVersion : uint8_t {
    V1 = 1,
    V2 = 2,
};

struct SsOutboundConfig {
    OutboundServer server;
    std::optional<SsUotVersion> uot_version;
};

// ============================================================================
// SsOutbound — 出站编排（握手、初始 payload、relay、收尾）
// 协议加密状态由 shadowsocks_protocol.cpp 承担。
// ============================================================================
namespace proxy::shadowsocks::outbound {

struct PreparedSettings {
    SsOutboundConfig config;
    Credentials credentials;
};

class Handler final : public ::Outbound {
public:
    explicit Handler(std::shared_ptr<const PreparedSettings> prepared);

    ~Handler() noexcept override = default;

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
    std::shared_ptr<const PreparedSettings> prepared_;
};

}  // namespace proxy::shadowsocks::outbound

