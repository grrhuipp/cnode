#pragma once

#include "acppnode/proxy/outbound.hpp"
#include "ss_outbound_credentials.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
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
// SS Outbound 配置
// ============================================================================
enum class SsUotVersion : uint8_t {
    V1 = 1,
    V2 = 2,
};

struct SsOutboundConfig {
    std::string            address;
    std::optional<net::ip::address> literal_address;
    uint16_t               port    = 8388;
    StreamSettings         stream_settings;
    OutboundBind           send_through;
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

class Handler final : public ::acpp::Outbound {
public:
    Handler(std::string_view tag,
            std::shared_ptr<const PreparedSettings> prepared,
            ::acpp::app::dns::DNS& dns_service,
            std::chrono::seconds dial_timeout);

    ~Handler() noexcept override = default;

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

    [[nodiscard]] std::string_view Tag() const noexcept override { return tag_; }

private:
    memory::ThreadLocalString tag_;
    std::shared_ptr<const PreparedSettings> prepared_;
    std::chrono::seconds dial_timeout_;
    ::acpp::app::dns::DNS& dns_service_;
};

}  // namespace proxy::shadowsocks::outbound

}  // namespace acpp
