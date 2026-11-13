#include "app/proxyman/outbound_handler.hpp"
#include "app/relay.hpp"
#include "common/multi_buffer.hpp"
#include "common/session.hpp"
#include "common/constants.hpp"
#include "infra/log.hpp"
#include "proxy/outbound.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
namespace proxy {

namespace {
constexpr std::string_view kHttp403Response =
    "HTTP/1.1 403 Forbidden\r\n"
    "Connection: close\r\n"
    "Cache-Control: max-age=3600, public\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

}  // namespace


class BlackholeOutbound final : public Outbound {
public:
    explicit BlackholeOutbound(const infra::BlackholeSettings& settings);

    net::awaitable<OutboundProcessResult> Process(
        common::Context& ctx,
        transport::Link inbound,
        transport::OutboundDialer& dialer,
        const infra::TimeoutsConfig& timeouts,
        app::StatsShard& stats,
        const app::RelayConfig& relay_config,
        common::MultiBufferBatch first_payload) override;

private:
    bool http_response_;
};

// ============================================================================
// Handler 实现
// ============================================================================

BlackholeOutbound::BlackholeOutbound(const infra::BlackholeSettings& settings)
    : http_response_(settings.http_response) {
}

net::awaitable<OutboundProcessResult> BlackholeOutbound::Process(
    common::Context& ctx,
    transport::Link inbound,
    transport::OutboundDialer& /*dialer*/,
    const infra::TimeoutsConfig& /*timeouts*/,
    app::StatsShard& /*stats*/,
    const app::RelayConfig& /*relay_config*/,
    common::MultiBufferBatch first_payload) {
    first_payload.clear();
    const bool send_http =
        http_response_ && ctx.content.network == common::Network::TCP && inbound.writer;
    if (send_http) {
        net::const_buffer response{kHttp403Response.data(), kHttp403Response.size()};
        try {
            co_await inbound.writer->WriteBuffers(
                std::span<const net::const_buffer>{&response, 1});
            co_await inbound.writer->AsyncShutdownWrite();
        } catch (...) {
            LOG_CONN_DEBUG(ctx, "failed to write HTTP response");
        }
    }
    LOG_CONN_DEBUG(ctx, "blocked before relay response={}", send_http ? "http" : "none");
    co_return tl::unexpected(common::ErrorCode::BLOCKED);
}

}  // namespace proxy

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kBlackholeRegistered = (::app::RegisterProxy(
    ::common::kBlackhole,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::app::PreparedOutboundProxy> {
        const auto* settings = std::get_if<::infra::BlackholeSettings>(&cfg.settings);
        if (!settings) return std::nullopt;
        return ::app::PreparedOutboundProxy{
            .create = ::app::MakePreparedOutboundCreator<
                ::infra::BlackholeSettings,
                +[](std::string_view /*tag*/,
                    std::shared_ptr<const ::infra::BlackholeSettings> s,
                    ::net::io_context& /*io_context*/,
                    ::common::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::proxy::Outbound> {
                    return std::make_unique<::proxy::BlackholeOutbound>(*s);
                }>(*settings),
            .sender = {},
        };
    }), true);
}  // namespace
