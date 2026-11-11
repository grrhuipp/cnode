#include "app/proxyman/outbound/handler.hpp"
#include "app/relay.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/session.hpp"
#include "core/constants.hpp"
#include "infra/log.hpp"
#include "proxy/outbound.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
namespace proxy::blackhole::outbound {

namespace {
constexpr std::string_view kHttp403Response =
    "HTTP/1.1 403 Forbidden\r\n"
    "Connection: close\r\n"
    "Cache-Control: max-age=3600, public\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

}  // namespace


class Handler final : public Outbound {
public:
    explicit Handler(const infra::BlackholeSettings& settings);

    net::awaitable<OutboundProcessResult> Process(
        session::Context& ctx,
        transport::Link inbound,
        OutboundDialer& dialer,
        const TimeoutsConfig& timeouts,
        StatsShard& stats,
        const RelayConfig& relay_config,
        buf::MultiBufferBatch first_payload) override;

private:
    bool http_response_;
};

// ============================================================================
// Handler 实现
// ============================================================================

Handler::Handler(const infra::BlackholeSettings& settings)
    : http_response_(settings.http_response) {
}

net::awaitable<OutboundProcessResult> Handler::Process(
    session::Context& ctx,
    transport::Link inbound,
    OutboundDialer& /*dialer*/,
    const TimeoutsConfig& /*timeouts*/,
    StatsShard& /*stats*/,
    const RelayConfig& /*relay_config*/,
    buf::MultiBufferBatch first_payload) {
    first_payload.clear();
    const bool send_http =
        http_response_ && ctx.content.network == Network::TCP && inbound.writer;
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
    co_return tl::unexpected(ErrorCode::BLOCKED);
}

}  // namespace proxy::blackhole::outbound

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kBlackholeRegistered = (::proxyman::outbound::RegisterProxy(
    ::constants::protocol::kBlackhole,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::proxyman::outbound::PreparedOutboundProxy> {
        const auto* settings = std::get_if<::infra::BlackholeSettings>(&cfg.settings);
        if (!settings) return std::nullopt;
        return ::proxyman::outbound::PreparedOutboundProxy{
            .create = ::proxyman::outbound::MakePreparedOutboundCreator<
                ::infra::BlackholeSettings,
                +[](std::string_view /*tag*/,
                    std::shared_ptr<const ::infra::BlackholeSettings> s,
                    ::net::io_context& /*io_context*/,
                    ::AwaitableTaskGroup& /*tasks*/) -> std::unique_ptr<::Outbound> {
                    return std::make_unique<::proxy::blackhole::outbound::Handler>(*s);
                }>(*settings),
            .sender = {},
        };
    }), true);
}  // namespace
