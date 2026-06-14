#include "acppnode/app/proxyman/outbound/handler.hpp"

#include "acppnode/app/relay.hpp"
#include "acppnode/common/mux/mux_relay.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/proxy/outbound.hpp"
#include "acppnode/transport/link.hpp"

namespace acpp::proxyman::outbound {

Handler::Handler(std::string tag, std::unique_ptr<Outbound> proxy, StatsShard& stats)
    : tag_(std::move(tag))
    , proxy_(std::move(proxy))
    , stats_(&stats) {}

net::awaitable<std::optional<RelayResult>> Handler::Dispatch(
    net::io_context& io_context,
    const tcp::endpoint* inbound_local_addr,
    session::Context& ctx,
    const TimeoutsConfig& timeouts,
    transport::Link inbound_link,
    const RelayConfig& relay_config,
    std::span<const uint8_t> initial_payload,
    buf::MultiBuffer& first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    if (!proxy_) {
        LOG_CONN_FAIL_CTX(ctx, "OUTBOUND_HANDLER_EMPTY {} -> {} via {}",
                          ctx.inbound.source_ip, ctx.outbound.target, tag_);
        co_return std::nullopt;
    }

    if (!inbound_link.Valid()) {
        LOG_CONN_FAIL_CTX(ctx, "OUTBOUND_INBOUND_LINK_MISSING {} -> {} via {}",
                          ctx.inbound.source_ip, ctx.outbound.target, tag_);
        co_return std::nullopt;
    }

    OutboundProcessResult process_result = co_await proxy_->Process(
        io_context,
        inbound_local_addr,
        ctx,
        timeouts,
        inbound_link,
        *stats_,
        relay_config,
        initial_payload,
        first_payload,
        relay_idle_timeout,
        relay_write_timeout);
    if (!process_result) {
        ErrorCode process_error = process_result.error();
        if (process_error == ErrorCode::OK) {
            process_error = ErrorCode::PROTOCOL_AUTH_FAILED;
        }
        LOG_CONN_FAIL_CTX(ctx, "OUTBOUND_PROCESS_FAILED {} -> {} via {}: {}",
                          ctx.inbound.source_ip, ctx.outbound.target,
                          ctx.outbound.tag, ErrorCodeToString(process_error));
        co_return std::nullopt;
    }

    LOG_CONN_DEBUG(ctx, "[Outbound] outbound.Process ok via {}", ctx.outbound.tag);

    co_return std::optional<RelayResult>{std::move(*process_result)};
}

net::awaitable<RelayResult> Handler::DispatchMux(
    net::io_context& io_context,
    AsyncStream& inbound_stream,
    session::Context& ctx,
    const UDPRelayConfig& relay_config) {
    if (!proxy_) {
        LOG_CONN_FAIL_CTX(ctx, "OUTBOUND_HANDLER_EMPTY {} -> {} via {}",
                          ctx.inbound.source_ip, ctx.outbound.target, tag_);
        RelayResult result;
        result.error = ErrorCode::OUTBOUND_CONNECTION_FAILED;
        co_return result;
    }

    co_return co_await mux::DoMuxRelay(
        io_context, inbound_stream, *this, ctx, relay_config);
}

net::awaitable<UDPSession*> Handler::DispatchUDP(
    session::Context& ctx) {
    if (!proxy_) {
        LOG_CONN_FAIL_CTX(ctx, "OUTBOUND_HANDLER_EMPTY {} -> {} via {}",
                          ctx.inbound.source_ip, ctx.outbound.target, tag_);
        co_return nullptr;
    }

    LOG_CONN_DEBUG(ctx, "[Outbound] UDP dial start -> {} via {}",
                   ctx.outbound.target, ctx.outbound.tag);
    UDPSession* session = co_await proxy_->DialUDP(ctx);
    if (!session) {
        LOG_CONN_DEBUG(ctx, "[Outbound] UDP dial failed/unsupported via {}", ctx.outbound.tag);
        co_return nullptr;
    }
    LOG_CONN_DEBUG(ctx, "[Outbound] UDP dial ok via {}", ctx.outbound.tag);
    LOG_ACCESS(FormatAccessLog(ctx));

    co_return session;
}

}  // namespace acpp::proxyman::outbound
