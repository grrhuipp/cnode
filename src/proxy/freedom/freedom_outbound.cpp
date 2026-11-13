#include "app/outbound_handler.hpp"
#include "app/relay.hpp"
#include "common/session.hpp"
#include "common/target_address.hpp"
#include "common/constants.hpp"
#include "infra/log.hpp"
#include "proxy/freedom/freedom_udp.hpp"
#include "infra/outbound_types.hpp"
#include "proxy/outbound.hpp"
#include "proxy/outbound_stream_endpoint.hpp"
#include "transport/outbound_target_builder.hpp"
#include <memory>
#include <optional>
#include <string_view>
#include <tl/expected.hpp>

namespace proxy {


class FreedomOutbound final : public Outbound {
public:
    explicit FreedomOutbound(const infra::FreedomSettings& settings);

    net::awaitable<OutboundProcessResult> Process(
        common::Context& ctx,
        transport::Link inbound,
        transport::OutboundDialer& dialer,
        const infra::TimeoutsConfig& timeouts,
        app::StatsShard& stats,
        const app::RelayConfig& relay_config,
        common::MultiBufferBatch first_payload) override;

private:
    DomainStrategy domain_strategy_;
    std::optional<common::TargetAddress> redirect_target_;
};

namespace {

transport::OutboundDialer::AddressFamilyPolicy FamilyPolicy(DomainStrategy strategy) {
    using Policy = transport::OutboundDialer::AddressFamilyPolicy;
    switch (strategy) {
        case DomainStrategy::UseIPv4:
            return Policy{.accepts_v6 = false};
        case DomainStrategy::ForceIPv4:
            return Policy{.accepts_v6 = false, .restricts_literals = true};
        case DomainStrategy::UseIPv6:
            return Policy{.accepts_v4 = false, .prefers_v6 = true};
        case DomainStrategy::ForceIPv6:
            return Policy{.accepts_v4 = false, .prefers_v6 = true, .restricts_literals = true};
        case DomainStrategy::UseIPv6v4:
        case DomainStrategy::ForceIPv6v4:
            return Policy{.prefers_v6 = true, .preserves_dns_order = false};
        case DomainStrategy::UseIPv4v6:
        case DomainStrategy::ForceIPv4v6:
            return Policy{.preserves_dns_order = false};
        default:
            return Policy{};
    }
}

}  // namespace

FreedomOutbound::FreedomOutbound(const infra::FreedomSettings& settings)
    : domain_strategy_(settings.domain_strategy)
    , redirect_target_(settings.redirect) {}

net::awaitable<OutboundProcessResult> FreedomOutbound::Process(
    common::Context& ctx,
    transport::Link inbound,
    transport::OutboundDialer& dialer,
    const infra::TimeoutsConfig& /*timeouts*/,
    app::StatsShard& stats,
    const app::RelayConfig& relay_config,
    common::MultiBufferBatch first_payload) {
    if (!inbound.Valid()) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }

    // UDP 数据面：dispatcher.Dispatch -> outbound.Process -> DoRelayLink。
    // 不做 redirect（保持 UDP 逐包目标语义）；嗅探首包作为普通上行交给转发。
    if (ctx.content.network == common::Network::UDP) {
        const auto& target = ctx.outbound.target;
        std::optional<FreedomUdpRequest> endpoint;
        if (auto opened = dialer.OpenDatagram(ctx, transport::OutboundDialer::DatagramRemote{
                .address = target.IsDomain() ? std::nullopt : target.resolved_addr,
                .family_hint = target.IsDomain() ? target.resolved_addr : std::nullopt,
                .family_policy = FamilyPolicy(domain_strategy_),
            }, endpoint); !opened) {
            co_return tl::unexpected(opened.error());
        }
        proxy::ApplyOutboundDatagramTimeouts(*endpoint, relay_config);
        co_return co_await app::DoRelayLink(dialer.IoContext(), *inbound.reader, *inbound.writer,
            inbound.control, *endpoint, ctx, stats, relay_config, std::move(first_payload));
    }

    // redirect：替换目标地址（Xray freedom redirect 语义）
    if (redirect_target_) {
        LOG_CONN_DEBUG(ctx, "redirect {} -> {}",
                       ctx.outbound.target, *redirect_target_);
        ctx.outbound.target = *redirect_target_;
    }

    auto dialed = co_await dialer.Dial(ctx, ctx.outbound.target, FamilyPolicy(domain_strategy_));
    if (!dialed) {
        co_return tl::unexpected(dialed.error());
    }
    auto stream = std::move(*dialed);
    proxy::ApplyOutboundRelayTimeouts(*stream, relay_config);
    co_return co_await app::DoRelayLink(
        dialer.IoContext(), *inbound.reader, *inbound.writer, inbound.control,
        *stream, ctx, stats, relay_config, std::move(first_payload));
}


namespace {
[[nodiscard]] app::PreparedOutboundCreator
MakeFreedomPreparedOutboundCreator(infra::FreedomSettings settings) {
    return app::MakePreparedOutboundCreator<
        infra::FreedomSettings,
        +[](std::string_view, std::shared_ptr<const infra::FreedomSettings> config,
            net::io_context&, common::AwaitableTaskGroup&) -> std::unique_ptr<Outbound> {
            return std::make_unique<FreedomOutbound>(*config);
        }>(std::move(settings));
}
}  // namespace
}  // namespace proxy

// ============================================================================
// 自注册（静态初始化，Xray init() 设计）
// ============================================================================
namespace {
const bool kFreedomRegistered = (::app::RegisterProxy(
    ::common::kFreedom,
    [](const ::infra::OutboundSourceConfig& cfg)
        -> std::optional<::app::PreparedOutboundProxy> {
        const auto* settings = std::get_if<::infra::FreedomSettings>(&cfg.settings);
        if (!settings) return std::nullopt;
        ::transport::OutboundSenderSettings sender{
            .stream_settings = {},
            .send_through = ::transport::OutboundBind::Auto(),
        };
        return ::app::PreparedOutboundProxy{
            .create = ::proxy::MakeFreedomPreparedOutboundCreator(*settings),
            .sender = std::move(sender),
        };
    }), true);
}  // namespace
