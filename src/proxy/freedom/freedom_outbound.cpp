#include "app/outbound_handler.hpp"
#include "common/session.hpp"
#include "common/target_address.hpp"
#include "common/constants.hpp"
#include "infra/log.hpp"
#include "proxy/freedom/freedom_udp.hpp"
#include "infra/outbound_types.hpp"
#include "proxy/outbound.hpp"
#include "transport/outbound_target_builder.hpp"
#include <memory>
#include <optional>
#include <string_view>
#include <tl/expected.hpp>

namespace proxy {


class FreedomOutbound final : public Outbound {
public:
    explicit FreedomOutbound(const infra::FreedomSettings& settings);

    struct Session;
    auto SessionArguments() const noexcept {
        return std::tuple{domain_strategy_, std::cref(redirect_target_)};
    }

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

struct FreedomOutbound::Session final : OutboundSession {
    OutboundPrepareContext& context;
    DomainStrategy domain_strategy;
    const std::optional<common::TargetAddress>& redirect_target;
    std::unique_ptr<transport::AsyncStream> stream;
    std::optional<FreedomUdpRequest> datagram;

    Session(OutboundPrepareContext& context, DomainStrategy strategy,
            const std::optional<common::TargetAddress>& redirect) noexcept
        : context(context), domain_strategy(strategy), redirect_target(redirect) {}

    using Prepared = OutboundPrepareResult<transport::AsyncStream, FreedomUdpRequest>;

    OutboundPreparationPlan<transport::AsyncStream, FreedomUdpRequest> Prepare() {
        auto& ctx = context.ctx;
        if (ctx.content.network != common::Network::UDP) return PrepareTcp();
        // Preserve the target on each datagram; redirect applies only to TCP.
        const auto& target = ctx.outbound.target;
        if (auto opened = context.dialer.OpenDatagram(ctx, transport::OutboundDialer::DatagramRemote{
                .address = target.IsDomain() ? std::nullopt : target.resolved_addr,
                .family_hint = target.IsDomain() ? target.resolved_addr : std::nullopt,
                .family_policy = FamilyPolicy(domain_strategy),
            }, datagram); !opened) {
            return Prepared(tl::unexpected(opened.error()));
        }
        return Prepared(std::ref(*datagram));
    }

private:
    net::awaitable<Prepared> PrepareTcp() {
        auto& [ctx, dialer, timeouts] = context;
        if (redirect_target) {
            LOG_CONN_DEBUG(ctx, "redirect {} -> {}", ctx.outbound.target, *redirect_target);
            ctx.outbound.target = *redirect_target;
        }
        auto dialed = co_await dialer.Dial(ctx, ctx.outbound.target, FamilyPolicy(domain_strategy));
        if (!dialed) co_return tl::unexpected(dialed.error());
        stream = std::move(*dialed);
        co_return std::ref(*stream);
    }
};

FreedomOutbound::FreedomOutbound(const infra::FreedomSettings& settings)
    : Outbound(std::in_place_type<FreedomOutbound>)
    , domain_strategy_(settings.domain_strategy)
    , redirect_target_(settings.redirect) {}


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
