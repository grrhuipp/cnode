#include "transport/internet/outbound_target_builder.hpp"
#include "common/allocator.hpp"
#include "common/ip_address.hpp"
#include "transport/internet/http_headers.hpp"

#include "app/dns/dns.hpp"
#include "app/session_group_executor.hpp"
#include "common/ip_utils.hpp"
#include "core/constants.hpp"
#include "common/session.hpp"
#include "infra/log.hpp"
#include "transport/internet/transport_dialer.hpp"

#include <algorithm>
#include <memory>
#include <utility>


namespace {


bool AutoPrefersIPv6(const OutboundBind& bind,
                     const tcp::endpoint* inbound_local_addr) noexcept {
    if (bind.GetMode() != OutboundBind::Mode::Auto || !inbound_local_addr) {
        return false;
    }
    const auto inbound_local =
        iputil::NormalizeAddress(inbound_local_addr->address());
    return inbound_local.is_v6() && !inbound_local.is_unspecified() &&
           !inbound_local.is_loopback() &&
           !inbound_local.to_v6().is_link_local();
}

// The explicit host is resolved once by stream-settings normalization; only
// the dial-address fallback is formatted per target.
[[nodiscard]] memory::ThreadLocalString BuildHttpHostHeader(
    const StreamSettings& settings,
    std::string_view fallback_host,
    uint16_t port) {
    if (!settings.IsWs() && !settings.IsHttpUpgrade() &&
        !settings.IsHttp() && !settings.IsGrpc() && !settings.IsXHttp()) {
        return {};
    }
    if (!settings.configured_http_host.empty()) {
        return memory::ThreadLocalString(settings.configured_http_host);
    }
    if (settings.IsGrpc() && settings.IsReality()) {
        return {};
    }
    const std::string_view effective_host =
        (settings.IsReality() && !settings.reality.server_name.empty())
            ? std::string_view(settings.reality.server_name)
            : fallback_host;
    memory::ThreadLocalString out;
    iputil::FormatHttpHostHeaderInto(
        out, effective_host, port, settings.IsTlsLike());
    return out;
}

net::awaitable<tl::expected<OutboundTransportTarget, ErrorCode>>
AttachXHttpDownloadTarget(
    OutboundTransportTarget target,
    const OutboundTargetOptions& options,
    const tcp::endpoint* inbound_local_addr,
    std::optional<OutboundBind::Selection> download_ordered_v4,
    std::optional<OutboundBind::Selection> download_ordered_v6) {
    if (!options.stream_settings ||
        !options.stream_settings->IsXHttp() ||
        !options.stream_settings->xhttp.download_settings) {
        co_return target;
    }

    const auto& upload_xhttp = options.stream_settings->xhttp;
    if (upload_xhttp.IsStreamOne()) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    const auto& download = *upload_xhttp.download_settings;
    if (download.address.empty() || download.port == 0) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    // A download target never carries its own downloadSettings; reject rather
    // than silently ignore a nested one.
    if (!download.stream_settings.IsXHttp() ||
        download.stream_settings.IsUnsupported() ||
        download.stream_settings.xhttp.IsStreamOne() ||
        download.stream_settings.xhttp.download_settings) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    auto download_target = co_await BuildOutboundTransportTarget(
        OutboundTargetOptions{
            .dns_service = options.dns_service,
            .address = download.address,
            .literal_address = std::nullopt,
            .port = download.port,
            .stream_settings = &download.stream_settings,
            .security = options.security ? options.security->XHttpDownload() : nullptr,
            .timeout = options.timeout,
            .send_through = &download.send_through,
            .inbound_local_addr = inbound_local_addr,
            .inbound_source_port = options.inbound_source_port,
            .inbound_user_id = options.inbound_user_id,
            .ordered_bind_v4 = download_ordered_v4,
            .ordered_bind_v6 = download_ordered_v6,
        });
    if (!download_target) {
        co_return tl::unexpected(download_target.error());
    }

    target.xhttp_download_target =
        memory::AllocateShared<OutboundTransportTarget>(std::move(*download_target));
    co_return target;
}

}  // namespace

std::string_view ResolveOutboundTlsServerName(
    const StreamSettings& settings,
    std::string_view fallback_server_name) {
    if (settings.IsReality() && !settings.reality.server_name.empty()) {
        return settings.reality.server_name;
    }
    if (!settings.tls.server_name.empty()) {
        return settings.tls.server_name;
    }
    return fallback_server_name;
}

net::awaitable<tl::expected<OutboundTransportTarget, ErrorCode>>
BuildOutboundTransportTarget(OutboundTargetOptions options) {
    if (!options.stream_settings || options.port == 0) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    if (!options.literal_address && options.address.empty()) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    const std::optional<tcp::endpoint> inbound_local = options.inbound_local_addr
        ? std::optional<tcp::endpoint>(*options.inbound_local_addr)
        : std::nullopt;
    const tcp::endpoint* const inbound_local_ptr =
        inbound_local ? &*inbound_local : nullptr;

    const OutboundBind unbound;
    const auto& bind = options.send_through ? *options.send_through : unbound;
    const auto ordered_v4 = bind.GetMode() == OutboundBind::Mode::Ordered
        ? (options.ordered_bind_v4 ? *options.ordered_bind_v4
            : bind.Select(net::ip::address_v4::any(),
                          options.inbound_source_ip,
                          options.inbound_user_id,
                          options.inbound_user_email,
                          options.inbound_tag))
        : OutboundBind::Selection{};
    const auto ordered_v6 = bind.GetMode() == OutboundBind::Mode::Ordered
        ? (options.ordered_bind_v6 ? *options.ordered_bind_v6
            : bind.Select(net::ip::address_v6::any(),
                          options.inbound_source_ip,
                          options.inbound_user_id,
                          options.inbound_user_email,
                          options.inbound_tag))
        : OutboundBind::Selection{};

    std::optional<OutboundBind::Selection> download_ordered_v4;
    std::optional<OutboundBind::Selection> download_ordered_v6;
    if (options.stream_settings->IsXHttp() &&
        options.stream_settings->xhttp.download_settings) {
        const auto& download_bind =
            options.stream_settings->xhttp.download_settings->send_through;
        if (download_bind.GetMode() == OutboundBind::Mode::Ordered) {
            download_ordered_v4 = download_bind.Select(
                net::ip::address_v4::any(),
                options.inbound_source_ip,
                options.inbound_user_id,
                options.inbound_user_email,
                options.inbound_tag);
            download_ordered_v6 = download_bind.Select(
                net::ip::address_v6::any(),
                options.inbound_source_ip,
                options.inbound_user_id,
                options.inbound_user_email,
                options.inbound_tag);
        }
    }

    options.inbound_local_addr = nullptr;
    options.inbound_source_ip = {};
    options.inbound_user_email = {};
    options.inbound_tag = {};

    OutboundTransportTarget target;
    target.timeout = options.timeout;
    target.stream_settings = options.stream_settings;
    target.security_context = options.security ? options.security->Context() : nullptr;
    target.tls_server_name = ResolveOutboundTlsServerName(
        *options.stream_settings, options.address);
    target.ws_host = BuildHttpHostHeader(
        *options.stream_settings, options.address, options.port);

    auto make_candidate = [&](const net::ip::address& raw_remote_addr) {
        const net::ip::address remote_addr = iputil::NormalizeAddress(raw_remote_addr);
        OutboundDialCandidate candidate;
        candidate.endpoint = tcp::endpoint(remote_addr, options.port);
        if (bind.GetMode() == OutboundBind::Mode::Ordered) {
            const auto& selected = remote_addr.is_v6() ? ordered_v6 : ordered_v4;
            candidate.bind_local = selected.address;
        } else {
            candidate.bind_local = bind.BindAddressFor(inbound_local_ptr, remote_addr);
        }
        return candidate;
    };
    auto append_single = [&](const net::ip::address& raw_remote_addr) {
        target.single_candidate = make_candidate(raw_remote_addr);
    };

    if (options.literal_address) {
        append_single(*options.literal_address);
        co_return co_await AttachXHttpDownloadTarget(
            std::move(target),
            options,
            inbound_local_ptr,
            download_ordered_v4,
            download_ordered_v6);
    }
    if (auto literal = iputil::ParseLiteral(options.address)) {
        append_single(*literal);
        co_return co_await AttachXHttpDownloadTarget(
            std::move(target),
            options,
            inbound_local_ptr,
            download_ordered_v4,
            download_ordered_v6);
    }
    if (!options.dns_service) {
        co_return tl::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    auto dns_result = co_await options.dns_service->Resolve(options.address);
    if (!dns_result.Ok() || dns_result.addresses.empty()) {
        co_return tl::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }
    const size_t max_candidates = dns_result.addresses.size();
    auto add_candidate = [&](const net::ip::address& addr) {
        OutboundDialCandidate candidate = make_candidate(addr);
        if (!target.single_candidate && target.candidates.empty()) {
            target.single_candidate = std::move(candidate);
            return;
        }
        if (target.single_candidate) {
            target.candidates.reserve(max_candidates);
            target.candidates.push_back(std::move(*target.single_candidate));
            target.single_candidate.reset();
        }
        target.candidates.push_back(std::move(candidate));
    };
    auto finalize_candidates = [&]()
        -> net::awaitable<tl::expected<OutboundTransportTarget, ErrorCode>> {
        if (target.candidates.empty() && !target.single_candidate) {
            co_return tl::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
        }
        co_return co_await AttachXHttpDownloadTarget(
            std::move(target),
            options,
            inbound_local_ptr,
            download_ordered_v4,
            download_ordered_v6);
    };

    if (bind.GetMode() == OutboundBind::Mode::Ordered) {
        for (const bool ipv6 : {bind.PrefersIPv6(), !bind.PrefersIPv6()}) {
            for (const auto& raw_addr : dns_result.addresses) {
                const auto addr = iputil::NormalizeAddress(raw_addr);
                if (addr.is_v6() != ipv6) continue;
                add_candidate(addr);
            }
        }
        co_return co_await finalize_candidates();
    }

    if (bind.GetMode() == OutboundBind::Mode::Explicit) {
        const bool want_v6 = bind.ExplicitAddress() &&
            iputil::NormalizeAddress(*bind.ExplicitAddress()).is_v6();
        for (const auto& raw_addr : dns_result.addresses) {
            const auto addr = iputil::NormalizeAddress(raw_addr);
            if (addr.is_v6() == want_v6) {
                add_candidate(addr);
            }
        }
        co_return co_await finalize_candidates();
    }

    if (AutoPrefersIPv6(bind, inbound_local_ptr)) {
        for (const bool ipv6 : {true, false}) {
            for (const auto& raw_addr : dns_result.addresses) {
                const auto addr = iputil::NormalizeAddress(raw_addr);
                if (addr.is_v6() == ipv6) {
                    add_candidate(addr);
                }
            }
        }
        co_return co_await finalize_candidates();
    }

    for (const auto& raw_addr : dns_result.addresses) {
        const auto addr = iputil::NormalizeAddress(raw_addr);
        if (addr.is_v4()) {
            add_candidate(addr);
        }
    }
    if (target.single_candidate || !target.candidates.empty()) {
        co_return co_await finalize_candidates();
    }

    for (const auto& raw_addr : dns_result.addresses) {
        add_candidate(iputil::NormalizeAddress(raw_addr));
    }
    co_return co_await finalize_candidates();
}

OutboundDialer::OutboundDialer(net::io_context& io_context,
                               app::dns::DNS& dns,
                               const OutboundSenderSettings& sender,
                               std::chrono::seconds timeout)
    : io_context_(io_context)
    , dns_(dns)
    , sender_(sender)
    , security_(sender.stream_settings, StreamEndpointRole::Outbound)
    , timeout_(timeout) {}

net::io_context& OutboundDialer::IoContext() const noexcept {
    const auto domain = ExecutionDomain::Current();
    return domain ? domain->Reactor() : io_context_;
}

ForwardedMetadataView OutboundDialer::ForwardedMetadata(
    const session::Context& ctx) const noexcept {
    return sender_.passthrough ? ctx.inbound.MakeForwardedMetadata()
                               : ForwardedMetadataView{};
}

std::optional<OutboundDialer::OrderedBind> OutboundDialer::SelectOrderedBind(
    const session::Context& ctx) const {
    const auto& bind = sender_.send_through;
    if (bind.GetMode() != OutboundBind::Mode::Ordered) return std::nullopt;
    const auto client_ip = ctx.inbound.EffectiveClientIp();
    const auto user_id = ctx.inbound.EffectiveUserId();
    const auto user_email = ctx.inbound.EffectiveUserEmail();
    const auto inbound_tag = ctx.inbound.EffectiveInboundTag();
    return OrderedBind{
        .v4 = bind.Select(net::ip::address_v4::any(), client_ip, user_id, user_email, inbound_tag),
        .v6 = bind.Select(net::ip::address_v6::any(), client_ip, user_id, user_email, inbound_tag),
    };
}

net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
OutboundDialer::Dial(session::Context& ctx, const OutboundServer& server,
                     const OrderedBind* ordered) {
    auto target = co_await BuildOutboundTransportTarget(OutboundTargetOptions{
        .dns_service = &dns_,
        .address = server.address,
        .literal_address = server.literal_address,
        .port = server.port,
        .stream_settings = &sender_.stream_settings,
        .security = &security_,
        .timeout = timeout_,
        .send_through = &sender_.send_through,
        .inbound_local_addr = ctx.inbound.local_endpoint
            ? &*ctx.inbound.local_endpoint : nullptr,
        .inbound_source_ip = ctx.inbound.EffectiveClientIp(),
        .inbound_source_port = ctx.inbound.source_port,
        .inbound_user_id = ctx.inbound.EffectiveUserId(),
        .inbound_user_email = ctx.inbound.EffectiveUserEmail(),
        .inbound_tag = ctx.inbound.EffectiveInboundTag(),
        .ordered_bind_v4 = ordered ? std::optional{ordered->v4} : std::nullopt,
        .ordered_bind_v6 = ordered ? std::optional{ordered->v6} : std::nullopt,
    });
    if (!target) {
        if (target.error() == ErrorCode::DNS_RESOLVE_FAILED) {
            LOG_CONN_WARN(ctx, "DNS resolve failed for {}", server.address);
        }
        co_return tl::unexpected(target.error());
    }
    co_return co_await DialTarget(ctx, *target);
}

net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
OutboundDialer::Dial(session::Context& ctx,
                     std::span<const net::ip::address> addresses,
                     uint16_t port) {
    if (addresses.empty() || port == 0) {
        co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    const auto& bind = sender_.send_through;
    const auto ordered = SelectOrderedBind(ctx);
    const tcp::endpoint* inbound_local =
        ctx.inbound.local_endpoint ? &*ctx.inbound.local_endpoint : nullptr;
    auto candidate_for = [&](const net::ip::address& raw_remote) {
        const net::ip::address remote = iputil::NormalizeAddress(raw_remote);
        return OutboundDialCandidate{
            .endpoint = tcp::endpoint(remote, port),
            .bind_local = ordered
                ? (remote.is_v6() ? ordered->v6.address : ordered->v4.address)
                : bind.BindAddressFor(inbound_local, remote),
        };
    };

    OutboundTransportTarget target;
    target.timeout = timeout_;
    target.stream_settings = &sender_.stream_settings;
    target.security_context = security_.Context();
    if (addresses.size() == 1) {
        target.single_candidate = candidate_for(addresses.front());
    } else {
        target.candidates.reserve(addresses.size());
        for (const auto& remote : addresses) {
            target.candidates.push_back(candidate_for(remote));
        }
    }
    LOG_CONN_DEBUG(ctx, "dialing {} resolved candidates port={}", addresses.size(), port);
    co_return co_await DialTarget(ctx, target);
}

net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
OutboundDialer::DialTarget(session::Context& ctx, const OutboundTransportTarget& target) {
    auto dialed = co_await DialOutboundTransport(IoContext(), ctx, target);
    if (!dialed.Ok()) {
        ctx.outbound.connected_local_addr.reset();
        // The dispatcher reports every non-cancellation failure once.
        LOG_CONN_DEBUG(ctx, "dial failed {} -> {} > {}",
                       ctx.inbound.source_ip, ctx.outbound.target, dialed.error_msg);
        co_return tl::unexpected(dialed.error);
    }
    RecordConnected(ctx, *dialed.stream);
    co_return std::move(dialed.stream);
}

tl::expected<net::ip::address, ErrorCode> OutboundDialer::SelectDatagramBind(
    const session::Context& ctx, const DatagramRemote& remote) const {
    const auto& bind = sender_.send_through;
    if (bind.GetMode() == OutboundBind::Mode::Explicit) {
        return iputil::NormalizeAddress(*bind.ExplicitAddress());
    }
    const std::optional<net::ip::address> remote_addr = remote.address
        ? std::optional<net::ip::address>(iputil::NormalizeAddress(*remote.address))
        : std::nullopt;
    const std::optional<net::ip::address> family_hint = remote.family_hint
        ? std::optional<net::ip::address>(iputil::NormalizeAddress(*remote.family_hint))
        : std::nullopt;
    // Same-in-same-out: reuse the inbound local address when it can source
    // the association (OutboundBind owns the family/scope rules).
    if (bind.GetMode() == OutboundBind::Mode::Auto && ctx.inbound.local_endpoint) {
        const auto* local = &*ctx.inbound.local_endpoint;
        if (remote_addr) {
            if (auto bound = bind.BindAddressFor(local, *remote_addr)) return *bound;
        } else {
            const auto local_ip = iputil::NormalizeAddress(local->address());
            if (local_ip.is_v6() ? remote.accepts_v6 : remote.accepts_v4) {
                if (auto bound = bind.BindAddressFor(local, local_ip)) return *bound;
            }
        }
    }
    const bool v6 = remote_addr ? remote_addr->is_v6()
        : (remote.prefers_v6 && remote.accepts_v6) ? true
        : !remote.accepts_v6 ? false
        : family_hint ? family_hint->is_v6()
        : bind.PrefersIPv6();
    const net::ip::address any = v6
        ? net::ip::address(net::ip::address_v6::any())
        : net::ip::address(net::ip::address_v4::any());
    if (bind.GetMode() != OutboundBind::Mode::Ordered) return any;

    const auto client_ip = ctx.inbound.EffectiveClientIp();
    const auto user_id = ctx.inbound.EffectiveUserId();
    const auto user_email = ctx.inbound.EffectiveUserEmail();
    const auto inbound_tag = ctx.inbound.EffectiveInboundTag();
    auto selected = bind.Select(remote_addr.value_or(any),
                                client_ip, user_id, user_email, inbound_tag);
    // A hostname may still be reached over the other accepted family.
    if (!selected.address && !remote_addr && (v6 ? remote.accepts_v4 : remote.accepts_v6)) {
        const net::ip::address other = v6
            ? net::ip::address(net::ip::address_v4::any())
            : net::ip::address(net::ip::address_v6::any());
        selected = bind.Select(other, client_ip, user_id, user_email, inbound_tag);
    }
    if (!selected.address) return tl::unexpected(ErrorCode::SOCKET_BIND_FAILED);
    return *selected.address;
}

void OutboundDialer::ReportDatagramFailure(const session::Context& ctx,
                                           const net::ip::address& bind,
                                           std::string_view reason) const {
    LOG_CONN_DEBUG(ctx, "failed to open UDP {} via {} > {}",
                   ctx.outbound.target, iputil::AddressText(bind).View(), reason);
}

void OutboundDialer::RecordConnected(session::Context& ctx, const AsyncStream& stream) const {
    const auto local = stream.LocalEndpoint();
    RecordEgress(ctx, local ? std::optional{local->address()} : std::nullopt);
}

void OutboundDialer::RecordEgress(session::Context& ctx,
                                  const std::optional<net::ip::address>& local) const {
    ctx.outbound.connected_local_addr.reset();
    if (local) {
        const auto local_ip = iputil::NormalizeAddress(*local);
        if (!local_ip.is_unspecified()) {
            ctx.outbound.connected_local_addr = local_ip;
        }
    }
    LOG_ACCESS(FormatAccessLog(ctx));
}

