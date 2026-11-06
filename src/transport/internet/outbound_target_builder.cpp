#include "acppnode/transport/internet/outbound_target_builder.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/ip_address.hpp"
#include "acppnode/transport/internet/http_headers.hpp"

#include "acppnode/app/dns/dns.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/internet/transport_dialer.hpp"

#include <algorithm>
#include <memory>
#include <utility>

namespace acpp {

namespace {

void AppendCandidate(
    OutboundTransportTarget& target,
    const OutboundBind& bind,
    const tcp::endpoint* inbound_local_addr,
    const net::ip::address& remote_addr,
    uint16_t port) {
    OutboundDialCandidate candidate;
    candidate.endpoint = tcp::endpoint(remote_addr, port);
    candidate.bind_local = bind.BindAddressFor(inbound_local_addr, remote_addr);
    target.candidates.push_back(std::move(candidate));
}

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
AttachXHttpDownloadTarget(OutboundTransportTarget target,
                          const OutboundTargetOptions& options) {
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
            .inbound_local_addr = options.inbound_local_addr,
            .inbound_source_ip = options.inbound_source_ip,
            .inbound_source_port = options.inbound_source_port,
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

    const OutboundBind unbound;
    const auto& bind = options.send_through ? *options.send_through : unbound;
    const auto ordered_v4 = bind.GetMode() == OutboundBind::Mode::Ordered
        ? (options.ordered_bind_v4 ? *options.ordered_bind_v4
            : bind.Select(net::ip::address_v4::any(),
                          options.inbound_source_ip, options.inbound_source_port))
        : OutboundBind::Selection{};
    const auto ordered_v6 = bind.GetMode() == OutboundBind::Mode::Ordered
        ? (options.ordered_bind_v6 ? *options.ordered_bind_v6
            : bind.Select(net::ip::address_v6::any(),
                          options.inbound_source_ip, options.inbound_source_port))
        : OutboundBind::Selection{};

    OutboundTransportTarget target;
    target.timeout = options.timeout;
    target.stream_settings = options.stream_settings;
    target.security_context = options.security ? options.security->Context() : nullptr;
    target.tls_server_name = ResolveOutboundTlsServerName(
        *options.stream_settings, options.address);
    target.ws_host = BuildHttpHostHeader(
        *options.stream_settings, options.address, options.port);

    auto append_single = [&](const net::ip::address& remote_addr) {
        OutboundDialCandidate candidate;
        candidate.endpoint = tcp::endpoint(remote_addr, options.port);
        if (bind.GetMode() == OutboundBind::Mode::Ordered) {
            const auto& selected = remote_addr.is_v6() ? ordered_v6 : ordered_v4;
            candidate.bind_local = selected.address;
        } else {
            candidate.bind_local = bind.BindAddressFor(options.inbound_local_addr, remote_addr);
        }
        target.single_candidate = std::move(candidate);
    };

    if (options.literal_address) {
        append_single(*options.literal_address);
        co_return co_await AttachXHttpDownloadTarget(std::move(target), options);
    }
    if (auto literal = iputil::ParseLiteral(options.address)) {
        append_single(*literal);
        co_return co_await AttachXHttpDownloadTarget(std::move(target), options);
    }
    if (!options.dns_service) {
        co_return tl::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    auto dns_result = co_await options.dns_service->Resolve(options.address);
    if (!dns_result.Ok() || dns_result.addresses.empty()) {
        co_return tl::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }
    auto finalize_candidates = [&]()
        -> net::awaitable<tl::expected<OutboundTransportTarget, ErrorCode>> {
        if (target.candidates.empty() && !target.single_candidate) {
            co_return tl::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
        }
        if (target.candidates.size() == 1) {
            target.single_candidate = std::move(target.candidates.front());
            target.candidates.clear();
        }
        co_return co_await AttachXHttpDownloadTarget(std::move(target), options);
    };

    if (bind.GetMode() == OutboundBind::Mode::Ordered) {
        target.candidates.reserve(dns_result.addresses.size());
        for (const bool ipv6 : {bind.PrefersIPv6(), !bind.PrefersIPv6()}) {
            const auto& selected = ipv6 ? ordered_v6 : ordered_v4;
            for (const auto& addr : dns_result.addresses) {
                if (addr.is_v6() != ipv6) continue;
                target.candidates.push_back(OutboundDialCandidate{
                    .endpoint = tcp::endpoint(addr, options.port),
                    .bind_local = selected.address,
                });
            }
        }
        co_return co_await finalize_candidates();
    }

    if (bind.GetMode() == OutboundBind::Mode::Explicit) {
        const bool want_v6 = bind.ExplicitAddress() && bind.ExplicitAddress()->is_v6();
        target.candidates.reserve(dns_result.addresses.size());
        for (const auto& addr : dns_result.addresses) {
            if (addr.is_v6() == want_v6) {
                AppendCandidate(target, bind, options.inbound_local_addr, addr, options.port);
            }
        }
        co_return co_await finalize_candidates();
    }

    if (AutoPrefersIPv6(bind, options.inbound_local_addr)) {
        target.candidates.reserve(dns_result.addresses.size());
        for (const bool ipv6 : {true, false}) {
            for (const auto& addr : dns_result.addresses) {
                if (addr.is_v6() == ipv6) {
                    AppendCandidate(target, bind, options.inbound_local_addr, addr, options.port);
                }
            }
        }
        co_return co_await finalize_candidates();
    }

    const bool has_v4 = std::ranges::any_of(
        dns_result.addresses,
        [](const net::ip::address& addr) { return addr.is_v4(); });

    if (has_v4) {
        size_t v4_count = 0;
        const net::ip::address* first_v4 = nullptr;
        for (const auto& addr : dns_result.addresses) {
            if (!addr.is_v4()) {
                continue;
            }
            ++v4_count;
            if (!first_v4) {
                first_v4 = &addr;
            }
        }
        if (v4_count == 1) {
            append_single(*first_v4);
            co_return co_await AttachXHttpDownloadTarget(std::move(target), options);
        }
        target.candidates.reserve(v4_count);
        for (const auto& addr : dns_result.addresses) {
            if (addr.is_v4()) {
                AppendCandidate(target, bind, options.inbound_local_addr, addr, options.port);
            }
        }
        co_return co_await AttachXHttpDownloadTarget(std::move(target), options);
    }

    target.candidates.reserve(dns_result.addresses.size());
    for (const auto& addr : dns_result.addresses) {
        AppendCandidate(target, bind, options.inbound_local_addr, addr, options.port);
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

std::optional<OutboundDialer::OrderedBind> OutboundDialer::SelectOrderedBind(
    const session::Context& ctx) const {
    const auto& bind = sender_.send_through;
    if (bind.GetMode() != OutboundBind::Mode::Ordered) return std::nullopt;
    return OrderedBind{
        .v4 = bind.Select(net::ip::address_v4::any(),
                          ctx.inbound.source_ip, ctx.inbound.source_port),
        .v6 = bind.Select(net::ip::address_v6::any(),
                          ctx.inbound.source_ip, ctx.inbound.source_port),
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
        .inbound_source_ip = ctx.inbound.source_ip,
        .inbound_source_port = ctx.inbound.source_port,
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
    auto candidate_for = [&](const net::ip::address& remote) {
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
    auto dialed = co_await DialOutboundTransport(io_context_, ctx, target);
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
        return *bind.ExplicitAddress();
    }
    // Same-in-same-out: reuse the inbound local address when it can source
    // the association (OutboundBind owns the family/scope rules).
    if (bind.GetMode() == OutboundBind::Mode::Auto && ctx.inbound.local_endpoint) {
        const auto* local = &*ctx.inbound.local_endpoint;
        if (remote.address) {
            if (auto bound = bind.BindAddressFor(local, *remote.address)) return *bound;
        } else {
            const auto local_ip = iputil::NormalizeAddress(local->address());
            if (local_ip.is_v6() ? remote.accepts_v6 : remote.accepts_v4) {
                if (auto bound = bind.BindAddressFor(local, local_ip)) return *bound;
            }
        }
    }
    const bool v6 = remote.address ? remote.address->is_v6()
        : (remote.prefers_v6 && remote.accepts_v6) ? true
        : !remote.accepts_v6 ? false
        : remote.family_hint ? remote.family_hint->is_v6()
        : bind.PrefersIPv6();
    const net::ip::address any = v6
        ? net::ip::address(net::ip::address_v6::any())
        : net::ip::address(net::ip::address_v4::any());
    if (bind.GetMode() != OutboundBind::Mode::Ordered) return any;

    auto selected = bind.Select(remote.address.value_or(any),
                                ctx.inbound.source_ip, ctx.inbound.source_port);
    // A hostname may still be reached over the other accepted family.
    if (!selected.address && !remote.address && (v6 ? remote.accepts_v4 : remote.accepts_v6)) {
        const net::ip::address other = v6
            ? net::ip::address(net::ip::address_v4::any())
            : net::ip::address(net::ip::address_v6::any());
        selected = bind.Select(other, ctx.inbound.source_ip, ctx.inbound.source_port);
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

}  // namespace acpp
