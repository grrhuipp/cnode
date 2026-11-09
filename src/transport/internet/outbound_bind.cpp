#include "transport/internet/outbound_bind.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "app/dns/dns.hpp"
#include "common/allocator.hpp"
#include "common/session.hpp"
#include "infra/log.hpp"

#include "common/ip_utils.hpp"
#include "common/ip_address.hpp"
#include "core/constants.hpp"
#include "transport/internet/http_headers.hpp"

#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <functional>
#include <string>
#include <thread>

namespace {

uint64_t MixHash(uint64_t value) noexcept {
    value += 0x9e3779b97f4a7c15ull;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ull;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebull;
    return value ^ (value >> 31);
}

uint64_t IpKeyHash(std::string_view ip) noexcept {
    uint64_t value = 14695981039346656037ull;
    for (const unsigned char byte : ip) {
        value = (value ^ byte) * 1099511628211ull;
    }
    return MixHash(value);
}

uint64_t UserKeyHash(
    int64_t user_id,
    std::string_view user_email,
    std::string_view fallback_ip,
    std::string_view inbound_tag) noexcept {
    if (user_id <= 0 && user_email.empty()) {
        return IpKeyHash(fallback_ip);
    }
    uint64_t value = 14695981039346656037ull;
    for (const unsigned char byte : inbound_tag) {
        value = (value ^ byte) * 1099511628211ull;
    }
    value = (value ^ 0xffu) * 1099511628211ull;
    const uint64_t uid = user_id > 0 ? static_cast<uint64_t>(user_id) : 0;
    for (unsigned shift = 0; shift < 64; shift += 8) {
        value = (value ^ static_cast<unsigned char>(uid >> shift)) *
                1099511628211ull;
    }
    value = (value ^ 0xffu) * 1099511628211ull;
    for (const unsigned char byte : user_email) {
        value = (value ^ byte) * 1099511628211ull;
    }
    return MixHash(value);
}

uint64_t RandomIndex() noexcept {
    static thread_local uint64_t state =
        static_cast<uint64_t>(std::chrono::steady_clock::now().time_since_epoch().count()) ^
        std::hash<std::thread::id>{}(std::this_thread::get_id()) ^
        0x9e3779b97f4a7c15ull;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * 2685821657736338717ull;
}

[[nodiscard]] std::optional<OutboundDialer::OrderedBind> SelectOrderedBind(
    const OutboundBind& bind,
    std::string_view source_ip,
    int64_t user_id,
    std::string_view user_email,
    std::string_view inbound_tag) {
    if (bind.GetMode() != OutboundBind::Mode::Ordered) return std::nullopt;
    return OutboundDialer::OrderedBind{
        .v4 = bind.Select(net::ip::address_v4::any(), source_ip, user_id, user_email, inbound_tag),
        .v6 = bind.Select(net::ip::address_v6::any(), source_ip, user_id, user_email, inbound_tag),
    };
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
AttachXHttpDownloadTarget(
    OutboundTransportTarget target,
    const OutboundTargetOptions& options,
    const tcp::endpoint* inbound_local_addr,
    const std::optional<OutboundDialer::OrderedBind>& download_ordered) {
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
            .inbound_user_id = options.inbound_user_id,
            .ordered_bind_v4 = download_ordered ? std::optional{download_ordered->v4} : std::nullopt,
            .ordered_bind_v6 = download_ordered ? std::optional{download_ordered->v6} : std::nullopt,
        });
    if (!download_target) {
        co_return tl::unexpected(download_target.error());
    }

    target.xhttp_download_target =
        memory::AllocateShared<OutboundTransportTarget>(std::move(*download_target));
    co_return target;
}
}  // namespace

OutboundBind OutboundBind::Auto() noexcept {
    OutboundBind bind;
    bind.mode_ = Mode::Auto;
    return bind;
}

std::optional<net::ip::address> OutboundBind::BindAddressFor(
    const tcp::endpoint* inbound_local, const net::ip::address& remote) const noexcept {
    if (mode_ == Mode::Explicit) {
        return explicit_address_;
    }
    if (mode_ != Mode::Auto || !inbound_local) {
        return std::nullopt;
    }
    // Same-in-same-out: reuse the inbound local address when it can source
    // a connection to `remote`.
    const auto local = iputil::NormalizeAddress(inbound_local->address());
    const auto normalized_remote = iputil::NormalizeAddress(remote);
    if (local.is_unspecified() || local.is_loopback() ||
        normalized_remote.is_unspecified() || normalized_remote.is_loopback() ||
        local.is_v4() != normalized_remote.is_v4()) {
        return std::nullopt;
    }
    if (local.is_v6() &&
        (local.to_v6().is_link_local() || normalized_remote.to_v6().is_link_local())) {
        return std::nullopt;
    }
    return local;
}

std::optional<OutboundBind> OutboundBind::Parse(std::string_view value) {
    OutboundBind bind;
    if (value.empty()) return bind;
    if (transport::internet::EqualsAsciiCI(value, constants::binding::kAuto)) return Auto();

    auto address = iputil::ParseLiteral(value);
    if (!address) return std::nullopt;
    *address = iputil::NormalizeAddress(*address);
    if (address->is_unspecified()) return bind;
    bind.mode_ = Mode::Explicit;
    bind.explicit_address_ = std::move(*address);
    return bind;
}

std::optional<OutboundBind> OutboundBind::ParseCandidates(
    std::span<const std::string_view> entries, ChoicePolicy policy) {
    if (entries.empty()) return std::nullopt;
    OutboundBind bind;
    bind.mode_ = Mode::Ordered;
    bind.policy_ = policy;
    std::vector<Entry> prepared;
    prepared.reserve(entries.size());
    for (const auto text : entries) {
        if (text.empty() || text.find('\0') != std::string_view::npos) return std::nullopt;
        Entry entry;
        const auto slash = text.find('/');
        auto address = iputil::ParseLiteral(text.substr(0, slash));
        if (!address) return std::nullopt;
        const auto normalized = iputil::NormalizeAddress(*address);
        if (slash != std::string_view::npos && address->is_v6() != normalized.is_v6()) {
            return std::nullopt;
        }
        *address = normalized;
        entry.is_v6 = address->is_v6();
        const unsigned int max_prefix = entry.is_v6 ? 128 : 32;
        unsigned int prefix = max_prefix;
        if (slash != std::string_view::npos) {
            const auto length = text.substr(slash + 1);
            if (length.empty() || (length.size() > 1 && length.front() == '0')) {
                return std::nullopt;
            }
            const auto [end, error] = std::from_chars(
                length.data(), length.data() + length.size(), prefix);
            if (error != std::errc{} || end != length.data() + length.size() ||
                prefix > max_prefix) return std::nullopt;
        }
        entry.prefix_length = static_cast<uint8_t>(prefix);
        entry.network_or_ip = slash == std::string_view::npos ? *address :
            entry.is_v6
                ? net::ip::address(net::ip::network_v6(
                    address->to_v6(), static_cast<unsigned short>(prefix)).network())
                : net::ip::address(net::ip::network_v4(
                    address->to_v4(), static_cast<unsigned short>(prefix)).network());
        if (entry.network_or_ip.is_unspecified()) return std::nullopt;
        prepared.push_back(std::move(entry));
    }
    bind.entries_ = std::make_shared<const std::vector<Entry>>(std::move(prepared));
    return bind;
}

OutboundBind::Selection OutboundBind::Select(
    const net::ip::address& remote,
    std::string_view client_ip,
    int64_t user_id,
    std::string_view user_email,
    std::string_view inbound_tag) const noexcept {
    if (mode_ == Mode::Explicit) return {.address = explicit_address_};
    if (mode_ != Mode::Ordered) return {};

    const auto normalized_remote = iputil::NormalizeAddress(remote);
    for (const auto& entry : *entries_) {
        if (entry.is_v6 != normalized_remote.is_v6()) continue;
        if (entry.prefix_length == (entry.is_v6 ? 128 : 32)) {
            return {.address = entry.network_or_ip};
        }
        const uint64_t key = policy_ == ChoicePolicy::Random
            ? RandomIndex()
            : policy_ == ChoicePolicy::UserHash
                ? UserKeyHash(user_id, user_email, client_ip, inbound_tag)
                : IpKeyHash(client_ip);
        if (!entry.is_v6) {
            const auto prefix = entry.prefix_length;
            const uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
            const uint32_t ip = (entry.network_or_ip.to_v4().to_uint() & mask) |
                (static_cast<uint32_t>(key) & ~mask);
            return {.address = net::ip::address_v4(ip)};
        }
        const auto v6 = entry.network_or_ip.to_v6();
        auto bytes = v6.to_bytes();
        const uint64_t high = key;
        const uint64_t low = policy_ == ChoicePolicy::Random ? RandomIndex() : MixHash(key);
        for (size_t i = 0; i < bytes.size(); ++i) {
            const unsigned bits = entry.prefix_length > i * 8
                ? std::min<unsigned>(8, entry.prefix_length - static_cast<unsigned>(i * 8))
                : 0;
            const uint8_t mask = bits == 0 ? 0 : static_cast<uint8_t>(0xffu << (8 - bits));
            const uint64_t word = i < 8 ? high : low;
            const unsigned shift = static_cast<unsigned>(i < 8 ? (7 - i) * 8 : (15 - i) * 8);
            const auto suffix = static_cast<uint8_t>(word >> shift);
            bytes[i] = (bytes[i] & mask) | (suffix & static_cast<uint8_t>(~mask));
        }
        return {.address = net::ip::address_v6(bytes, v6.scope_id())};
    }
    return {};
}
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
    const auto default_ordered =
        (!options.ordered_bind_v4 || !options.ordered_bind_v6)
            ? SelectOrderedBind(
                  bind,
                  options.inbound_source_ip,
                  options.inbound_user_id,
                  options.inbound_user_email,
                  options.inbound_tag)
            : std::nullopt;
    const auto ordered_v4 = options.ordered_bind_v4
        ? *options.ordered_bind_v4
        : (default_ordered ? default_ordered->v4 : OutboundBind::Selection{});
    const auto ordered_v6 = options.ordered_bind_v6
        ? *options.ordered_bind_v6
        : (default_ordered ? default_ordered->v6 : OutboundBind::Selection{});

    std::optional<OutboundDialer::OrderedBind> download_ordered;
    if (options.stream_settings->IsXHttp() &&
        options.stream_settings->xhttp.download_settings) {
        download_ordered = SelectOrderedBind(
            options.stream_settings->xhttp.download_settings->send_through,
            options.inbound_source_ip,
            options.inbound_user_id,
            options.inbound_user_email,
            options.inbound_tag);
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
            download_ordered);
    }
    if (auto literal = iputil::ParseLiteral(options.address)) {
        append_single(*literal);
        co_return co_await AttachXHttpDownloadTarget(
            std::move(target),
            options,
            inbound_local_ptr,
            download_ordered);
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
            download_ordered);
    };

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

    if (bind.GetMode() == OutboundBind::Mode::Ordered ||
        AutoPrefersIPv6(bind, inbound_local_ptr)) {
        const bool prefer_v6 = bind.GetMode() == OutboundBind::Mode::Ordered
            ? bind.PrefersIPv6()
            : true;
        for (const bool ipv6 : {prefer_v6, !prefer_v6}) {
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

ForwardedMetadataView OutboundDialer::ForwardedMetadata(
    const session::Context& ctx) const noexcept {
    return sender_.passthrough ? ctx.inbound.MakeForwardedMetadata()
                               : ForwardedMetadataView{};
}

std::optional<OutboundDialer::OrderedBind> OutboundDialer::SelectOrderedBind(
    const session::Context& ctx) const {
    return ::SelectOrderedBind(
        sender_.send_through,
        ctx.inbound.EffectiveClientIp(),
        ctx.inbound.EffectiveUserId(),
        ctx.inbound.EffectiveUserEmail(),
        ctx.inbound.EffectiveInboundTag());
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


