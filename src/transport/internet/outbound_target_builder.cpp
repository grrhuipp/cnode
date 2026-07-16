#include "acppnode/transport/internet/outbound_target_builder.hpp"

#include "acppnode/app/dns/dns.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/core/constants.hpp"

#include <algorithm>
#include <cctype>
#include <memory>
#include <utility>

namespace acpp {

net::awaitable<std::expected<OutboundTransportTarget, ErrorCode>>
BuildOutboundTransportTargetInternal(OutboundTargetOptions options,
                                     bool allow_xhttp_download);

namespace {

std::optional<net::ip::address> SelectBindAddress(
    const OutboundBind& bind,
    const tcp::endpoint* inbound_local_addr,
    const net::ip::address& remote_addr) {
    if (bind.GetMode() == OutboundBind::Mode::Explicit) {
        return bind.ExplicitAddress();
    }
    if (bind.GetMode() != OutboundBind::Mode::Auto || !inbound_local_addr) {
        return std::nullopt;
    }

    const auto inbound_local =
        iputil::NormalizeAddress(inbound_local_addr->address());
    if (inbound_local.is_unspecified() || inbound_local.is_loopback()) {
        return std::nullopt;
    }
    if ((remote_addr.is_v4() && inbound_local.is_v4()) ||
        (remote_addr.is_v6() && inbound_local.is_v6())) {
        return inbound_local;
    }
    return std::nullopt;
}

void AppendCandidate(
    OutboundTransportTarget& target,
    const OutboundBind& bind,
    const tcp::endpoint* inbound_local_addr,
    const net::ip::address& remote_addr,
    uint16_t port) {
    OutboundDialCandidate candidate;
    candidate.endpoint = tcp::endpoint(remote_addr, port);
    candidate.bind_local = SelectBindAddress(bind, inbound_local_addr, remote_addr);
    target.candidates.push_back(std::move(candidate));
}

bool WantsIPv6(const OutboundBind& bind, const tcp::endpoint* inbound_local_addr) noexcept {
    if (bind.GetMode() == OutboundBind::Mode::Explicit) {
        return bind.ExplicitAddress() && bind.ExplicitAddress()->is_v6();
    }
    if (!inbound_local_addr) {
        return false;
    }
    const auto inbound_local =
        iputil::NormalizeAddress(inbound_local_addr->address());
    return inbound_local.is_v6() && !inbound_local.is_unspecified() &&
           !inbound_local.is_loopback();
}

[[nodiscard]] char LowerAsciiChar(char ch) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
}

[[nodiscard]] bool EqualsAsciiCI(std::string_view lhs, std::string_view rhs) {
    if (lhs.size() != rhs.size()) {
        return false;
    }
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (LowerAsciiChar(lhs[i]) != LowerAsciiChar(rhs[i])) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string_view FindHttpHeaderCI(
    const transport::internet::HttpHeaders& headers,
    std::string_view name) {
    for (const auto& [key, value] : headers) {
        if (EqualsAsciiCI(key, name)) {
            return value;
        }
    }
    return {};
}

[[nodiscard]] std::string BuildWsHostHeader(
    const StreamSettings& settings,
    std::string_view fallback_host,
    uint16_t port) {
    if (!settings.IsWs()) {
        return {};
    }
    if (const std::string_view explicit_host = FindHttpHeaderCI(settings.ws.headers, "Host");
        !explicit_host.empty()) {
        return std::string(explicit_host);
    }
    return iputil::FormatHttpHostHeader(fallback_host, port, settings.IsTls());
}

[[nodiscard]] std::string BuildHttpUpgradeHostHeader(
    const StreamSettings& settings,
    std::string_view fallback_host,
    uint16_t port) {
    if (!settings.IsHttpUpgrade()) {
        return {};
    }
    if (!settings.http_upgrade.host.empty()) {
        return settings.http_upgrade.host;
    }
    if (const std::string_view explicit_host =
            FindHttpHeaderCI(settings.http_upgrade.headers, "Host");
        !explicit_host.empty()) {
        return std::string(explicit_host);
    }
    return iputil::FormatHttpHostHeader(fallback_host, port, settings.IsTls());
}

[[nodiscard]] std::string BuildGrpcAuthority(
    const StreamSettings& settings,
    std::string_view fallback_host,
    uint16_t port) {
    if (!settings.IsGrpc()) {
        return {};
    }
    if (!settings.grpc.authority.empty()) {
        return settings.grpc.authority;
    }
    if (settings.IsReality()) {
        return {};
    }
    return iputil::FormatHttpHostHeader(fallback_host, port, settings.IsTls());
}

[[nodiscard]] std::string BuildXHttpHostHeader(
    const StreamSettings& settings,
    std::string_view fallback_host,
    uint16_t port) {
    if (!settings.IsXHttp()) {
        return {};
    }
    if (!settings.xhttp.host.empty()) {
        return settings.xhttp.host;
    }
    if (const std::string_view explicit_host =
            FindHttpHeaderCI(settings.xhttp.headers, "Host");
        !explicit_host.empty()) {
        return std::string(explicit_host);
    }
    return iputil::FormatHttpHostHeader(fallback_host, port, settings.IsTls());
}

[[nodiscard]] std::string BuildHttpHostHeader(
    const StreamSettings& settings,
    std::string_view fallback_host,
    uint16_t port) {
    if (settings.IsWs()) {
        return BuildWsHostHeader(settings, fallback_host, port);
    }
    if (settings.IsHttpUpgrade()) {
        return BuildHttpUpgradeHostHeader(settings, fallback_host, port);
    }
    if (settings.IsGrpc()) {
        return BuildGrpcAuthority(settings, fallback_host, port);
    }
    if (settings.IsXHttp()) {
        return BuildXHttpHostHeader(settings, fallback_host, port);
    }
    return {};
}

net::awaitable<std::expected<OutboundTransportTarget, ErrorCode>>
AttachXHttpDownloadTarget(OutboundTransportTarget target,
                          const OutboundTargetOptions& options,
                          bool allow_xhttp_download) {
    if (!allow_xhttp_download ||
        !options.stream_settings ||
        !options.stream_settings->IsXHttp() ||
        !options.stream_settings->xhttp.download_settings) {
        co_return target;
    }

    const auto& upload_xhttp = options.stream_settings->xhttp;
    if (upload_xhttp.IsStreamOne()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    const auto& download = *upload_xhttp.download_settings;
    if (download.address.empty() || download.port == 0) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    if (!download.stream_settings.IsXHttp() ||
        download.stream_settings.IsUnsupported() ||
        download.stream_settings.xhttp.IsStreamOne()) {
        co_return std::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
    }

    auto download_target = co_await BuildOutboundTransportTargetInternal(
        OutboundTargetOptions{
            .dns_service = options.dns_service,
            .address = download.address,
            .literal_address = std::nullopt,
            .port = download.port,
            .stream_settings = &download.stream_settings,
            .timeout = options.timeout,
            .send_through = download.send_through,
            .inbound_local_addr = options.inbound_local_addr,
            .tls_server_name = ResolveOutboundTlsServerName(
                download.stream_settings,
                download.address),
            .ws_host = download.address,
        },
        false);
    if (!download_target) {
        co_return std::unexpected(download_target.error());
    }

    target.xhttp_download_target =
        std::make_shared<OutboundTransportTarget>(std::move(*download_target));
    co_return target;
}

}  // namespace

std::optional<net::ip::address> ParseLiteralAddress(std::string_view address) {
    IoErrorCode ec;
    auto parsed = net::ip::make_address(address, ec);
    if (ec) {
        return std::nullopt;
    }
    return parsed;
}

void NormalizeOutboundStreamSettings(
    StreamSettings& settings,
    const OutboundStreamDefaults& defaults) {
    if (settings.network.empty()) {
        settings.network = std::string(constants::protocol::kTcp);
    }
    if (settings.security.empty()) {
        settings.security = std::string(constants::protocol::kNone);
    }
    if (defaults.require_tls) {
        settings.security = std::string(constants::protocol::kTls);
    }

    settings.RecomputeModes();
    if (settings.IsTls()) {
        if (settings.tls.server_name.empty() && !defaults.fallback_server_name.empty()) {
            settings.tls.server_name = std::string(defaults.fallback_server_name);
        }
        if (defaults.allow_insecure) {
            settings.tls.allow_insecure = true;
        }
        if (settings.tls.alpn.empty() && !defaults.alpn.empty()) {
            settings.tls.alpn.assign(defaults.alpn.begin(), defaults.alpn.end());
        }
    }
    settings.RecomputeModes();
}

std::string_view ResolveOutboundTlsServerName(
    const StreamSettings& settings,
    std::string_view fallback_server_name) {
    if (!settings.tls.server_name.empty()) {
        return settings.tls.server_name;
    }
    return fallback_server_name;
}

net::awaitable<std::expected<OutboundTransportTarget, ErrorCode>>
BuildOutboundTransportTargetInternal(OutboundTargetOptions options,
                                     bool allow_xhttp_download) {
    if (!options.stream_settings || options.port == 0) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }
    if (!options.literal_address && options.address.empty()) {
        co_return std::unexpected(ErrorCode::INVALID_ARGUMENT);
    }

    const auto& bind = options.send_through;

    OutboundTransportTarget target;
    switch (bind.GetMode()) {
        case OutboundBind::Mode::None:
            target.bind_mode = OutboundTransportTarget::BindMode::None;
            break;
        case OutboundBind::Mode::Auto:
            target.bind_mode = OutboundTransportTarget::BindMode::Auto;
            break;
        case OutboundBind::Mode::Explicit:
            target.bind_mode = OutboundTransportTarget::BindMode::Explicit;
            break;
    }
    target.timeout = options.timeout;
    target.stream_settings = options.stream_settings;
    target.tls_server_name = options.tls_server_name;
    target.ws_host = BuildHttpHostHeader(
        *options.stream_settings,
        options.ws_host.empty() ? options.address : options.ws_host,
        options.port);

    auto append_single = [&](const net::ip::address& remote_addr) {
        OutboundDialCandidate candidate;
        candidate.endpoint = tcp::endpoint(remote_addr, options.port);
        candidate.bind_local =
            SelectBindAddress(bind, options.inbound_local_addr, remote_addr);
        target.single_candidate = std::move(candidate);
    };

    if (options.literal_address) {
        append_single(*options.literal_address);
        co_return co_await AttachXHttpDownloadTarget(
            std::move(target),
            options,
            allow_xhttp_download);
    }
    if (auto literal = ParseLiteralAddress(options.address)) {
        append_single(*literal);
        co_return co_await AttachXHttpDownloadTarget(
            std::move(target),
            options,
            allow_xhttp_download);
    }
    if (!options.dns_service) {
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

    auto dns_result = co_await options.dns_service->Resolve(options.address);
    if (!dns_result.Ok()) {
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }
    const bool wants_v6 = WantsIPv6(bind, options.inbound_local_addr);
    const bool has_v4 = std::ranges::any_of(
        dns_result.addresses,
        [](const net::ip::address& addr) { return addr.is_v4(); });

    if (wants_v6) {
        for (const auto& addr : dns_result.addresses) {
            if (addr.is_v6()) {
                append_single(addr);
                co_return co_await AttachXHttpDownloadTarget(
                    std::move(target),
                    options,
                    allow_xhttp_download);
            }
        }
        co_return std::unexpected(ErrorCode::DNS_RESOLVE_FAILED);
    }

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
            co_return co_await AttachXHttpDownloadTarget(
                std::move(target),
                options,
                allow_xhttp_download);
        }
        target.candidates.reserve(v4_count);
        for (const auto& addr : dns_result.addresses) {
            if (addr.is_v4()) {
                AppendCandidate(target, bind, options.inbound_local_addr, addr, options.port);
            }
        }
        co_return co_await AttachXHttpDownloadTarget(
            std::move(target),
            options,
            allow_xhttp_download);
    }

    target.candidates.reserve(dns_result.addresses.size());
    for (const auto& addr : dns_result.addresses) {
        AppendCandidate(target, bind, options.inbound_local_addr, addr, options.port);
    }
    co_return co_await AttachXHttpDownloadTarget(
        std::move(target),
        options,
        allow_xhttp_download);
}

net::awaitable<std::expected<OutboundTransportTarget, ErrorCode>>
BuildOutboundTransportTarget(OutboundTargetOptions options) {
    co_return co_await BuildOutboundTransportTargetInternal(
        std::move(options),
        true);
}

}  // namespace acpp
