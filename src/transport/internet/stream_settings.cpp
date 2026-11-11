#include "transport/internet/stream_settings.hpp"
#include "core/constants.hpp"

#include <algorithm>
#include <atomic>
#include <utility>


std::string XHttpConfig::NormalizedPath() const {
    std::string normalized = path.empty()
        ? std::string(constants::binding::kRootPath)
        : path;
    const size_t query_pos = normalized.find('?');
    if (query_pos != std::string::npos) {
        normalized.erase(query_pos);
    }
    if (normalized.empty() || normalized.front() != '/') {
        normalized.insert(normalized.begin(), '/');
    }
    if (normalized.back() != '/') {
        normalized.push_back('/');
    }
    return normalized;
}

std::string GrpcConfig::RequestPath() const {
    if (!service_name.empty() && service_name.front() == '/') {
        return service_name;
    }
    std::string path;
    path.reserve(service_name.size() + 10);
    path.push_back('/');
    path.append(service_name);
    path.append(multi_mode ? "/TunMulti" : "/Tun");
    return path;
}

namespace {

// Explicit host precedence per layer: dedicated field, then a configured
// Host header. gRPC has no Host header; its :authority comes from `authority`.
[[nodiscard]] std::string ConfiguredHttpHost(const StreamSettings& settings) {
    using transport::internet::ResolveConfiguredHttpHost;
    switch (settings.network_mode) {
    case NetworkMode::Ws:
        return std::string(ResolveConfiguredHttpHost({}, &settings.ws.headers));
    case NetworkMode::HttpUpgrade:
        return std::string(ResolveConfiguredHttpHost(
            settings.http_upgrade.host, &settings.http_upgrade.headers));
    case NetworkMode::Http:
        return std::string(ResolveConfiguredHttpHost(
            settings.http.host, &settings.http.headers));
    case NetworkMode::Grpc:
        return settings.grpc.authority;
    case NetworkMode::XHttp:
        return std::string(ResolveConfiguredHttpHost(
            settings.xhttp.host, &settings.xhttp.headers));
    default:
        return {};
    }
}

void NormalizeInPlace(StreamSettings& settings) {
    // 仅初始化/配置更新时调用，热路径不再做字符串比较
    settings.prepared_security.reset();
    if (settings.security_mode == SecurityMode::Reality) {
        settings.tls.min_version = TlsVersion::V1_3;
        settings.tls.max_version = TlsVersion::V1_3;
        if (settings.tls.server_name.empty() && !settings.reality.server_name.empty()) {
            settings.tls.server_name = settings.reality.server_name;
        }
    }

    const bool tls_like_for_alpn = settings.IsTls();
    const bool http_should_default_h2 =
        settings.network_mode == NetworkMode::Http &&
        (settings.http.force_http2 ||
         (tls_like_for_alpn && settings.tls.alpn.empty()));
    const bool xhttp_should_default_h2 =
        settings.network_mode == NetworkMode::XHttp &&
        settings.security_mode != SecurityMode::Reality &&
        (settings.xhttp.AcceptsStreamOne() || tls_like_for_alpn) &&
        settings.tls.alpn.empty();
    if ((settings.network_mode == NetworkMode::Grpc && tls_like_for_alpn) ||
        http_should_default_h2 ||
        xhttp_should_default_h2) {
        auto has_h2 = std::ranges::find(settings.tls.alpn, "h2") != settings.tls.alpn.end();
        if (!has_h2) {
            settings.tls.alpn.insert(settings.tls.alpn.begin(), "h2");
        }
    }

    settings.grpc.request_path = settings.grpc.RequestPath();
    settings.xhttp.normalized_path = settings.xhttp.NormalizedPath();
    if (settings.IsXHttp() && settings.xhttp.session_namespace.empty()) {
        static std::atomic<uint64_t> next_namespace{1};
        settings.xhttp.session_namespace =
            std::to_string(next_namespace.fetch_add(1, std::memory_order_relaxed));
    }
    settings.configured_http_host = ConfiguredHttpHost(settings);
}

}  // namespace

NetworkMode ParseNetworkMode(std::string_view network) noexcept {
    if (network.empty() || EqualsAsciiCI(network, constants::protocol::kTcp) ||
        EqualsAsciiCI(network, constants::protocol::kRaw)) {
        return NetworkMode::Tcp;
    }
    if (EqualsAsciiCI(network, constants::protocol::kWs) ||
        EqualsAsciiCI(network, constants::protocol::kWebSocket)) {
        return NetworkMode::Ws;
    }
    if (EqualsAsciiCI(network, constants::protocol::kHttpUpgrade)) return NetworkMode::HttpUpgrade;
    if (EqualsAsciiCI(network, constants::protocol::kGrpc)) return NetworkMode::Grpc;
    if (EqualsAsciiCI(network, constants::protocol::kHttp) || EqualsAsciiCI(network, "h2")) {
        return NetworkMode::Http;
    }
    if (EqualsAsciiCI(network, constants::protocol::kXHttp) || EqualsAsciiCI(network, "splithttp")) {
        return NetworkMode::XHttp;
    }
    return NetworkMode::Unsupported;
}

SecurityMode ParseSecurityMode(std::string_view security) noexcept {
    if (security.empty() || EqualsAsciiCI(security, constants::protocol::kNone)) return SecurityMode::None;
    if (EqualsAsciiCI(security, constants::protocol::kTls)) return SecurityMode::Tls;
    if (EqualsAsciiCI(security, constants::protocol::kReality)) return SecurityMode::Reality;
    return SecurityMode::Unsupported;
}

std::string_view NetworkModeName(NetworkMode mode) noexcept {
    switch (mode) {
        case NetworkMode::Tcp: return "tcp";
        case NetworkMode::Ws: return "ws";
        case NetworkMode::HttpUpgrade: return "httpupgrade";
        case NetworkMode::Grpc: return "grpc";
        case NetworkMode::Http: return "http";
        case NetworkMode::XHttp: return "xhttp";
        case NetworkMode::Unsupported: return "unsupported";
    }
    return "unsupported";
}

std::string_view SecurityModeName(SecurityMode mode) noexcept {
    switch (mode) {
        case SecurityMode::None: return "none";
        case SecurityMode::Tls: return "tls";
        case SecurityMode::Reality: return "reality";
        case SecurityMode::Unsupported: return "unsupported";
    }
    return "unsupported";
}

XHttpMode ResolveXHttpOutboundMode(const StreamSettings& settings) noexcept {
    const XHttpConfig& cfg = settings.xhttp;
    if (cfg.mode != XHttpMode::Auto) {
        return cfg.mode;
    }
    if (cfg.download_settings) {
        return XHttpMode::StreamUp;
    }
    if (settings.IsReality()) {
        return XHttpMode::StreamOne;
    }
    const bool http11_only = settings.tls.alpn.size() == 1 &&
                             settings.tls.alpn.front() == "http/1.1";
    if (settings.IsTls() && !http11_only) {
        return XHttpMode::StreamUp;
    }
    return XHttpMode::PacketUp;
}

StreamSettings NormalizeStreamSettings(const StreamSettings& source) {
    auto settings = source;
    NormalizeInPlace(settings);
    return settings;
}

StreamSettings NormalizeOutboundStreamSettings(
    const StreamSettings& source, const OutboundStreamDefaults& defaults) {
    auto settings = source;
    if (defaults.require_tls) settings.security_mode = SecurityMode::Tls;
    NormalizeInPlace(settings);
    if (settings.IsTls()) {
        if (settings.tls.server_name.empty() && !defaults.fallback_server_name.empty()) {
            settings.tls.server_name = defaults.fallback_server_name;
        }
        if (defaults.allow_insecure) settings.tls.allow_insecure = true;
        if (settings.tls.alpn.empty() && !defaults.alpn.empty()) {
            settings.tls.alpn.assign(defaults.alpn.begin(), defaults.alpn.end());
        }
    }
    return settings;
}

