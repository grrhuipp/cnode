#include "transport/internet/stream_settings.hpp"
#include "core/naming.hpp"

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
    const auto header_host = [](const transport::internet::HttpHeaders& headers) {
        const auto* host = transport::internet::FindHttpHeader(headers, "Host");
        return host ? *host : std::string{};
    };
    switch (settings.network_mode) {
    case NetworkMode::Ws:
        return header_host(settings.ws.headers);
    case NetworkMode::HttpUpgrade:
        return settings.http_upgrade.host.empty()
            ? header_host(settings.http_upgrade.headers) : settings.http_upgrade.host;
    case NetworkMode::Http:
        return settings.http.host.empty()
            ? header_host(settings.http.headers) : settings.http.host;
    case NetworkMode::Grpc:
        return settings.grpc.authority;
    case NetworkMode::XHttp:
        return settings.xhttp.host.empty()
            ? header_host(settings.xhttp.headers) : settings.xhttp.host;
    default:
        return {};
    }
}

void NormalizeInPlace(StreamSettings& settings) {
    // 仅初始化/配置更新时调用，热路径不再做字符串比较
    settings.prepared_security.reset();
    settings.network = naming::LowerAscii(std::move(settings.network));
    settings.security = naming::LowerAscii(std::move(settings.security));

    settings.network_mode = ParseNetworkMode(settings.network);
    if (settings.network_mode == NetworkMode::Http && settings.network == "h2") {
        settings.http.force_http2 = true;
    }

    if (settings.security.empty() || settings.security == constants::protocol::kNone) {
        settings.security_mode = SecurityMode::None;
    } else if (settings.security == constants::protocol::kTls) {
        settings.security_mode = SecurityMode::Tls;
    } else if (settings.security == constants::protocol::kReality) {
        settings.security_mode = SecurityMode::Reality;
        settings.tls.min_version = TlsVersion::V1_3;
        settings.tls.max_version = TlsVersion::V1_3;
        if (settings.tls.server_name.empty() && !settings.reality.server_name.empty()) {
            settings.tls.server_name = settings.reality.server_name;
        }
    } else {
        settings.security_mode = SecurityMode::Unsupported;
    }

    settings.flags = kFlagNone;
    if (settings.network_mode == NetworkMode::Ws) {
        settings.flags |= kFlagWs;
    }
    if (settings.network_mode == NetworkMode::HttpUpgrade) {
        settings.flags |= kFlagHttpUpgrade;
    }
    if (settings.network_mode == NetworkMode::Grpc) {
        settings.flags |= kFlagGrpc;
        settings.network = std::string(constants::protocol::kGrpc);
    }
    if (settings.network_mode == NetworkMode::Http) {
        settings.flags |= kFlagHttp;
        settings.network = settings.http.force_http2 ? "h2" : std::string(constants::protocol::kHttp);
    }
    if (settings.network_mode == NetworkMode::XHttp) {
        settings.flags |= kFlagXHttp;
        settings.network = std::string(constants::protocol::kXHttp);
    }
    if (settings.security_mode == SecurityMode::Tls) {
        settings.flags |= kFlagTls;
    }
    if (settings.security_mode == SecurityMode::Reality) {
        settings.flags |= kFlagReality;
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
    using transport::internet::EqualsAsciiCI;
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
    if (settings.network.empty()) settings.network = constants::protocol::kTcp;
    if (settings.security.empty()) settings.security = constants::protocol::kNone;
    if (defaults.require_tls) settings.security = constants::protocol::kTls;
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

