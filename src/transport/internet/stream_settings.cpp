#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/core/naming.hpp"

#include <algorithm>
#include <utility>

namespace acpp {

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

bool XHttpConfig::IsStreamOne() const noexcept {
    return mode == "stream-one";
}

bool XHttpConfig::AcceptsStreamOne() const noexcept {
    return mode.empty() ||
           mode == "auto" ||
           mode == "stream-one" ||
           mode == "stream-up";
}

bool XHttpConfig::AcceptsPacketUp() const noexcept {
    return mode.empty() ||
           mode == "auto" ||
           mode == "packet-up";
}

bool XHttpConfig::AcceptsStreamUp() const noexcept {
    return mode.empty() ||
           mode == "auto" ||
           mode == "stream-up";
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

void NormalizeInPlace(StreamSettings& settings) {
    // 仅初始化/配置更新时调用，热路径不再做字符串比较
    settings.network = naming::LowerAscii(std::move(settings.network));
    settings.security = naming::LowerAscii(std::move(settings.security));

    if (settings.network.empty() ||
        settings.network == constants::protocol::kTcp ||
        settings.network == constants::protocol::kRaw) {
        settings.network_mode = NetworkMode::Tcp;
    } else if (settings.network == constants::protocol::kWs ||
               settings.network == constants::protocol::kWebSocket) {
        settings.network_mode = NetworkMode::Ws;
    } else if (settings.network == constants::protocol::kHttpUpgrade) {
        settings.network_mode = NetworkMode::HttpUpgrade;
        settings.network = std::string(constants::protocol::kHttpUpgrade);
    } else if (settings.network == constants::protocol::kGrpc) {
        settings.network_mode = NetworkMode::Grpc;
    } else if (settings.network == constants::protocol::kHttp || settings.network == "h2") {
        settings.http.force_http2 = settings.http.force_http2 || (settings.network == "h2");
        settings.network_mode = NetworkMode::Http;
    } else if (settings.network == constants::protocol::kXHttp || settings.network == "splithttp") {
        settings.network_mode = NetworkMode::XHttp;
    } else {
        settings.network_mode = NetworkMode::Unsupported;
    }

    if (settings.security.empty() || settings.security == constants::protocol::kNone) {
        settings.security_mode = SecurityMode::None;
    } else if (settings.security == constants::protocol::kTls) {
        settings.security_mode = SecurityMode::Tls;
    } else if (settings.security == constants::protocol::kReality) {
        settings.security_mode = SecurityMode::Reality;
        settings.tls.min_version = TlsVersion::V1_3;
        settings.tls.max_version = TlsVersion::V1_3;
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
}

}  // namespace

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

}  // namespace acpp
