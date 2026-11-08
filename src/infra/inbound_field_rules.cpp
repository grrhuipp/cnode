#include "infra/inbound_field_rules.hpp"

#include "common/domain_name.hpp"
#include "common/ip_utils.hpp"
#include "common/target_address.hpp"
#include "core/constants.hpp"
#include "core/naming.hpp"
#include "proxy/sniff_config.hpp"
#include "transport/internet/http_headers.hpp"
#include "transport/internet/reality_client_version.hpp"
#include "transport/internet/reality_key.hpp"
#include "transport/internet/reality_short_id.hpp"
#include "../proxy/anytls/anytls_codec.hpp"
#include "../proxy/anytls/padding.hpp"

#include <format>

namespace infra {

bool IsValidRealityServerName(std::string_view name) noexcept {
    return !name.empty() && !iputil::ParseLiteral(name) &&
           domain::IsValidDnsHostname(name, domain::TrailingDotPolicy::Forbid);
}

tl::expected<void, std::string> ApplyRealityServerInput(
    const RealityServerInput& input, RealityConfig& out) {
    if (input.private_key) {
        if (input.private_key->empty()) {
            return tl::unexpected("REALITY privateKey must not be empty");
        }
        auto parsed = transport::internet::ParseRealityKey(*input.private_key);
        if (!parsed) {
            return tl::unexpected("REALITY privateKey is invalid");
        }
        out.private_key = *parsed;
    }

    std::vector<std::string> server_names;
    server_names.reserve(input.server_names.size());
    for (const auto& name : input.server_names) {
        // An empty entry explicitly permits a REALITY ClientHello without SNI.
        if (!name.empty() && !IsValidRealityServerName(name)) {
            return tl::unexpected(
                "REALITY serverNames contains an invalid hostname");
        }
        server_names.push_back(naming::LowerAscii(name));
    }

    std::vector<transport::internet::RealityShortId> short_ids;
    short_ids.reserve(input.short_ids.size());
    for (const auto& short_id : input.short_ids) {
        auto parsed = transport::internet::ParseRealityShortId(short_id);
        if (!parsed) {
            return tl::unexpected("REALITY shortIds contains an invalid value");
        }
        short_ids.push_back(*parsed);
    }

    std::string dest_host;
    uint16_t dest_port = 0;
    if (input.dest) {
        const auto parsed = TargetAddress::Parse(*input.dest);
        if (!parsed) {
            return tl::unexpected("REALITY dest is invalid");
        }
        dest_host = parsed->IsIP()
            ? iputil::NormalizeAddressString(*parsed->resolved_addr)
            : std::string(parsed->host);
        dest_port = parsed->port;
    }

    if (input.xver > 2) {
        return tl::unexpected("REALITY xver must be between 0 and 2");
    }
    if (input.xver != 0 && (dest_host.empty() || dest_port == 0)) {
        return tl::unexpected(
            "REALITY xver 1 and 2 require dest for PROXY protocol forwarding");
    }

    std::optional<transport::internet::RealityKey> mldsa65_seed;
    if (input.mldsa65_seed) {
        auto parsed =
            transport::internet::ParseRealityMldsa65Seed(*input.mldsa65_seed);
        if (input.mldsa65_seed->empty() || !parsed) {
            return tl::unexpected("REALITY mldsa65Seed is invalid");
        }
        mldsa65_seed = *parsed;
    }

    const auto min_client_version =
        transport::internet::ParseRealityClientVersion(input.min_client_ver);
    if (!min_client_version) {
        return tl::unexpected("REALITY minClientVer is invalid");
    }
    const auto max_client_version =
        transport::internet::ParseRealityClientVersion(input.max_client_ver);
    if (!max_client_version) {
        return tl::unexpected("REALITY maxClientVer is invalid");
    }
    if (*min_client_version && *max_client_version &&
        transport::internet::RealityClientVersionValue(**min_client_version) >
            transport::internet::RealityClientVersionValue(**max_client_version)) {
        return tl::unexpected(
            "REALITY minClientVer must not exceed maxClientVer");
    }

    out.server_names = std::move(server_names);
    out.short_ids = std::move(short_ids);
    out.dest_host = std::move(dest_host);
    out.dest_port = dest_port;
    out.xver = static_cast<uint8_t>(input.xver);
    if (mldsa65_seed) {
        out.mldsa65_seed = *mldsa65_seed;
    }
    out.min_client_version = *min_client_version;
    out.max_client_version = *max_client_version;
    out.max_time_diff = input.max_time_diff;
    return {};
}

tl::expected<void, std::string> ValidateInboundReality(
    const RealityConfig& config) {
    if (!config.private_key) {
        return tl::unexpected("inbound REALITY requires privateKey");
    }
    if (config.server_names.empty()) {
        return tl::unexpected(
            "inbound REALITY requires at least one serverName");
    }
    if (config.short_ids.empty()) {
        return tl::unexpected("inbound REALITY requires at least one shortId");
    }
    return {};
}

tl::expected<std::string, std::string> NormalizeTlsServerName(
    std::string_view value, std::string_view field) {
    if (value.empty()) {
        return std::string{};
    }
    if (!iputil::ParseLiteral(value) &&
        !domain::IsValidDnsHostname(value, domain::TrailingDotPolicy::Forbid)) {
        return tl::unexpected(std::format(
            "{} must be an IP address or DNS hostname", field));
    }
    return naming::LowerAscii(std::string(value));
}

tl::expected<std::string, std::string> NormalizeTransportPath(
    std::string_view value, std::string_view field) {
    if (value.empty()) {
        return std::string(constants::binding::kRootPath);
    }
    if (!transport::internet::IsValidHttpRequestTarget(value)) {
        return tl::unexpected(std::format(
            "{} must be a valid HTTP request target", field));
    }
    return std::string(value);
}

tl::expected<std::string, std::string> NormalizeHttpAuthority(
    std::string_view value, std::string_view field) {
    if (value.empty()) {
        return std::string{};
    }
    if (!transport::internet::IsValidHttpAuthority(value)) {
        return tl::unexpected(std::format(
            "{} must be a valid HTTP authority", field));
    }
    return naming::LowerAscii(std::string(value));
}

tl::expected<void, std::string> ValidateGrpcServiceName(
    std::string_view value, std::string_view field) {
    for (const unsigned char ch : value) {
        if (ch <= 0x20 || ch == 0x7f || ch == '#') {
            return tl::unexpected(std::format(
                "{} contains invalid characters", field));
        }
    }
    GrpcConfig probe;
    probe.service_name = std::string(value);
    if (!transport::internet::IsValidHttpRequestTarget(probe.RequestPath())) {
        return tl::unexpected(std::format(
            "{} path must be a valid HTTP request target", field));
    }
    return {};
}

tl::expected<uint8_t, std::string> ParseSniffDestOverride(
    std::span<const std::string> protocols) {
    uint8_t bits = 0;
    for (const auto& raw : protocols) {
        const std::string protocol = naming::LowerAscii(raw);
        if (protocol == "fakedns" || protocol == "fakedns+others") {
            return tl::unexpected(
                "sniffing destOverride fakedns is not supported");
        }
        const uint8_t bit = SniffConfig::DestOverrideBit(protocol);
        if (bit == 0) {
            return tl::unexpected(std::format(
                "sniffing destOverride contains unsupported value '{}'",
                protocol));
        }
        bits |= bit;
    }
    return bits;
}

tl::expected<std::string, std::string> ParseAnyTlsPaddingScheme(
    const json::value& value, std::string_view field) {
    std::string scheme;
    if (value.is_null()) {
        return scheme;
    }
    if (value.is_string()) {
        scheme = std::string(value.as_string());
    } else if (value.is_array()) {
        bool first = true;
        for (const auto& item : value.as_array()) {
            if (!item.is_string()) {
                return tl::unexpected(std::format(
                    "{} must contain only strings", field));
            }
            if (!first) {
                scheme.push_back('\n');
            }
            scheme.append(item.as_string());
            first = false;
        }
    } else {
        return tl::unexpected(std::format(
            "{} must be a string, array of strings, or null", field));
    }
    if (scheme.empty()) {
        return scheme;
    }
    // The advertised raw scheme must fit in one UpdatePaddingScheme frame.
    if (scheme.size() > anytls::kMaxFramePayload) {
        return tl::unexpected(std::format(
            "{} exceeds {} bytes", field, anytls::kMaxFramePayload));
    }
    if (!anytls::ParsePaddingScheme(scheme)) {
        return tl::unexpected(std::format("{} is invalid", field));
    }
    return scheme;
}

}  // namespace infra
