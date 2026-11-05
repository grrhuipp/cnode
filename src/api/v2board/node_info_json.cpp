#include "node_info_json.hpp"

#include "acppnode/common/target_address.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/json_field.hpp"
#include "acppnode/transport/internet/http_headers.hpp"
#include "acppnode/transport/internet/reality_client_version.hpp"
#include "acppnode/transport/internet/reality_key.hpp"
#include "acppnode/transport/internet/reality_server_name.hpp"
#include "acppnode/transport/internet/reality_short_id.hpp"

#include <format>
#include <limits>
#include <optional>
#include <utility>

namespace acpp::api::v2board {

namespace {

tl::expected<uint16_t, std::string> ParseServerPort(const json::object& source) {
    const auto result = ReadJsonPort(source, "server_port");
    switch (result.error) {
        case JsonPortError::None:
            return result.value;
        case JsonPortError::Missing:
            return tl::unexpected("server_port is required");
        case JsonPortError::InvalidType:
            return tl::unexpected("server_port must be an integer");
        case JsonPortError::OutOfRange:
            return tl::unexpected("server_port must be between 1 and 65535");
    }
    return tl::unexpected("server_port is invalid");
}

// 0 keeps the local default cadence; the bound keeps the value representable
// in NodeInfo and in steady_clock deadline arithmetic.
tl::expected<int, std::string> ParseReportInterval(
    const json::object& base, std::string_view field, int current) {
    const auto* raw = base.if_contains(field);
    if (!raw || raw->is_null()) {
        return current;
    }
    const auto seconds = JsonUnsignedInteger(*raw);
    if (!seconds || *seconds > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
        return tl::unexpected(std::format(
            "base_config.{} must be a non-negative integer number of seconds", field));
    }
    return static_cast<int>(*seconds);
}

}  // namespace

tl::expected<::acpp::api::NodeInfo, std::string> ParseNodeInfo(
    const json::object& source,
    std::string_view node_type) {
    auto port = ParseServerPort(source);
    if (!port) {
        return tl::unexpected(std::move(port.error()));
    }

    ::acpp::api::NodeInfo config;
    config.NodeType = std::string(node_type);
    config.Port = *port;

    if (const auto* network = source.if_contains("network");
        network && !network->is_null()) {
        if (!network->is_string()) {
            return tl::unexpected("network must be a string");
        }
        config.TransportProtocol = std::string(network->as_string());
    }

    if (const auto* network_settings = source.if_contains("networkSettings");
        network_settings && !network_settings->is_null()) {
        if (!network_settings->is_object()) {
            return tl::unexpected("networkSettings must be an object");
        }
        const auto& settings = network_settings->as_object();
        if (const auto* path = settings.if_contains("path")) {
            if (!path->is_string()) {
                return tl::unexpected(
                    "networkSettings path must be a string");
            }
            config.Path = std::string(path->as_string());
            if (!config.Path.empty() &&
                !transport::internet::IsValidHttpRequestTarget(config.Path)) {
                return tl::unexpected(
                    "networkSettings path must be a valid HTTP request target");
            }
        }
        if (const auto* service_name = settings.if_contains("serviceName")) {
            if (!service_name->is_string()) {
                return tl::unexpected(
                    "networkSettings serviceName must be a string");
            }
            config.ServiceName = std::string(service_name->as_string());
        }
        if (const auto* headers = settings.if_contains("headers")) {
            if (!headers->is_object()) {
                return tl::unexpected(
                    "networkSettings headers must be an object");
            }
            std::optional<std::string> host;
            for (const auto& [name, raw_value] : headers->as_object()) {
                if (transport::internet::NormalizeHttpHeaderName(name) != "host") {
                    continue;
                }
                if (!raw_value.is_string()) {
                    return tl::unexpected(
                        "networkSettings Host must be a string");
                }
                const std::string value(raw_value.as_string());
                if (!transport::internet::IsValidHttpHeaderValue(value)) {
                    return tl::unexpected(
                        "networkSettings Host contains invalid control characters");
                }
                if (!transport::internet::IsValidHttpAuthority(value)) {
                    return tl::unexpected(
                        "networkSettings Host must be a valid HTTP authority");
                }
                if (host && *host != value) {
                    return tl::unexpected(
                        "networkSettings Host aliases must match");
                }
                if (!host) {
                    host = value;
                }
            }
            config.Host = std::move(host).value_or("");
        }
    }

    if (const auto* tls = source.if_contains(constants::protocol::kTls);
        tls && !tls->is_null()) {
        // V2Board encodes 0 = none, 1 = TLS, 2 = REALITY; older panels send a
        // boolean. Any other value is ambiguous and rejects the node.
        if (tls->is_bool()) {
            config.EnableTLS = tls->as_bool();
        } else if (const auto mode = JsonUnsignedInteger(*tls); mode && *mode <= 2) {
            config.EnableTLS = (*mode == 1);
            config.EnableReality = (*mode == 2);
        } else {
            return tl::unexpected("tls must be 0, 1, 2 or a boolean");
        }
    }

    if (const auto* flow = source.if_contains("flow");
        flow && !flow->is_null()) {
        if (!flow->is_string()) {
            return tl::unexpected("flow must be a string");
        }
        config.Flow = std::string(flow->as_string());
    }

    if (const auto* server_name = source.if_contains("server_name");
        server_name && !server_name->is_null()) {
        if (!server_name->is_string()) {
            return tl::unexpected("server_name must be a string");
        }
        config.TLSServerName = std::string(server_name->as_string());
    }
    if (const auto* cipher = source.if_contains("cipher");
        cipher && !cipher->is_null()) {
        if (!cipher->is_string()) {
            return tl::unexpected("cipher must be a string");
        }
        config.CypherMethod = std::string(cipher->as_string());
    }
    if (const auto* server_key = source.if_contains("server_key");
        server_key && !server_key->is_null()) {
        if (!server_key->is_string()) {
            return tl::unexpected("server_key must be a string");
        }
        config.ShadowsocksServerKey = std::string(server_key->as_string());
    }

    if (config.EnableReality) {
        const auto* tls_settings_val = source.if_contains("tls_settings");
        if (!tls_settings_val) {
            tls_settings_val = source.if_contains("tlsSettings");
        }
        if (!tls_settings_val || !tls_settings_val->is_object()) {
            return tl::unexpected(
                "REALITY node requires tls_settings object");
        }
        const auto& rs = tls_settings_val->as_object();

        const auto* priv_val = rs.if_contains("private_key");
        if (!priv_val) {
            priv_val = rs.if_contains("privateKey");
        }
        if (!priv_val || !priv_val->is_string() || priv_val->as_string().empty()) {
            return tl::unexpected("REALITY tls_settings requires private_key");
        }
        const auto parsed_priv =
            transport::internet::ParseRealityKey(priv_val->as_string());
        if (!parsed_priv) {
            return tl::unexpected("REALITY private_key is invalid");
        }
        config.Reality.private_key = *parsed_priv;

        auto append_server_name = [&](std::string_view name) -> bool {
            if (!name.empty() &&
                !domain::IsValidDnsHostname(name, domain::TrailingDotPolicy::Forbid)) {
                return false;
            }
            config.Reality.server_names.emplace_back(name);
            return true;
        };
        if (const auto* sn_list = rs.if_contains("server_names")
                ? rs.if_contains("server_names")
                : rs.if_contains("serverNames")) {
            if (!sn_list->is_array()) {
                return tl::unexpected("REALITY server_names must be an array");
            }
            for (const auto& item : sn_list->as_array()) {
                if (!item.is_string() || !append_server_name(item.as_string())) {
                    return tl::unexpected("REALITY server_names contains an invalid hostname");
                }
            }
        } else if (const auto* sn = rs.if_contains("server_name")
                       ? rs.if_contains("server_name")
                       : rs.if_contains("serverName")) {
            if (!sn->is_string() || !append_server_name(sn->as_string())) {
                return tl::unexpected("REALITY server_name is invalid");
            }
        } else if (!config.TLSServerName.empty()) {
            if (!append_server_name(config.TLSServerName)) {
                return tl::unexpected("REALITY server_name is invalid");
            }
        }
        if (config.Reality.server_names.empty()) {
            return tl::unexpected("REALITY node requires server_name");
        }

        auto append_short_id = [&](std::string_view sid) -> bool {
            auto parsed = transport::internet::ParseRealityShortId(sid);
            if (!parsed) {
                return false;
            }
            config.Reality.short_ids.push_back(*parsed);
            return true;
        };
        if (const auto* sid_list = rs.if_contains("short_ids")
                ? rs.if_contains("short_ids")
                : rs.if_contains("shortIds")) {
            if (!sid_list->is_array()) {
                return tl::unexpected("REALITY short_ids must be an array");
            }
            for (const auto& item : sid_list->as_array()) {
                if (!item.is_string() || !append_short_id(item.as_string())) {
                    return tl::unexpected("REALITY short_ids contains an invalid value");
                }
            }
        } else if (const auto* sid = rs.if_contains("short_id")
                       ? rs.if_contains("short_id")
                       : rs.if_contains("shortId")) {
            if (sid->is_array()) {
                for (const auto& item : sid->as_array()) {
                    if (!item.is_string() || !append_short_id(item.as_string())) {
                        return tl::unexpected("REALITY short_id contains an invalid value");
                    }
                }
            } else if (sid->is_string()) {
                if (!append_short_id(sid->as_string())) {
                    return tl::unexpected("REALITY short_id is invalid");
                }
            } else if (!sid->is_null()) {
                return tl::unexpected("REALITY short_id must be a string or array");
            }
        }
        if (config.Reality.short_ids.empty()) {
            config.Reality.short_ids.push_back(transport::internet::RealityShortId{});
        }

        if (const auto* dest_val = rs.if_contains("dest")) {
            if (!dest_val->is_string() || dest_val->as_string().empty()) {
                return tl::unexpected("REALITY dest must be a non-empty string");
            }
            const auto parsed_dest = TargetAddress::Parse(dest_val->as_string());
            if (!parsed_dest) {
                return tl::unexpected("REALITY dest is invalid");
            }
            config.Reality.dest_host = parsed_dest->IsIP()
                ? iputil::NormalizeAddressString(*parsed_dest->resolved_addr)
                : std::string(parsed_dest->host);
            config.Reality.dest_port = parsed_dest->port;
        } else if (rs.contains("server_port")) {
            const auto dest_port = ReadJsonPort(rs, "server_port");
            if (dest_port.error != JsonPortError::None) {
                return tl::unexpected("REALITY tls_settings.server_port is invalid");
            }
            const std::string& fallback_host = config.Reality.server_names.front();
            if (!fallback_host.empty()) {
                config.Reality.dest_host = fallback_host;
                config.Reality.dest_port = dest_port.value;
            }
        }

        if (const auto* xver_val = rs.if_contains("xver");
            xver_val && !xver_val->is_null()) {
            const auto xver = JsonUnsignedInteger(*xver_val);
            if (!xver) {
                return tl::unexpected("REALITY xver must be an integer between 0 and 2");
            }
            if (*xver > 2) {
                return tl::unexpected("REALITY xver must be between 0 and 2");
            }
            config.Reality.xver = static_cast<uint8_t>(*xver);
            if (config.Reality.xver != 0 && !config.Reality.HasDest()) {
                return tl::unexpected("REALITY xver requires dest");
            }
        }

        if (const auto* mldsa_val = rs.if_contains("mldsa65_seed")
                ? rs.if_contains("mldsa65_seed")
                : rs.if_contains("mldsa65Seed");
            mldsa_val && !mldsa_val->is_null()) {
            if (!mldsa_val->is_string() || mldsa_val->as_string().empty()) {
                return tl::unexpected("REALITY mldsa65_seed must be a non-empty string");
            }
            auto parsed_seed =
                transport::internet::ParseRealityMldsa65Seed(mldsa_val->as_string());
            if (!parsed_seed) {
                return tl::unexpected("REALITY mldsa65_seed is invalid");
            }
            config.Reality.mldsa65_seed = *parsed_seed;
        }

        if (const auto* min_ver_val = rs.if_contains("min_client_ver")
                ? rs.if_contains("min_client_ver")
                : rs.if_contains("minClientVer");
            min_ver_val && !min_ver_val->is_null()) {
            if (!min_ver_val->is_string()) {
                return tl::unexpected("REALITY min_client_ver must be a string");
            }
            const auto parsed_min =
                transport::internet::ParseRealityClientVersion(min_ver_val->as_string());
            if (!parsed_min) {
                return tl::unexpected("REALITY min_client_ver is invalid");
            }
            config.Reality.min_client_version = *parsed_min;
        }

        if (const auto* max_ver_val = rs.if_contains("max_client_ver")
                ? rs.if_contains("max_client_ver")
                : rs.if_contains("maxClientVer");
            max_ver_val && !max_ver_val->is_null()) {
            if (!max_ver_val->is_string()) {
                return tl::unexpected("REALITY max_client_ver must be a string");
            }
            const auto parsed_max =
                transport::internet::ParseRealityClientVersion(max_ver_val->as_string());
            if (!parsed_max) {
                return tl::unexpected("REALITY max_client_ver is invalid");
            }
            config.Reality.max_client_version = *parsed_max;
        }

        if (config.Reality.min_client_version && config.Reality.max_client_version &&
            transport::internet::RealityClientVersionValue(*config.Reality.min_client_version) >
                transport::internet::RealityClientVersionValue(*config.Reality.max_client_version)) {
            return tl::unexpected("REALITY min_client_ver must not exceed max_client_ver");
        }

        if (const auto* max_time_val = rs.if_contains("max_time_diff")
                ? rs.if_contains("max_time_diff")
                : rs.if_contains("maxTimeDiff");
            max_time_val && !max_time_val->is_null()) {
            const auto max_time_diff = JsonUnsignedInteger(*max_time_val);
            if (!max_time_diff) {
                return tl::unexpected(
                    "REALITY max_time_diff must be a non-negative integer");
            }
            config.Reality.max_time_diff = *max_time_diff;
        }
    }
    if (const auto* base_config = source.if_contains("base_config");
        base_config && !base_config->is_null()) {
        if (!base_config->is_object()) {
            return tl::unexpected("base_config must be an object");
        }
        const auto& base = base_config->as_object();
        auto pull = ParseReportInterval(base, "pull_interval", config.PullInterval);
        if (!pull) {
            return tl::unexpected(std::move(pull.error()));
        }
        auto push = ParseReportInterval(base, "push_interval", config.PushInterval);
        if (!push) {
            return tl::unexpected(std::move(push.error()));
        }
        config.PullInterval = *pull;
        config.PushInterval = *push;
    }

    return config;
}

}  // namespace acpp::api::v2board
