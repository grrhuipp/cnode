#include "node_info_json.hpp"

#include "acppnode/common/target_address.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/infra/json_port.hpp"
#include "acppnode/transport/internet/http_headers.hpp"
#include "acppnode/transport/internet/reality_client_version.hpp"
#include "acppnode/transport/internet/reality_key.hpp"
#include "acppnode/transport/internet/reality_server_name.hpp"
#include "acppnode/transport/internet/reality_short_id.hpp"

#include <limits>
#include <optional>
#include <utility>

namespace acpp::api::v2board {

namespace {

std::expected<uint16_t, std::string> ParseServerPort(const json::object& source) {
    const auto result = ReadJsonPort(source, "server_port");
    switch (result.error) {
        case JsonPortError::None:
            return result.value;
        case JsonPortError::Missing:
            return std::unexpected("server_port is required");
        case JsonPortError::InvalidType:
            return std::unexpected("server_port must be an integer");
        case JsonPortError::OutOfRange:
            return std::unexpected("server_port must be between 1 and 65535");
    }
    return std::unexpected("server_port is invalid");
}

}  // namespace

std::expected<::acpp::api::NodeInfo, std::string> ParseNodeInfo(
    const json::object& source,
    int node_id,
    std::string_view node_type) {
    auto port = ParseServerPort(source);
    if (!port) {
        return std::unexpected(std::move(port.error()));
    }

    ::acpp::api::NodeInfo config;
    config.NodeID = node_id;
    config.NodeType = std::string(node_type);
    config.Port = *port;

    if (const auto* network = source.if_contains("network");
        network && network->is_string()) {
        config.TransportProtocol = std::string(network->as_string());
    }

    if (const auto* network_settings = source.if_contains("networkSettings");
        network_settings && network_settings->is_object()) {
        const auto& settings = network_settings->as_object();
        if (const auto* path = settings.if_contains("path")) {
            if (!path->is_string()) {
                return std::unexpected(
                    "networkSettings path must be a string");
            }
            config.Path = std::string(path->as_string());
            if (!config.Path.empty() &&
                !transport::internet::IsValidHttpRequestTarget(config.Path)) {
                return std::unexpected(
                    "networkSettings path must be a valid HTTP request target");
            }
        }
        if (const auto* service_name = settings.if_contains("serviceName")) {
            if (!service_name->is_string()) {
                return std::unexpected(
                    "networkSettings serviceName must be a string");
            }
            config.ServiceName = std::string(service_name->as_string());
        }
        if (const auto* headers = settings.if_contains("headers")) {
            if (!headers->is_object()) {
                return std::unexpected(
                    "networkSettings headers must be an object");
            }
            std::optional<std::string> host;
            for (const auto& [name, raw_value] : headers->as_object()) {
                if (transport::internet::NormalizeHttpHeaderName(name) != "host") {
                    continue;
                }
                if (!raw_value.is_string()) {
                    return std::unexpected(
                        "networkSettings Host must be a string");
                }
                const std::string value(raw_value.as_string());
                if (!transport::internet::IsValidHttpHeaderValue(value)) {
                    return std::unexpected(
                        "networkSettings Host contains invalid control characters");
                }
                if (!transport::internet::IsValidHttpAuthority(value)) {
                    return std::unexpected(
                        "networkSettings Host must be a valid HTTP authority");
                }
                if (host && *host != value) {
                    return std::unexpected(
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
        if (tls->is_int64()) {
            const auto mode = tls->as_int64();
            config.EnableTLS = (mode == 1);
            config.EnableReality = (mode == 2);
        } else if (tls->is_uint64()) {
            const auto mode = tls->as_uint64();
            config.EnableTLS = (mode == 1);
            config.EnableReality = (mode == 2);
        } else if (tls->is_bool()) {
            config.EnableTLS = tls->as_bool();
        }
    }

    if (const auto* flow = source.if_contains("flow");
        flow && !flow->is_null()) {
        if (!flow->is_string()) {
            return std::unexpected("flow must be a string");
        }
        config.Flow = std::string(flow->as_string());
    }

    if (const auto* server_name = source.if_contains("server_name");
        server_name && server_name->is_string()) {
        config.TLSServerName = std::string(server_name->as_string());
    }
    if (const auto* cipher = source.if_contains("cipher");
        cipher && cipher->is_string()) {
        config.CypherMethod = std::string(cipher->as_string());
    }
    if (const auto* server_key = source.if_contains("server_key");
        server_key && server_key->is_string()) {
        config.ShadowsocksServerKey = std::string(server_key->as_string());
    }

    if (config.EnableReality) {
        const auto* tls_settings_val = source.if_contains("tls_settings");
        if (!tls_settings_val) {
            tls_settings_val = source.if_contains("tlsSettings");
        }
        if (!tls_settings_val || !tls_settings_val->is_object()) {
            return std::unexpected(
                "REALITY node requires tls_settings object");
        }
        const auto& rs = tls_settings_val->as_object();

        const auto* priv_val = rs.if_contains("private_key");
        if (!priv_val) {
            priv_val = rs.if_contains("privateKey");
        }
        if (!priv_val || !priv_val->is_string() || priv_val->as_string().empty()) {
            return std::unexpected("REALITY tls_settings requires private_key");
        }
        const auto parsed_priv =
            transport::internet::ParseRealityKey(priv_val->as_string());
        if (!parsed_priv) {
            return std::unexpected("REALITY private_key is invalid");
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
                return std::unexpected("REALITY server_names must be an array");
            }
            for (const auto& item : sn_list->as_array()) {
                if (!item.is_string() || !append_server_name(item.as_string())) {
                    return std::unexpected("REALITY server_names contains an invalid hostname");
                }
            }
        } else if (const auto* sn = rs.if_contains("server_name")
                       ? rs.if_contains("server_name")
                       : rs.if_contains("serverName")) {
            if (!sn->is_string() || !append_server_name(sn->as_string())) {
                return std::unexpected("REALITY server_name is invalid");
            }
        } else if (!config.TLSServerName.empty()) {
            if (!append_server_name(config.TLSServerName)) {
                return std::unexpected("REALITY server_name is invalid");
            }
        }
        if (config.Reality.server_names.empty()) {
            return std::unexpected("REALITY node requires server_name");
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
                return std::unexpected("REALITY short_ids must be an array");
            }
            for (const auto& item : sid_list->as_array()) {
                if (!item.is_string() || !append_short_id(item.as_string())) {
                    return std::unexpected("REALITY short_ids contains an invalid value");
                }
            }
        } else if (const auto* sid = rs.if_contains("short_id")
                       ? rs.if_contains("short_id")
                       : rs.if_contains("shortId")) {
            if (sid->is_array()) {
                for (const auto& item : sid->as_array()) {
                    if (!item.is_string() || !append_short_id(item.as_string())) {
                        return std::unexpected("REALITY short_id contains an invalid value");
                    }
                }
            } else if (sid->is_string()) {
                if (!append_short_id(sid->as_string())) {
                    return std::unexpected("REALITY short_id is invalid");
                }
            } else if (!sid->is_null()) {
                return std::unexpected("REALITY short_id must be a string or array");
            }
        }
        if (config.Reality.short_ids.empty()) {
            config.Reality.short_ids.push_back(transport::internet::RealityShortId{});
        }

        if (const auto* dest_val = rs.if_contains("dest")) {
            if (!dest_val->is_string() || dest_val->as_string().empty()) {
                return std::unexpected("REALITY dest must be a non-empty string");
            }
            const auto parsed_dest = TargetAddress::Parse(dest_val->as_string());
            if (!parsed_dest) {
                return std::unexpected("REALITY dest is invalid");
            }
            config.Reality.dest_host = parsed_dest->IsIP()
                ? iputil::NormalizeAddressString(*parsed_dest->resolved_addr)
                : std::string(parsed_dest->host);
            config.Reality.dest_port = parsed_dest->port;
        } else if (rs.contains("server_port")) {
            const auto dest_port = ReadJsonPort(rs, "server_port");
            if (dest_port.error != JsonPortError::None) {
                return std::unexpected("REALITY tls_settings.server_port is invalid");
            }
            const std::string& fallback_host = config.Reality.server_names.front();
            if (!fallback_host.empty()) {
                config.Reality.dest_host = fallback_host;
                config.Reality.dest_port = dest_port.value;
            }
        }

        if (const auto* xver_val = rs.if_contains("xver");
            xver_val && !xver_val->is_null()) {
            uint64_t xver = 0;
            if (xver_val->is_int64() && xver_val->as_int64() >= 0) {
                xver = static_cast<uint64_t>(xver_val->as_int64());
            } else if (xver_val->is_uint64()) {
                xver = xver_val->as_uint64();
            } else {
                return std::unexpected("REALITY xver must be an integer between 0 and 2");
            }
            if (xver > 2) {
                return std::unexpected("REALITY xver must be between 0 and 2");
            }
            config.Reality.xver = static_cast<uint8_t>(xver);
            if (config.Reality.xver != 0 && !config.Reality.HasDest()) {
                return std::unexpected("REALITY xver requires dest");
            }
        }

        if (const auto* mldsa_val = rs.if_contains("mldsa65_seed")
                ? rs.if_contains("mldsa65_seed")
                : rs.if_contains("mldsa65Seed");
            mldsa_val && !mldsa_val->is_null()) {
            if (!mldsa_val->is_string() || mldsa_val->as_string().empty()) {
                return std::unexpected("REALITY mldsa65_seed must be a non-empty string");
            }
            auto parsed_seed =
                transport::internet::ParseRealityMldsa65Seed(mldsa_val->as_string());
            if (!parsed_seed) {
                return std::unexpected("REALITY mldsa65_seed is invalid");
            }
            config.Reality.mldsa65_seed = *parsed_seed;
        }

        if (const auto* min_ver_val = rs.if_contains("min_client_ver")
                ? rs.if_contains("min_client_ver")
                : rs.if_contains("minClientVer");
            min_ver_val && !min_ver_val->is_null()) {
            if (!min_ver_val->is_string()) {
                return std::unexpected("REALITY min_client_ver must be a string");
            }
            const auto parsed_min =
                transport::internet::ParseRealityClientVersion(min_ver_val->as_string());
            if (!parsed_min) {
                return std::unexpected("REALITY min_client_ver is invalid");
            }
            config.Reality.min_client_version = *parsed_min;
        }

        if (const auto* max_ver_val = rs.if_contains("max_client_ver")
                ? rs.if_contains("max_client_ver")
                : rs.if_contains("maxClientVer");
            max_ver_val && !max_ver_val->is_null()) {
            if (!max_ver_val->is_string()) {
                return std::unexpected("REALITY max_client_ver must be a string");
            }
            const auto parsed_max =
                transport::internet::ParseRealityClientVersion(max_ver_val->as_string());
            if (!parsed_max) {
                return std::unexpected("REALITY max_client_ver is invalid");
            }
            config.Reality.max_client_version = *parsed_max;
        }

        if (config.Reality.min_client_version && config.Reality.max_client_version &&
            transport::internet::RealityClientVersionValue(*config.Reality.min_client_version) >
                transport::internet::RealityClientVersionValue(*config.Reality.max_client_version)) {
            return std::unexpected("REALITY min_client_ver must not exceed max_client_ver");
        }

        if (const auto* max_time_val = rs.if_contains("max_time_diff")
                ? rs.if_contains("max_time_diff")
                : rs.if_contains("maxTimeDiff");
            max_time_val && !max_time_val->is_null()) {
            if (max_time_val->is_int64() && max_time_val->as_int64() >= 0) {
                config.Reality.max_time_diff =
                    static_cast<uint64_t>(max_time_val->as_int64());
            } else if (max_time_val->is_uint64()) {
                config.Reality.max_time_diff = max_time_val->as_uint64();
            } else {
                return std::unexpected(
                    "REALITY max_time_diff must be a non-negative integer");
            }
        }
    }
    if (const auto* base_config = source.if_contains("base_config");
        base_config && base_config->is_object()) {
        const auto& base = base_config->as_object();
        if (const auto* pull = base.if_contains("pull_interval");
            pull && pull->is_int64()) {
            config.PullInterval = static_cast<int>(pull->as_int64());
        }
        if (const auto* push = base.if_contains("push_interval");
            push && push->is_int64()) {
            config.PushInterval = static_cast<int>(push->as_int64());
        }
    }

    return config;
}

}  // namespace acpp::api::v2board
