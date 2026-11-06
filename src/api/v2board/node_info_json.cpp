#include "node_info_json.hpp"

#include "acppnode/common/target_address.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/json_field.hpp"
#include "acppnode/transport/internet/http_headers.hpp"
#include "acppnode/transport/internet/reality_client_version.hpp"
#include "acppnode/transport/internet/reality_key.hpp"
#include "acppnode/transport/internet/reality_short_id.hpp"
#include "panel_json_compat.hpp"

#include <format>
#include <limits>
#include <optional>
#include <utility>

namespace acpp::api::v2board {

namespace {

tl::expected<uint16_t, std::string> ParseServerPort(const json::object& source) {
    const auto* raw = source.if_contains("server_port");
    if (!raw || raw->is_null()) {
        return tl::unexpected("server_port is required");
    }
    const auto result = PanelUnsignedInteger(*raw);
    if (!result) {
        return tl::unexpected(
            "server_port must be an integer or decimal integer string");
    }
    if (*result == 0 || *result > std::numeric_limits<uint16_t>::max()) {
        return tl::unexpected("server_port must be between 1 and 65535");
    }
    return static_cast<uint16_t>(*result);
}

// 0 keeps the local default cadence; the bound keeps the value representable
// in NodeInfo and in steady_clock deadline arithmetic.
tl::expected<int, std::string> ParseReportInterval(
    const json::object& base, std::string_view field, int current) {
    const auto* raw = base.if_contains(field);
    if (!raw || raw->is_null()) {
        return current;
    }
    const auto seconds = PanelUnsignedInteger(*raw);
    if (!seconds || *seconds > static_cast<uint64_t>(std::numeric_limits<int>::max())) {
        return tl::unexpected(std::format(
            "base_config.{} must be a non-negative integer number of seconds", field));
    }
    return static_cast<int>(*seconds);
}

tl::expected<const json::value*, std::string> ResolveAlias(
    const json::object& obj,
    std::string_view primary,
    std::string_view secondary,
    std::string_view context) {
    const auto* primary_val = obj.if_contains(primary);
    if (primary_val && primary_val->is_null()) {
        primary_val = nullptr;
    }
    const auto* secondary_val = obj.if_contains(secondary);
    if (secondary_val && secondary_val->is_null()) {
        secondary_val = nullptr;
    }
    if (primary_val && secondary_val &&
        json::serialize(*primary_val) != json::serialize(*secondary_val)) {
        return tl::unexpected(std::format(
            "{} aliases '{}' and '{}' must match", context, primary, secondary));
    }
    return primary_val ? primary_val : secondary_val;
}

tl::expected<uint32_t, std::string> ParseRequiredPanelUint32(
    const json::object& source,
    std::string_view field) {
    const auto* raw = source.if_contains(field);
    if (!raw || raw->is_null()) {
        return tl::unexpected(std::format("{} is required", field));
    }
    const auto value = PanelUnsignedInteger(*raw);
    if (!value || *value > std::numeric_limits<uint32_t>::max()) {
        return tl::unexpected(std::format(
            "{} must be a non-negative 32-bit integer or decimal integer string",
            field));
    }
    return static_cast<uint32_t>(*value);
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
    config.NodeType = naming::LowerAscii(std::string(node_type));
    config.Port = *port;

    if (const auto* network = source.if_contains("network");
        network && !network->is_null()) {
        if (!network->is_string()) {
            return tl::unexpected("network must be a string");
        }
        config.TransportProtocol =
            naming::LowerAscii(std::string(network->as_string()));
    }

    if (const auto* network_settings = source.if_contains("networkSettings");
        network_settings && !network_settings->is_null() &&
        !IsPanelEmptyObject(*network_settings)) {
        if (!network_settings->is_object()) {
            return tl::unexpected("networkSettings must be an object");
        }
        const auto& settings = network_settings->as_object();
        if (const auto* path = settings.if_contains("path");
            path && !path->is_null()) {
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
        if (const auto* service_name = settings.if_contains("serviceName");
            service_name && !service_name->is_null()) {
            if (!service_name->is_string()) {
                return tl::unexpected(
                    "networkSettings serviceName must be a string");
            }
            config.ServiceName = std::string(service_name->as_string());
            for (const unsigned char ch : config.ServiceName) {
                if (ch <= 0x20 || ch == 0x7f || ch == '#') {
                    return tl::unexpected(
                        "networkSettings serviceName contains invalid characters");
                }
            }
        }
        if (const auto* headers = settings.if_contains("headers");
            headers && !headers->is_null() && !IsPanelEmptyObject(*headers)) {
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
            config.Host = naming::LowerAscii(std::move(host).value_or(""));
        }
    }

    if (const auto* tls = source.if_contains(constants::protocol::kTls);
        tls && !tls->is_null()) {
        // V2Board encodes 0 = none, 1 = TLS, 2 = REALITY; older panels send a
        // boolean. Any other value is ambiguous and rejects the node.
        if (const auto mode = PanelBoolean(*tls)) {
            config.EnableTLS = *mode;
        } else if (const auto mode = PanelUnsignedInteger(*tls); mode && *mode <= 2) {
            config.EnableTLS = (*mode == 1);
            config.EnableReality = (*mode == 2);
        } else {
            return tl::unexpected(
                "tls must be a boolean or integer 0, 1, or 2");
        }
    }

    if (const auto* flow = source.if_contains("flow");
        flow && !flow->is_null()) {
        if (!flow->is_string()) {
            return tl::unexpected("flow must be a string");
        }
        config.Flow = naming::LowerAscii(std::string(flow->as_string()));
    }

    if (const auto* server_name = source.if_contains("server_name");
        server_name && !server_name->is_null()) {
        if (!server_name->is_string()) {
            return tl::unexpected("server_name must be a string");
        }
        config.TLSServerName =
            naming::LowerAscii(std::string(server_name->as_string()));
    }
    if (const auto* cipher = source.if_contains("cipher");
        cipher && !cipher->is_null()) {
        if (!cipher->is_string()) {
            return tl::unexpected("cipher must be a string");
        }
        config.CypherMethod =
            naming::LowerAscii(std::string(cipher->as_string()));
    }
    if (const auto* server_key = source.if_contains("server_key");
        server_key && !server_key->is_null()) {
        if (!server_key->is_string()) {
            return tl::unexpected("server_key must be a string");
        }
        config.ShadowsocksServerKey = std::string(server_key->as_string());
    }
    if (const auto* host = source.if_contains("host");
        host && !host->is_null() && !host->is_string()) {
        return tl::unexpected("host must be a string");
    }

    if (config.NodeType == constants::protocol::kShadowsocks) {
        if (const auto* obfs = source.if_contains("obfs");
            obfs && !obfs->is_null()) {
            if (!obfs->is_string()) {
                return tl::unexpected("obfs must be a string or null");
            }
            const std::string mode =
                naming::LowerAscii(std::string(obfs->as_string()));
            if (!mode.empty() && mode != constants::protocol::kNone) {
                return tl::unexpected(
                    "Shadowsocks obfs is not supported by this runtime");
            }
        }
        if (const auto* settings = source.if_contains("obfs_settings");
            settings && !settings->is_null() && !settings->is_object() &&
            !IsPanelEmptyObject(*settings)) {
            return tl::unexpected("obfs_settings must be an object or null");
        }
    }

    if (config.NodeType == constants::protocol::kVless) {
        if (const auto* encryption = source.if_contains("encryption");
            encryption && !encryption->is_null()) {
            if (!encryption->is_string()) {
                return tl::unexpected("encryption must be a string or null");
            }
            const std::string mode =
                naming::LowerAscii(std::string(encryption->as_string()));
            if (!mode.empty() && mode != constants::protocol::kNone) {
                return tl::unexpected(
                    "panel VLESS encryption is not supported by this runtime");
            }
        }
        if (const auto* settings = source.if_contains("encryption_settings");
            settings && !settings->is_null() && !settings->is_object() &&
            !IsPanelEmptyObject(*settings)) {
            return tl::unexpected(
                "encryption_settings must be an object or null");
        }
        if (const auto* settings = source.if_contains("tls_settings");
            settings && !settings->is_null() && !settings->is_object() &&
            !IsPanelEmptyObject(*settings)) {
            return tl::unexpected("tls_settings must be an object or null");
        }
    }

    if (config.NodeType == constants::protocol::kAnyTLS) {
        if (const auto* padding = source.if_contains("padding_scheme");
            padding && !padding->is_null()) {
            if (padding->is_string()) {
                config.PaddingScheme = std::string(padding->as_string());
            } else if (padding->is_array()) {
                bool first = true;
                for (const auto& item : padding->as_array()) {
                    if (!item.is_string()) {
                        return tl::unexpected(
                            "padding_scheme must contain only strings");
                    }
                    if (!first) {
                        config.PaddingScheme.push_back('\n');
                    }
                    config.PaddingScheme.append(item.as_string());
                    first = false;
                }
            } else {
                return tl::unexpected(
                    "padding_scheme must be a string, array of strings, or null");
            }
        }
    }

    if (config.NodeType == constants::protocol::kHysteria ||
        config.NodeType == constants::protocol::kHysteria2) {
        auto version = ParseRequiredPanelUint32(source, "version");
        if (!version || (*version != 1 && *version != 2)) {
            return tl::unexpected(
                version ? "version must be 1 or 2" : std::move(version.error()));
        }
        config.NodeType = *version == 1
            ? std::string(constants::protocol::kHysteria)
            : std::string(constants::protocol::kHysteria2);

        auto up_mbps = ParseRequiredPanelUint32(source, "up_mbps");
        if (!up_mbps) {
            return tl::unexpected(std::move(up_mbps.error()));
        }
        auto down_mbps = ParseRequiredPanelUint32(source, "down_mbps");
        if (!down_mbps) {
            return tl::unexpected(std::move(down_mbps.error()));
        }
        config.HysteriaUpMbps = *up_mbps;
        config.HysteriaDownMbps = *down_mbps;

        if (const auto* ignored = source.if_contains("ignore_client_bandwidth");
            ignored && !ignored->is_null() && !PanelBoolean(*ignored)) {
            return tl::unexpected(
                "ignore_client_bandwidth must be a boolean or 0/1");
        }

        for (const std::string_view field : {"obfs", "obfs-password"}) {
            const auto* value = source.if_contains(field);
            if (!value || value->is_null()) {
                continue;
            }
            if (!value->is_string()) {
                return tl::unexpected(std::format(
                    "{} must be a string or null", field));
            }
            if (!value->as_string().empty()) {
                return tl::unexpected(
                    "Hysteria obfs is not supported by this runtime");
            }
        }
    }


    if (config.EnableReality) {
        const auto tls_settings_res =
            ResolveAlias(source, "tls_settings", "tlsSettings", "REALITY");
        if (!tls_settings_res) {
            return tl::unexpected(std::move(tls_settings_res.error()));
        }
        const auto* tls_settings_val = *tls_settings_res;
        if (!tls_settings_val || !tls_settings_val->is_object()) {
            return tl::unexpected(
                "REALITY node requires tls_settings object");
        }
        const auto& rs = tls_settings_val->as_object();

        const auto priv_res =
            ResolveAlias(rs, "private_key", "privateKey", "REALITY tls_settings");
        if (!priv_res) {
            return tl::unexpected(std::move(priv_res.error()));
        }
        const auto* priv_val = *priv_res;
        if (!priv_val || !priv_val->is_string() || priv_val->as_string().empty()) {
            return tl::unexpected("REALITY tls_settings requires private_key");
        }
        const auto parsed_priv =
            transport::internet::ParseRealityKey(priv_val->as_string());
        if (!parsed_priv) {
            return tl::unexpected("REALITY private_key is invalid");
        }
        config.Reality.private_key = *parsed_priv;

        auto append_server_name = [](std::vector<std::string>& out,
                                     std::string_view name) -> bool {
            if (name.empty() || iputil::ParseLiteral(name) ||
                !domain::IsValidDnsHostname(name, domain::TrailingDotPolicy::Forbid)) {
                return false;
            }
            out.push_back(naming::LowerAscii(std::string(name)));
            return true;
        };
        const auto sn_list_res =
            ResolveAlias(rs, "server_names", "serverNames", "REALITY tls_settings");
        if (!sn_list_res) {
            return tl::unexpected(std::move(sn_list_res.error()));
        }
        const auto sn_res =
            ResolveAlias(rs, "server_name", "serverName", "REALITY tls_settings");
        if (!sn_res) {
            return tl::unexpected(std::move(sn_res.error()));
        }
        const auto* sn_list = *sn_list_res;
        const auto* sn = *sn_res;
        if (sn_list) {
            if (!sn_list->is_array()) {
                return tl::unexpected("REALITY server_names must be an array");
            }
            for (const auto& item : sn_list->as_array()) {
                if (!item.is_string() ||
                    !append_server_name(config.Reality.server_names, item.as_string())) {
                    return tl::unexpected("REALITY server_names contains an invalid hostname");
                }
            }
        }
        if (sn) {
            std::vector<std::string> single_names;
            if (!sn->is_string() ||
                !append_server_name(single_names, sn->as_string())) {
                return tl::unexpected("REALITY server_name is invalid");
            }
            if (sn_list) {
                if (config.Reality.server_names != single_names) {
                    return tl::unexpected(
                        "REALITY server_names and server_name must match");
                }
            } else {
                config.Reality.server_names = std::move(single_names);
            }
        } else if (!sn_list && !config.TLSServerName.empty()) {
            if (!append_server_name(config.Reality.server_names, config.TLSServerName)) {
                return tl::unexpected("REALITY server_name is invalid");
            }
        }
        if (config.Reality.server_names.empty()) {
            return tl::unexpected("REALITY node requires server_name");
        }

        auto append_short_id =
            [](std::vector<transport::internet::RealityShortId>& out,
               std::string_view sid) -> bool {
            auto parsed = transport::internet::ParseRealityShortId(sid);
            if (!parsed) {
                return false;
            }
            out.push_back(*parsed);
            return true;
        };
        const auto sid_list_res =
            ResolveAlias(rs, "short_ids", "shortIds", "REALITY tls_settings");
        if (!sid_list_res) {
            return tl::unexpected(std::move(sid_list_res.error()));
        }
        const auto sid_res =
            ResolveAlias(rs, "short_id", "shortId", "REALITY tls_settings");
        if (!sid_res) {
            return tl::unexpected(std::move(sid_res.error()));
        }
        const auto* sid_list = *sid_list_res;
        const auto* sid = *sid_res;
        if (sid_list) {
            if (!sid_list->is_array()) {
                return tl::unexpected("REALITY short_ids must be an array");
            }
            if (sid_list->as_array().empty()) {
                return tl::unexpected("REALITY short_ids must not be empty");
            }
            for (const auto& item : sid_list->as_array()) {
                if (!item.is_string() ||
                    !append_short_id(config.Reality.short_ids, item.as_string())) {
                    return tl::unexpected("REALITY short_ids contains an invalid value");
                }
            }
        }
        if (sid) {
            std::vector<transport::internet::RealityShortId> alt_short_ids;
            if (sid->is_array()) {
                if (sid->as_array().empty()) {
                    return tl::unexpected("REALITY short_ids must not be empty");
                }
                for (const auto& item : sid->as_array()) {
                    if (!item.is_string() ||
                        !append_short_id(alt_short_ids, item.as_string())) {
                        return tl::unexpected("REALITY short_id contains an invalid value");
                    }
                }
            } else if (sid->is_string()) {
                if (!append_short_id(alt_short_ids, sid->as_string())) {
                    return tl::unexpected("REALITY short_id is invalid");
                }
            } else {
                return tl::unexpected("REALITY short_id must be a string or array");
            }
            if (sid_list) {
                if (config.Reality.short_ids != alt_short_ids) {
                    return tl::unexpected(
                        "REALITY short_ids and short_id must match");
                }
            } else {
                config.Reality.short_ids = std::move(alt_short_ids);
            }
        } else if (!sid_list) {
            config.Reality.short_ids.push_back(transport::internet::RealityShortId{});
        }
        const auto sp_res =
            ResolveAlias(rs, "server_port", "serverPort", "REALITY tls_settings");
        if (!sp_res) {
            return tl::unexpected(std::move(sp_res.error()));
        }
        std::optional<uint16_t> sp_port;
        if (const auto* sp_val = *sp_res) {
            const auto port = PanelUnsignedInteger(*sp_val);
            if (!port || *port == 0 ||
                *port > std::numeric_limits<uint16_t>::max()) {
                return tl::unexpected("REALITY tls_settings.server_port is invalid");
            }
            sp_port = static_cast<uint16_t>(*port);
        }
        if (const auto* dest_val = rs.if_contains("dest");
            dest_val && !dest_val->is_null()) {
            if (!dest_val->is_string() || dest_val->as_string().empty()) {
                return tl::unexpected("REALITY dest must be a non-empty string");
            }
            const auto parsed_dest = TargetAddress::Parse(dest_val->as_string());
            if (!parsed_dest) {
                return tl::unexpected("REALITY dest is invalid");
            }
            if (sp_port && *sp_port != parsed_dest->port) {
                return tl::unexpected(
                    "REALITY dest and server_port must not conflict");
            }
            config.Reality.dest_host = parsed_dest->IsIP()
                ? iputil::NormalizeAddressString(*parsed_dest->resolved_addr)
                : std::string(parsed_dest->host);
            config.Reality.dest_port = parsed_dest->port;
        } else if (sp_port) {
            const std::string& fallback_host = config.Reality.server_names.front();
            if (!fallback_host.empty()) {
                config.Reality.dest_host = fallback_host;
                config.Reality.dest_port = *sp_port;
            }
        }

        if (const auto* xver_val = rs.if_contains("xver");
            xver_val && !xver_val->is_null()) {
            const auto xver = PanelUnsignedInteger(*xver_val);
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

        const auto mldsa_res =
            ResolveAlias(rs, "mldsa65_seed", "mldsa65Seed", "REALITY tls_settings");
        if (!mldsa_res) {
            return tl::unexpected(std::move(mldsa_res.error()));
        }
        if (const auto* mldsa_val = *mldsa_res) {
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

        const auto min_ver_res =
            ResolveAlias(rs, "min_client_ver", "minClientVer", "REALITY tls_settings");
        if (!min_ver_res) {
            return tl::unexpected(std::move(min_ver_res.error()));
        }
        if (const auto* min_ver_val = *min_ver_res) {
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

        const auto max_ver_res =
            ResolveAlias(rs, "max_client_ver", "maxClientVer", "REALITY tls_settings");
        if (!max_ver_res) {
            return tl::unexpected(std::move(max_ver_res.error()));
        }
        if (const auto* max_ver_val = *max_ver_res) {
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

        const auto max_time_res =
            ResolveAlias(rs, "max_time_diff", "maxTimeDiff", "REALITY tls_settings");
        if (!max_time_res) {
            return tl::unexpected(std::move(max_time_res.error()));
        }
        if (const auto* max_time_val = *max_time_res) {
            const auto max_time_diff = PanelUnsignedInteger(*max_time_val);
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
