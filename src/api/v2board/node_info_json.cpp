#include "node_info_json.hpp"

#include "core/constants.hpp"
#include "core/naming.hpp"
#include "infra/inbound_field_rules.hpp"
#include "infra/json_field.hpp"
#include "transport/internet/http_headers.hpp"
#include "panel_json_compat.hpp"

#include <format>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

namespace api::v2board {

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
    if (primary_val && secondary_val && *primary_val != *secondary_val) {
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

// Reads one alias pair; null and absent are both "not declared".
#define ACPP_RESOLVE_OR_RETURN(var, obj, primary, secondary)                   \
    const auto var##_res =                                                     \
        ResolveAlias(obj, primary, secondary, "REALITY tls_settings");         \
    if (!var##_res) {                                                          \
        return tl::unexpected(std::move(var##_res.error()));                   \
    }                                                                          \
    const json::value* const var = *var##_res

tl::expected<std::vector<std::string>, std::string> ReadPanelStringList(
    const json::value& value, std::string_view field, bool allow_scalar) {
    std::vector<std::string> out;
    if (allow_scalar && value.is_string()) {
        out.push_back(naming::LowerAscii(std::string(value.as_string())));
        return out;
    }
    if (!value.is_array()) {
        return tl::unexpected(allow_scalar
            ? std::format("REALITY {} must be a string or array", field)
            : std::format("REALITY {} must be an array", field));
    }
    for (const auto& item : value.as_array()) {
        if (!item.is_string()) {
            return tl::unexpected(std::format(
                "REALITY {} must contain only strings", field));
        }
        out.push_back(naming::LowerAscii(std::string(item.as_string())));
    }
    return out;
}

// Maps v2board tls_settings onto the shared REALITY server input; semantic
// validation belongs to infra::ApplyRealityServerInput.
tl::expected<void, std::string> MapRealitySettings(
    const json::object& rs,
    std::string_view tls_server_name,
    RealityConfig& out) {
    infra::RealityServerInput input;

    ACPP_RESOLVE_OR_RETURN(private_key, rs, "private_key", "privateKey");
    if (private_key) {
        if (!private_key->is_string()) {
            return tl::unexpected("REALITY private_key must be a string");
        }
        input.private_key = std::string(private_key->as_string());
    }

    ACPP_RESOLVE_OR_RETURN(server_names, rs, "server_names", "serverNames");
    ACPP_RESOLVE_OR_RETURN(server_name, rs, "server_name", "serverName");
    if (server_names) {
        auto names = ReadPanelStringList(*server_names, "server_names", false);
        if (!names) {
            return tl::unexpected(std::move(names.error()));
        }
        input.server_names = std::move(*names);
    }
    if (server_name) {
        if (!server_name->is_string()) {
            return tl::unexpected("REALITY server_name must be a string");
        }
        std::vector<std::string> single{
            naming::LowerAscii(std::string(server_name->as_string()))};
        if (server_names && input.server_names != single) {
            return tl::unexpected(
                "REALITY server_names and server_name must match");
        }
        input.server_names = std::move(single);
    } else if (!server_names && !tls_server_name.empty()) {
        input.server_names.emplace_back(tls_server_name);
    }

    ACPP_RESOLVE_OR_RETURN(short_ids, rs, "short_ids", "shortIds");
    ACPP_RESOLVE_OR_RETURN(short_id, rs, "short_id", "shortId");
    if (short_ids) {
        auto ids = ReadPanelStringList(*short_ids, "short_ids", false);
        if (!ids) {
            return tl::unexpected(std::move(ids.error()));
        }
        input.short_ids = std::move(*ids);
    }
    if (short_id) {
        auto ids = ReadPanelStringList(*short_id, "short_id", true);
        if (!ids) {
            return tl::unexpected(std::move(ids.error()));
        }
        if (short_ids && input.short_ids != *ids) {
            return tl::unexpected("REALITY short_ids and short_id must match");
        }
        input.short_ids = std::move(*ids);
    } else if (!short_ids) {
        // Panel mapping default: a node without short ids admits the empty id.
        input.short_ids.emplace_back();
    }

    ACPP_RESOLVE_OR_RETURN(server_port, rs, "server_port", "serverPort");
    std::optional<uint16_t> sp_port;
    if (server_port) {
        const auto port = PanelUnsignedInteger(*server_port);
        if (!port || *port == 0 ||
            *port > std::numeric_limits<uint16_t>::max()) {
            return tl::unexpected("REALITY tls_settings.server_port is invalid");
        }
        sp_port = static_cast<uint16_t>(*port);
    }
    if (const auto* dest = rs.if_contains("dest"); dest && !dest->is_null()) {
        if (!dest->is_string()) {
            return tl::unexpected("REALITY dest must be a string");
        }
        input.dest = std::string(dest->as_string());
    } else if (sp_port && !input.server_names.empty() &&
               !input.server_names.front().empty()) {
        // v2board sends the fallback port separately from the SNI host.
        input.dest = std::format("{}:{}", input.server_names.front(), *sp_port);
    }

    if (const auto* xver = rs.if_contains("xver"); xver && !xver->is_null()) {
        const auto value = PanelUnsignedInteger(*xver);
        if (!value) {
            return tl::unexpected(
                "REALITY xver must be an integer between 0 and 2");
        }
        input.xver = *value;
    }

    ACPP_RESOLVE_OR_RETURN(mldsa65_seed, rs, "mldsa65_seed", "mldsa65Seed");
    if (mldsa65_seed) {
        if (!mldsa65_seed->is_string()) {
            return tl::unexpected("REALITY mldsa65_seed must be a string");
        }
        input.mldsa65_seed = std::string(mldsa65_seed->as_string());
    }

    ACPP_RESOLVE_OR_RETURN(min_ver, rs, "min_client_ver", "minClientVer");
    if (min_ver) {
        if (!min_ver->is_string()) {
            return tl::unexpected("REALITY min_client_ver must be a string");
        }
        input.min_client_ver = std::string(min_ver->as_string());
    }
    ACPP_RESOLVE_OR_RETURN(max_ver, rs, "max_client_ver", "maxClientVer");
    if (max_ver) {
        if (!max_ver->is_string()) {
            return tl::unexpected("REALITY max_client_ver must be a string");
        }
        input.max_client_ver = std::string(max_ver->as_string());
    }

    ACPP_RESOLVE_OR_RETURN(max_time, rs, "max_time_diff", "maxTimeDiff");
    if (max_time) {
        const auto value = PanelUnsignedInteger(*max_time);
        if (!value) {
            return tl::unexpected(
                "REALITY max_time_diff must be a non-negative integer");
        }
        input.max_time_diff = *value;
    }

    if (auto applied = infra::ApplyRealityServerInput(input, out); !applied) {
        return applied;
    }
    // A synthesized dest always carries server_port; a declared one must agree.
    if (sp_port && out.HasDest() && out.dest_port != *sp_port) {
        return tl::unexpected("REALITY dest and server_port must not conflict");
    }
    return infra::ValidateInboundReality(out);
}

#undef ACPP_RESOLVE_OR_RETURN

}  // namespace

tl::expected<::api::NodeInfo, std::string> ParseNodeInfo(
    const json::object& source,
    std::string_view node_type) {
    auto port = ParseServerPort(source);
    if (!port) {
        return tl::unexpected(std::move(port.error()));
    }

    ::api::NodeInfo config;
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
        }
        if (const auto* service_name = settings.if_contains("serviceName");
            service_name && !service_name->is_null()) {
            if (!service_name->is_string()) {
                return tl::unexpected(
                    "networkSettings serviceName must be a string");
            }
            config.ServiceName = std::string(service_name->as_string());
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
                auto value = infra::NormalizeHttpAuthority(
                    raw_value.as_string(), "networkSettings Host");
                if (!value) {
                    return tl::unexpected(std::move(value.error()));
                }
                if (host && *host != *value) {
                    return tl::unexpected(
                        "networkSettings Host aliases must match");
                }
                host = std::move(*value);
            }
            config.Host = std::move(host).value_or("");
        }
    }

    // gRPC carries its service in serviceName, falling back to path; every
    // other transport uses path with the shared "/" default.
    if (config.TransportProtocol == constants::protocol::kGrpc) {
        if (config.ServiceName.empty()) {
            config.ServiceName = std::exchange(config.Path, {});
        }
        config.Path.clear();
        if (auto valid = infra::ValidateGrpcServiceName(
                config.ServiceName, "networkSettings serviceName");
            !valid) {
            return tl::unexpected(std::move(valid.error()));
        }
    } else {
        auto path = infra::NormalizeTransportPath(
            config.Path, "networkSettings path");
        if (!path) {
            return tl::unexpected(std::move(path.error()));
        }
        config.Path = std::move(*path);
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
        auto normalized = infra::NormalizeTlsServerName(
            server_name->as_string(), "server_name");
        if (!normalized) {
            return tl::unexpected(std::move(normalized.error()));
        }
        config.TLSServerName = std::move(*normalized);
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
        if (const auto* padding = source.if_contains("padding_scheme")) {
            auto scheme = infra::ParseAnyTlsPaddingScheme(*padding, "padding_scheme");
            if (!scheme) {
                return tl::unexpected(std::move(scheme.error()));
            }
            config.PaddingScheme = std::move(*scheme);
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
        auto mapped = MapRealitySettings(
            tls_settings_val->as_object(), config.TLSServerName, config.Reality);
        if (!mapped) {
            return tl::unexpected(std::move(mapped.error()));
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

}  // namespace api::v2board
