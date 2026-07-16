#include "node_info_json.hpp"

#include "acppnode/core/constants.hpp"
#include "acppnode/infra/json_port.hpp"
#include "acppnode/transport/internet/http_headers.hpp"

#include <optional>
#include <utility>

namespace acpp::api::v2board {

namespace {

std::expected<uint16_t, std::string> ParseServerPort(const json::object& source) {
    const auto result = ReadJsonPort(source, {"server_port"});
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
            config.EnableTLS = tls->as_int64() != 0;
        } else if (tls->is_bool()) {
            config.EnableTLS = tls->as_bool();
        }
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
