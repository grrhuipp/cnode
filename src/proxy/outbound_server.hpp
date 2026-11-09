#pragma once

#include "infra/config_types.hpp"
#include "infra/log.hpp"
#include "transport/internet/outbound_target_builder.hpp"
#include "transport/internet/stream_settings.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace proxy {

// Cold-path result for a proxy protocol with a next hop: the validated server
// and the Handler's sender settings (sendThrough is applied by proxyman).
struct PreparedNextHop {
    OutboundServer server;
    OutboundSenderSettings sender;
};

// The one application of a protocol's stream defaults (TLS requirement,
// fallback SNI, ALPN) to the source streamSettings. Without an explicit
// fallback server name the next hop's address is used.
[[nodiscard]] inline StreamSettings PrepareOutboundStream(
    const infra::OutboundSourceConfig& source,
    const OutboundServer& server,
    OutboundStreamDefaults defaults) {
    if (defaults.fallback_server_name.empty()) {
        defaults.fallback_server_name = server.address;
    }
    auto settings = NormalizeOutboundStreamSettings(source.stream_settings, defaults);
    TransportSecurity::Prepare(settings, StreamEndpointRole::Outbound);
    return settings;
}

[[nodiscard]] inline std::optional<PreparedNextHop> PrepareNextHop(
    const infra::OutboundSourceConfig& source,
    std::string address,
    uint16_t port,
    const OutboundStreamDefaults& defaults) {
    auto server = MakeOutboundServer(std::move(address), port);
    if (!server) {
        LOG_ERROR("{} outbound '{}': {}", source.protocol, source.tag, server.error());
        return std::nullopt;
    }
    PreparedNextHop prepared{.server = std::move(*server), .sender = {}};
    prepared.sender.stream_settings = PrepareOutboundStream(source, prepared.server, defaults);
    return prepared;
}

// Validates an optional Xray-style single-element object array (e.g. "servers"
// or "vnext"). Returns nullptr when absent, the single object when valid, or
// std::nullopt on a malformed present field (Fail-Closed).
[[nodiscard]] inline std::optional<const json::object*>
ParseOptionalSingleObjectArray(
    const json::object& parent,
    std::string_view key,
    std::string_view protocol,
    std::string_view tag) {
    const auto* value = parent.if_contains(key);
    if (!value) {
        return static_cast<const json::object*>(nullptr);
    }
    if (!value->is_array() ||
        value->as_array().size() != 1 ||
        !value->as_array()[0].is_object()) {
        LOG_ERROR("{} outbound '{}': {} must be a single-element object array",
                  protocol, tag, key);
        return std::nullopt;
    }
    return &value->as_array()[0].as_object();
}

[[nodiscard]] inline const json::object*
ParseRequiredSingleObjectArray(
    const json::object& parent,
    std::string_view key,
    std::string_view protocol,
    std::string_view tag) {
    const auto parsed = ParseOptionalSingleObjectArray(parent, key, protocol, tag);
    if (!parsed) {
        return nullptr;
    }
    if (!*parsed) {
        LOG_ERROR("{} outbound '{}': {} must be a single-element object array",
                  protocol, tag, key);
        return nullptr;
    }
    return *parsed;
}

}  // namespace proxy
