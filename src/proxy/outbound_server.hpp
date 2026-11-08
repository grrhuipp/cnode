#pragma once

#include "infra/log.hpp"
#include "infra/outbound_source_config.hpp"
#include "transport/internet/outbound_sender.hpp"
#include "transport/internet/stream_settings.hpp"
#include "transport/internet/transport_security.hpp"

#include <cstdint>
#include <optional>
#include <string>
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

}  // namespace proxy
