#pragma once

#include "common/asio_types.hpp"
#include "common/domain_name.hpp"
#include "common/ip_address.hpp"
#include "transport/internet/outbound_bind.hpp"
#include "transport/internet/stream_settings.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tl/expected.hpp>
#include <utility>


// Xray proxyman SenderSettings: how one outbound tag leaves this node. Owned by
// the proxyman outbound Handler and borrowed by its OutboundDialer; protocol
// defaults (TLS requirement, fallback SNI, ALPN) are applied when prepared.
struct OutboundSenderSettings {
    StreamSettings stream_settings;
    OutboundBind send_through;
    bool passthrough = false;
};

// A proxy protocol's next hop. The literal form is parsed once on the cold
// path; a hostname is resolved by the dialer per connection.
struct OutboundServer {
    std::string address;
    std::optional<net::ip::address> literal_address;
    uint16_t port = 0;
};

// The one validator for a configured next hop: a non-empty IP literal or DNS
// hostname and a non-zero port.
[[nodiscard]] inline tl::expected<OutboundServer, std::string_view> MakeOutboundServer(
    std::string address, uint16_t port) {
    if (address.empty()) return tl::unexpected(std::string_view("server address is required"));
    if (port == 0) return tl::unexpected(std::string_view("server port is required"));
    auto literal = iputil::ParseLiteral(address);
    if (!literal && !domain::IsValidDnsHostname(address, domain::TrailingDotPolicy::Allow)) {
        return tl::unexpected(std::string_view(
            "server address must be an IP literal or DNS hostname"));
    }
    return OutboundServer{
        .address = std::move(address),
        .literal_address = literal,
        .port = port,
    };
}

