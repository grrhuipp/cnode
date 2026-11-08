#pragma once

#include "common/ip_utils.hpp"
#include "proxy/inbound_datagram.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace worker_detail {

struct ClientSessionKey final {
    ClientSessionKey(InboundDatagramOwner authenticated_owner,
                     std::optional<uint64_t> protocol_session_id,
                     udp::endpoint client_endpoint = {},
                     const proxyman::inbound::ProtocolSettings* configuration_identity = nullptr) noexcept
        : owner(authenticated_owner), session_id(protocol_session_id),
          endpoint(protocol_session_id ? udp::endpoint{} :
              udp::endpoint(iputil::NormalizeAddress(client_endpoint.address()), client_endpoint.port())),
          configuration(configuration_identity) {}

    [[nodiscard]] bool operator==(const ClientSessionKey& other) const noexcept {
        return configuration == other.configuration && owner.Same(other.owner) &&
            session_id == other.session_id && (session_id.has_value() || endpoint == other.endpoint);
    }

    InboundDatagramOwner owner;
    std::optional<uint64_t> session_id;
    udp::endpoint endpoint;
    const proxyman::inbound::ProtocolSettings* configuration = nullptr;
};

struct ClientSessionKeyHash final {
    [[nodiscard]] size_t operator()(const ClientSessionKey& key) const noexcept {
        size_t hash = 2166136261u;
        const auto mix = [&hash](uint8_t byte) noexcept {
            hash = (hash ^ byte) * 16777619u;
        };
        const auto configuration = reinterpret_cast<uintptr_t>(key.configuration);
        for (size_t shift = 0; shift < sizeof(configuration) * 8; shift += 8)
            mix(static_cast<uint8_t>(configuration >> shift));
        mix(key.owner.size);
        for (size_t i = 0; i < key.owner.size; ++i) mix(key.owner.bytes[i]);
        mix(key.session_id.has_value());
        if (key.session_id) {
            for (unsigned shift = 0; shift < 64; shift += 8)
                mix(static_cast<uint8_t>(*key.session_id >> shift));
        } else {
            const auto& address = key.endpoint.address();
            mix(address.is_v4() ? 4 : 6);
            if (address.is_v4()) {
                for (auto byte : address.to_v4().to_bytes()) mix(byte);
            } else {
                const auto v6 = address.to_v6();
                for (auto byte : v6.to_bytes()) mix(byte);
                const auto scope = v6.scope_id();
                for (size_t shift = 0; shift < sizeof(scope) * 8; shift += 8)
                    mix(static_cast<uint8_t>(scope >> shift));
            }
            mix(static_cast<uint8_t>(key.endpoint.port() >> 8));
            mix(static_cast<uint8_t>(key.endpoint.port()));
        }
        return hash;
    }
};

} // namespace worker_detail
