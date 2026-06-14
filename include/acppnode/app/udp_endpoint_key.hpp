#pragma once

#include "acppnode/common/asio_types.hpp"

#include <cstdint>
#include <functional>

namespace acpp {

struct UdpEndpointKey {
    net::ip::address address;
    uint16_t port = 0;

    [[nodiscard]] bool operator==(const UdpEndpointKey& other) const noexcept {
        return port == other.port && address == other.address;
    }
};

struct UdpEndpointKeyHash {
    [[nodiscard]] size_t operator()(const UdpEndpointKey& key) const noexcept {
        size_t h = std::hash<uint16_t>{}(key.port);
        if (key.address.is_v4()) {
            const auto bytes = key.address.to_v4().to_bytes();
            const uint32_t value = (static_cast<uint32_t>(bytes[0]) << 24) |
                                   (static_cast<uint32_t>(bytes[1]) << 16) |
                                   (static_cast<uint32_t>(bytes[2]) << 8) |
                                   static_cast<uint32_t>(bytes[3]);
            h ^= std::hash<uint32_t>{}(value) + 0x9e3779b9u + (h << 6) + (h >> 2);
            return h;
        }

        const auto bytes = key.address.to_v6().to_bytes();
        uint64_t hi = 0;
        uint64_t lo = 0;
        for (size_t i = 0; i < 8; ++i) {
            hi = (hi << 8) | bytes[i];
            lo = (lo << 8) | bytes[i + 8];
        }
        h ^= std::hash<uint64_t>{}(hi) + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        h ^= std::hash<uint64_t>{}(lo) + 0x9e3779b97f4a7c15ull + (h << 6) + (h >> 2);
        return h;
    }
};

}  // namespace acpp
