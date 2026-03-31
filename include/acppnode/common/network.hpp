#pragma once

#include <cstdint>

#include "acppnode/core/constants.hpp"

namespace acpp {

// ============================================================================
// 网络类型
// ============================================================================
enum class Network : uint8_t {
    TCP = 0,
    UDP = 1,
    MUX = 2,   // VMess Command=Mux（Mux.Cool 多路复用流）
};

constexpr const char* NetworkToString(Network n) {
    switch (n) {
        case Network::TCP: return constants::protocol::kTcp.data();
        case Network::UDP: return constants::protocol::kUdp.data();
        case Network::MUX: return constants::protocol::kMux.data();
        default: return "unknown";
    }
}

// ============================================================================
// 地址类型（内部表示，与具体协议无关）
// ============================================================================
enum class AddressType : uint8_t {
    IPv4 = 1,
    Domain = 3
};

}  // namespace acpp
