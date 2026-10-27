#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/internet/reality_short_id.hpp"
#include <array>
#include <cstdint>
#include <openssl/ssl.h>

namespace acpp {

struct RealityClientState : memory::ThreadAllocated {
    std::array<uint8_t, 32> server_public{};
    transport::internet::RealityShortId short_id{};
    std::array<uint8_t, 32> auth_key{};
    bool auth_key_ready = false;
};

[[nodiscard]] bool VerifyRealityClientHandshake(
    SSL* ssl,
    const RealityClientState& state);
}  // namespace acpp