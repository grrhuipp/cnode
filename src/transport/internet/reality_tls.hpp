#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/transport/internet/reality_key.hpp"
#include "acppnode/transport/internet/reality_short_id.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <openssl/ssl.h>

namespace acpp {

struct RealityClientState : memory::ThreadAllocated {
    std::array<uint8_t, 32> server_public{};
    transport::internet::RealityShortId short_id{};
    std::array<uint8_t, 32> auth_key{};
    std::string server_name;
    std::string spider_x;
    std::shared_ptr<const transport::internet::RealityMldsa65PublicKey> mldsa65_verify;
    memory::ByteVector client_hello_raw;
    memory::ByteVector server_hello_raw;
    bool auth_key_ready = false;
};

[[nodiscard]] bool VerifyRealityClientHandshake(
    SSL* ssl,
    const RealityClientState& state);

[[nodiscard]] bool VerifyRealityClientHelloRecord(
    std::span<const uint8_t> record,
    const RealityConfig& config,
    std::string* out_sni = nullptr);

}  // namespace acpp