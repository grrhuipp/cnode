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

class SslContext;

struct RealityClientState : memory::ThreadAllocated {
    std::array<uint8_t, 32> server_public{};
    transport::internet::RealityShortId short_id{};
    std::array<uint8_t, 32> auth_key{};
    memory::ThreadLocalString server_name;
    memory::ThreadLocalString spider_x;
    EVP_PKEY* mldsa65_verify_key = nullptr;
    memory::ByteVector client_hello_raw;
    memory::ByteVector server_hello_raw;
    bool auth_key_ready = false;
};

struct RealityServerConnState : memory::ThreadAllocated {
    std::array<uint8_t, 32> auth_key{};
    memory::ByteVector client_hello_raw;
    bool authenticated = false;
};

[[nodiscard]] bool VerifyRealityClientHandshake(
    SSL* ssl,
    const RealityClientState& state);

void ClearRealityClientState(
    SSL* ssl,
    std::unique_ptr<RealityClientState>& state) noexcept;

void ClearRealityServerConnState(SSL* ssl) noexcept;

[[nodiscard]] std::unique_ptr<RealityServerConnState>
VerifyRealityClientHelloRecord(
    std::span<const uint8_t> record,
    const SslContext& ctx,
    std::string* out_sni = nullptr);
}  // namespace acpp