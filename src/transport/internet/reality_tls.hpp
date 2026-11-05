#pragma once

#include "acppnode/transport/internet/reality_key.hpp"
#include "acppnode/transport/internet/reality_short_id.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/mem.h>

namespace acpp {

class SslContext;

struct RealityClientState {
    ~RealityClientState() {
        OPENSSL_cleanse(auth_key.data(), auth_key.size());
        OPENSSL_cleanse(short_id.data(), short_id.size());
    }
    std::array<uint8_t, 32> server_public{};
    transport::internet::RealityShortId short_id{};
    std::array<uint8_t, 32> auth_key{};
    std::string server_name;
    std::string spider_x;
    EVP_PKEY* mldsa65_verify_key = nullptr;
    std::vector<uint8_t> client_hello_raw;
    std::vector<uint8_t> server_hello_raw;
    bool auth_key_ready = false;
};

struct RealityServerConnState {
    ~RealityServerConnState() {
        OPENSSL_cleanse(auth_key.data(), auth_key.size());
    }
    std::array<uint8_t, 32> auth_key{};
    std::vector<uint8_t> client_hello_raw;
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
VerifyRealityClientHello(
    std::span<const uint8_t> handshake,
    const SslContext& ctx,
    std::string* out_sni = nullptr);
}  // namespace acpp