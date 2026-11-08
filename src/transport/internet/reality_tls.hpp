#pragma once

#include "common/allocator.hpp"
#include "transport/internet/reality_key.hpp"
#include "transport/internet/reality_short_id.hpp"
#include "transport/internet/stream_settings.hpp"
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <openssl/ssl.h>
#include <openssl/mem.h>
#include <openssl/mldsa.h>


class SslContext;

struct RealityClientState : memory::ThreadAllocated {
    ~RealityClientState() {
        OPENSSL_cleanse(auth_key.data(), auth_key.size());
        OPENSSL_cleanse(short_id.data(), short_id.size());
    }
    std::array<uint8_t, 32> server_public{};
    transport::internet::RealityShortId short_id{};
    std::array<uint8_t, 32> auth_key{};
    memory::ThreadLocalString server_name;
    memory::ThreadLocalString spider_x;
    const MLDSA65_public_key* mldsa65_verify_key = nullptr;
    memory::ByteVector client_hello_raw;
    memory::ByteVector server_hello_raw;
    bool auth_key_ready = false;
};

struct RealityServerConnState : memory::ThreadAllocated {
    ~RealityServerConnState() {
        OPENSSL_cleanse(auth_key.data(), auth_key.size());
    }
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
VerifyRealityClientHello(
    std::span<const uint8_t> handshake,
    const SslContext& ctx);