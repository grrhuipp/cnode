#pragma once

#include "common/allocator.hpp"
#include "common/byte_reader.hpp"
#include "transport/internet/reality_key.hpp"
#include "transport/internet/stream_settings.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <tl/expected.hpp>
#include <openssl/ssl.h>
#include <openssl/mem.h>
#include <openssl/mldsa.h>


namespace transport::internet {

enum class RealityKeyShareError {
    InvalidFormat,
};

[[nodiscard]] inline tl::expected<RealityKey, RealityKeyShareError>
ParseRealityClientKeyShareExtension(
    std::span<const uint8_t> extension) noexcept {
    constexpr uint16_t kTlsGroupX25519 = 29;
    constexpr uint16_t kTlsGroupX25519MlKem768 = 0x11ec;
    constexpr std::size_t kMlKem768PublicKeySize = 1184;
    constexpr std::size_t kX25519MlKem768ClientShareSize =
        kMlKem768PublicKeySize + kRealityKeySize;

    ByteReader outer(extension);
    const auto list = outer.ReadBytes(outer.ReadU16BE());
    if (!outer.Ok() || !outer.Empty()) {
        return tl::unexpected(RealityKeyShareError::InvalidFormat);
    }

    std::optional<RealityKey> x25519;
    std::optional<RealityKey> hybrid_x25519;
    ByteReader reader(list);
    while (!reader.Empty()) {
        const uint16_t group = reader.ReadU16BE();
        const uint16_t key_size = reader.ReadU16BE();
        const auto key = reader.ReadBytes(key_size);
        if (!reader.Ok() || key_size == 0) {
            return tl::unexpected(RealityKeyShareError::InvalidFormat);
        }
        if (group == kTlsGroupX25519) {
            if (x25519 || key.size() != kRealityKeySize) {
                return tl::unexpected(RealityKeyShareError::InvalidFormat);
            }
            RealityKey parsed{};
            std::copy_n(key.data(), parsed.size(), parsed.begin());
            x25519 = parsed;
        } else if (group == kTlsGroupX25519MlKem768) {
            if (hybrid_x25519 || key.size() != kX25519MlKem768ClientShareSize) {
                return tl::unexpected(RealityKeyShareError::InvalidFormat);
            }
            RealityKey parsed{};
            std::copy_n(
                key.data() + key.size() - kRealityKeySize,
                parsed.size(),
                parsed.begin());
            hybrid_x25519 = parsed;
        }
    }
    if (x25519) return *x25519;
    if (hybrid_x25519) return *hybrid_x25519;
    return tl::unexpected(RealityKeyShareError::InvalidFormat);
}

}  // namespace transport::internet

class SslContext;

struct RealityClientState : memory::ThreadAllocated {
    ~RealityClientState() {
        OPENSSL_cleanse(auth_key.data(), auth_key.size());
        OPENSSL_cleanse(short_id.data(), short_id.size());
    }
    transport::internet::RealityShortId short_id{};
    std::array<uint8_t, 32> auth_key{};
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
    memory::ByteVector handshake,
    const SslContext& ctx);