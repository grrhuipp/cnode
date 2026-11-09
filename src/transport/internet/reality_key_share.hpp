#pragma once

#include "common/byte_reader.hpp"
#include "transport/internet/reality_key.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <tl/expected.hpp>

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
