#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace acpp::transport::internet {

inline constexpr std::size_t kRealityKeySize = 32;
inline constexpr std::size_t kRealityMldsa65PublicKeySize = 1952;
inline constexpr std::size_t kRealityMldsa65SignatureSize = 3309;

using RealityKey = std::array<uint8_t, kRealityKeySize>;
using RealityMldsa65PublicKey = std::array<uint8_t, kRealityMldsa65PublicKeySize>;

enum class RealityKeyError {
    InvalidFormat,
};

[[nodiscard]] std::expected<RealityKey, RealityKeyError>
ParseRealityKey(std::string_view value) noexcept;

[[nodiscard]] std::expected<RealityKey, RealityKeyError>
ParseRealityMldsa65Seed(std::string_view value) noexcept;

[[nodiscard]] std::expected<RealityMldsa65PublicKey, RealityKeyError>
ParseRealityMldsa65PublicKey(std::string_view value) noexcept;

[[nodiscard]] std::optional<RealityMldsa65PublicKey>
DeriveRealityMldsa65PublicKeyFromSeed(const RealityKey& seed) noexcept;

[[nodiscard]] std::string
EncodeRealityBase64Url(std::span<const uint8_t> bytes);

[[nodiscard]] std::optional<std::string>
NormalizeRealityFingerprint(std::string_view value);

}  // namespace acpp::transport::internet
