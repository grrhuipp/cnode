#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace acpp::vless {

inline constexpr size_t kVlessX25519KeySize = 32;
inline constexpr size_t kVlessMlKem768SeedSize = 64;
inline constexpr size_t kVlessMlKem768PublicKeySize = 1184;
inline constexpr size_t kVlessMlKem768CiphertextSize = 1088;
inline constexpr size_t kVlessMlKem768SharedSecretSize = 32;

struct VlessX25519KeyPair {
    std::array<uint8_t, kVlessX25519KeySize> public_key{};
    std::array<uint8_t, kVlessX25519KeySize> private_key{};
};

struct VlessMlKem768Encapsulation {
    std::array<uint8_t, kVlessMlKem768CiphertextSize> ciphertext{};
    std::array<uint8_t, kVlessMlKem768SharedSecretSize> shared_secret{};
};

[[nodiscard]] VlessX25519KeyPair GenerateVlessX25519KeyPair() noexcept;

[[nodiscard]] bool DeriveVlessX25519PublicKey(
    std::span<const uint8_t> private_key,
    std::span<uint8_t, kVlessX25519KeySize> out_public_key) noexcept;

[[nodiscard]] std::optional<std::array<uint8_t, kVlessX25519KeySize>>
ComputeVlessX25519SharedKey(std::span<const uint8_t> private_key,
                            std::span<const uint8_t> peer_public_key) noexcept;

[[nodiscard]] std::optional<
    std::array<uint8_t, kVlessMlKem768PublicKeySize>>
DeriveVlessMlKem768PublicKeyFromSeed(std::span<const uint8_t> seed) noexcept;

[[nodiscard]] bool ValidateVlessMlKem768PublicKey(
    std::span<const uint8_t> public_key) noexcept;

[[nodiscard]] std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(std::span<const uint8_t> public_key) noexcept;

[[nodiscard]] std::optional<
    std::array<uint8_t, kVlessMlKem768SharedSecretSize>>
DecapsulateVlessMlKem768FromSeed(std::span<const uint8_t> seed,
                                 std::span<const uint8_t> ciphertext) noexcept;

}  // namespace acpp::vless
