#pragma once

#include <openssl/base.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/mlkem.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
namespace vless {

inline constexpr size_t kVlessX25519KeySize = 32;
inline constexpr size_t kVlessMlKem768SeedSize = 64;
inline constexpr size_t kVlessMlKem768PublicKeySize = 1184;
inline constexpr size_t kVlessMlKem768CiphertextSize = 1088;
inline constexpr size_t kVlessMlKem768SharedSecretSize = 32;
static_assert(kVlessMlKem768SeedSize == MLKEM_SEED_BYTES);
static_assert(kVlessMlKem768PublicKeySize == MLKEM768_PUBLIC_KEY_BYTES);
static_assert(kVlessMlKem768CiphertextSize == MLKEM768_CIPHERTEXT_BYTES);
static_assert(kVlessMlKem768SharedSecretSize == MLKEM_SHARED_SECRET_BYTES);

// The NFS key is a single X25519 or ML-KEM-768 shared secret.
inline constexpr size_t kVlessEncryptionNfsKeySize = kVlessX25519KeySize;
static_assert(kVlessEncryptionNfsKeySize == kVlessMlKem768SharedSecretSize);
inline constexpr size_t kVlessEncryptionPfsKeySize =
    kVlessMlKem768SharedSecretSize + kVlessX25519KeySize;
inline constexpr size_t kVlessEncryptionUnitedKeySize =
    kVlessEncryptionPfsKeySize + kVlessEncryptionNfsKeySize;

// Fixed-size key material that wipes its storage on destruction. Copies are
// independent and each wipes itself, so moves deliberately degrade to copies.
template <size_t N>
struct VlessSecretBytes {
    std::array<uint8_t, N> bytes{};

    VlessSecretBytes() noexcept = default;
    VlessSecretBytes(const VlessSecretBytes&) noexcept = default;
    VlessSecretBytes& operator=(const VlessSecretBytes&) noexcept = default;
    ~VlessSecretBytes() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

using VlessEncryptionNfsKey = VlessSecretBytes<kVlessEncryptionNfsKeySize>;
using VlessEncryptionPfsKey = VlessSecretBytes<kVlessEncryptionPfsKeySize>;
using VlessEncryptionUnitedKey = VlessSecretBytes<kVlessEncryptionUnitedKeySize>;

struct VlessX25519KeyPair {
    std::array<uint8_t, kVlessX25519KeySize> public_key{};
    VlessSecretBytes<kVlessX25519KeySize> private_key;
};

struct VlessMlKem768Encapsulation {
    std::array<uint8_t, kVlessMlKem768CiphertextSize> ciphertext{};
    VlessSecretBytes<kVlessMlKem768SharedSecretSize> shared_secret;
};

[[nodiscard]] VlessX25519KeyPair GenerateVlessX25519KeyPair() noexcept;

[[nodiscard]] bool DeriveVlessX25519PublicKey(
    std::span<const uint8_t> private_key,
    std::span<uint8_t, kVlessX25519KeySize> out_public_key) noexcept;

[[nodiscard]] bool ComputeVlessX25519SharedKey(
    std::span<const uint8_t> private_key,
    std::span<const uint8_t> peer_public_key,
    std::span<uint8_t, kVlessX25519KeySize> out_shared) noexcept;

// EVP_PKEY owns the expanded ML-KEM key and seed; EVP_PKEY_free wipes both.
// Configuration keys share ownership, while each PFS hello owns its own key.
[[nodiscard]] std::shared_ptr<EVP_PKEY>
CreateVlessMlKem768PrivateKeyFromSeed(std::span<const uint8_t> seed) noexcept;

[[nodiscard]] std::shared_ptr<EVP_PKEY>
CreateVlessMlKem768PublicKey(std::span<const uint8_t> public_key) noexcept;

[[nodiscard]] bssl::UniquePtr<EVP_PKEY> GenerateVlessMlKem768PrivateKey() noexcept;

[[nodiscard]] std::optional<
    std::array<uint8_t, kVlessMlKem768PublicKeySize>>
DeriveVlessMlKem768PublicKey(const EVP_PKEY* key) noexcept;

[[nodiscard]] std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(const EVP_PKEY* public_key) noexcept;

[[nodiscard]] std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(std::span<const uint8_t> public_key) noexcept;

[[nodiscard]] bool DecapsulateVlessMlKem768(
    const EVP_PKEY* private_key,
    std::span<const uint8_t> ciphertext,
    std::span<uint8_t, kVlessMlKem768SharedSecretSize> out_shared) noexcept;

}  // namespace vless
