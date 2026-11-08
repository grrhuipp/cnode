#include "vless_encryption_crypto.hpp"

#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mlkem.h>

#include <memory>
#include <new>

namespace vless {
namespace {

[[nodiscard]] std::shared_ptr<EVP_PKEY> ShareKey(
    bssl::UniquePtr<EVP_PKEY> key) noexcept {
    if (!key) {
        return nullptr;
    }
    try {
        return std::shared_ptr<EVP_PKEY>(key.release(), EVP_PKEY_free);
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
}

}  // namespace

VlessX25519KeyPair GenerateVlessX25519KeyPair() noexcept {
    VlessX25519KeyPair pair;
    X25519_keypair(pair.public_key.data(), pair.private_key.bytes.data());
    return pair;
}

bool DeriveVlessX25519PublicKey(
    std::span<const uint8_t> private_key,
    std::span<uint8_t, kVlessX25519KeySize> out_public_key) noexcept {
    if (private_key.size() != kVlessX25519KeySize) {
        return false;
    }
    X25519_public_from_private(out_public_key.data(), private_key.data());
    return true;
}

bool ComputeVlessX25519SharedKey(
    std::span<const uint8_t> private_key,
    std::span<const uint8_t> peer_public_key,
    std::span<uint8_t, kVlessX25519KeySize> out_shared) noexcept {
    return private_key.size() == kVlessX25519KeySize &&
           peer_public_key.size() == kVlessX25519KeySize &&
           X25519(out_shared.data(), private_key.data(),
                  peer_public_key.data()) == 1;
}

std::shared_ptr<EVP_PKEY>
CreateVlessMlKem768PrivateKeyFromSeed(
    std::span<const uint8_t> seed) noexcept {
    if (seed.size() != kVlessMlKem768SeedSize) {
        return nullptr;
    }
    // ML-KEM's seed is d || z (64 bytes), not the expanded private key.
    bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_from_private_seed(
        EVP_pkey_ml_kem_768(), seed.data(), seed.size()));
    if (!key) {
        ERR_clear_error();
        return nullptr;
    }
    return ShareKey(std::move(key));
}

std::shared_ptr<EVP_PKEY>
CreateVlessMlKem768PublicKey(
    std::span<const uint8_t> public_key) noexcept {
    if (public_key.size() != kVlessMlKem768PublicKeySize) {
        return nullptr;
    }
    bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_from_raw_public_key(
        EVP_pkey_ml_kem_768(),
        public_key.data(),
        public_key.size()));
    if (!key) {
        ERR_clear_error();
        return nullptr;
    }
    return ShareKey(std::move(key));
}

bssl::UniquePtr<EVP_PKEY> GenerateVlessMlKem768PrivateKey() noexcept {
    bssl::UniquePtr<EVP_PKEY> key(
        EVP_PKEY_generate_from_alg(EVP_pkey_ml_kem_768()));
    if (!key) {
        ERR_clear_error();
    }
    return key;
}

std::optional<std::array<uint8_t, kVlessMlKem768PublicKeySize>>
DeriveVlessMlKem768PublicKey(const EVP_PKEY* key) noexcept {
    if (!key || EVP_PKEY_id(key) != EVP_PKEY_ML_KEM_768) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessMlKem768PublicKeySize> public_key{};
    size_t public_len = public_key.size();
    if (EVP_PKEY_get_raw_public_key(
            key,
            public_key.data(),
            &public_len) != 1 ||
        public_len != public_key.size()) {
        ERR_clear_error();
        return std::nullopt;
    }
    return public_key;
}

std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(const EVP_PKEY* public_key) noexcept {
    if (!public_key) {
        return std::nullopt;
    }

    VlessMlKem768Encapsulation result;
    if (EVP_KEM_encap(
            EVP_kem_ml_kem_768(),
            result.ciphertext.data(),
            result.ciphertext.size(),
            result.shared_secret.bytes.data(),
            result.shared_secret.bytes.size(),
            public_key) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }
    return result;
}

std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(std::span<const uint8_t> public_key) noexcept {
    if (public_key.size() != kVlessMlKem768PublicKeySize) {
        return std::nullopt;
    }

    MLKEM768_public_key key;
    CBS input;
    CBS_init(&input, public_key.data(), public_key.size());
    if (MLKEM768_parse_public_key(&key, &input) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }
    VlessMlKem768Encapsulation result;
    MLKEM768_encap(result.ciphertext.data(), result.shared_secret.bytes.data(),
                  &key);
    return result;
}

bool DecapsulateVlessMlKem768(
    const EVP_PKEY* private_key,
    std::span<const uint8_t> ciphertext,
    std::span<uint8_t, kVlessMlKem768SharedSecretSize> out_shared) noexcept {
    if (!private_key || ciphertext.size() != kVlessMlKem768CiphertextSize) {
        return false;
    }

    if (EVP_KEM_decap(
            EVP_kem_ml_kem_768(),
            out_shared.data(),
            out_shared.size(),
            ciphertext.data(),
            ciphertext.size(),
            private_key) != 1) {
        ERR_clear_error();
        return false;
    }
    return true;
}

}  // namespace vless
