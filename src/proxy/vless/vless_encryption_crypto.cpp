#include "vless_encryption_crypto.hpp"

#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/experimental/kem_deterministic_api.h>
#include <openssl/nid.h>

#include <memory>

namespace acpp::vless {
namespace {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* key) const noexcept {
        EVP_PKEY_free(key);
    }
};

struct EvpPkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX* ctx) const noexcept {
        EVP_PKEY_CTX_free(ctx);
    }
};

using UniquePkey = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using UniquePkeyCtx = std::unique_ptr<EVP_PKEY_CTX, EvpPkeyCtxDeleter>;

[[nodiscard]] UniquePkey MlKem768PrivateKeyFromSeed(
    std::span<const uint8_t> seed) noexcept {
    if (seed.size() != kVlessMlKem768SeedSize) {
        return {};
    }

    UniquePkeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, nullptr));
    if (!ctx ||
        EVP_PKEY_keygen_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_kem_set_params(ctx.get(), NID_MLKEM768) != 1) {
        return {};
    }

    EVP_PKEY* raw = nullptr;
    size_t seed_len = seed.size();
    if (EVP_PKEY_keygen_deterministic(
            ctx.get(),
            &raw,
            seed.data(),
            &seed_len) != 1 ||
        raw == nullptr) {
        return {};
    }
    return UniquePkey(raw);
}

}  // namespace

VlessX25519KeyPair GenerateVlessX25519KeyPair() noexcept {
    VlessX25519KeyPair pair;
    X25519_keypair(pair.public_key.data(), pair.private_key.data());
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

std::optional<std::array<uint8_t, kVlessX25519KeySize>>
ComputeVlessX25519SharedKey(std::span<const uint8_t> private_key,
                            std::span<const uint8_t> peer_public_key) noexcept {
    if (private_key.size() != kVlessX25519KeySize ||
        peer_public_key.size() != kVlessX25519KeySize) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessX25519KeySize> shared{};
    if (X25519(shared.data(), private_key.data(), peer_public_key.data()) != 1) {
        return std::nullopt;
    }
    return shared;
}

std::optional<std::array<uint8_t, kVlessMlKem768PublicKeySize>>
DeriveVlessMlKem768PublicKeyFromSeed(
    std::span<const uint8_t> seed) noexcept {
    UniquePkey key = MlKem768PrivateKeyFromSeed(seed);
    if (!key) {
        return std::nullopt;
    }

    size_t public_len = 0;
    if (EVP_PKEY_get_raw_public_key(key.get(), nullptr, &public_len) != 1 ||
        public_len != kVlessMlKem768PublicKeySize) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessMlKem768PublicKeySize> public_key{};
    public_len = public_key.size();
    if (EVP_PKEY_get_raw_public_key(
            key.get(),
            public_key.data(),
            &public_len) != 1 ||
        public_len != public_key.size()) {
        return std::nullopt;
    }
    return public_key;
}

bool ValidateVlessMlKem768PublicKey(
    std::span<const uint8_t> public_key) noexcept {
    if (public_key.size() != kVlessMlKem768PublicKeySize) {
        return false;
    }

    UniquePkey key(EVP_PKEY_kem_new_raw_public_key(
        NID_MLKEM768,
        public_key.data(),
        public_key.size()));
    return key != nullptr;
}

std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(std::span<const uint8_t> public_key) noexcept {
    if (public_key.size() != kVlessMlKem768PublicKeySize) {
        return std::nullopt;
    }

    UniquePkey key(EVP_PKEY_kem_new_raw_public_key(
        NID_MLKEM768,
        public_key.data(),
        public_key.size()));
    if (!key) {
        return std::nullopt;
    }

    UniquePkeyCtx ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
    if (!ctx) {
        return std::nullopt;
    }

    size_t ciphertext_len = 0;
    size_t shared_len = 0;
    if (EVP_PKEY_encapsulate(
            ctx.get(),
            nullptr,
            &ciphertext_len,
            nullptr,
            &shared_len) != 1 ||
        ciphertext_len != kVlessMlKem768CiphertextSize ||
        shared_len != kVlessMlKem768SharedSecretSize) {
        return std::nullopt;
    }

    VlessMlKem768Encapsulation result;
    ciphertext_len = result.ciphertext.size();
    shared_len = result.shared_secret.size();
    if (EVP_PKEY_encapsulate(
            ctx.get(),
            result.ciphertext.data(),
            &ciphertext_len,
            result.shared_secret.data(),
            &shared_len) != 1 ||
        ciphertext_len != result.ciphertext.size() ||
        shared_len != result.shared_secret.size()) {
        return std::nullopt;
    }
    return result;
}

std::optional<std::array<uint8_t, kVlessMlKem768SharedSecretSize>>
DecapsulateVlessMlKem768FromSeed(std::span<const uint8_t> seed,
                                 std::span<const uint8_t> ciphertext) noexcept {
    if (ciphertext.size() != kVlessMlKem768CiphertextSize) {
        return std::nullopt;
    }

    UniquePkey key = MlKem768PrivateKeyFromSeed(seed);
    if (!key) {
        return std::nullopt;
    }

    UniquePkeyCtx ctx(EVP_PKEY_CTX_new(key.get(), nullptr));
    if (!ctx) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessMlKem768SharedSecretSize> shared{};
    size_t shared_len = shared.size();
    if (EVP_PKEY_decapsulate(
            ctx.get(),
            shared.data(),
            &shared_len,
            ciphertext.data(),
            ciphertext.size()) != 1 ||
        shared_len != shared.size()) {
        return std::nullopt;
    }
    return shared;
}

}  // namespace acpp::vless
