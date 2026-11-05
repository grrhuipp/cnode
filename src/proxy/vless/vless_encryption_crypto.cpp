#include "vless_encryption_crypto.hpp"

#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/experimental/kem_deterministic_api.h>
#include <openssl/nid.h>

#include <memory>

namespace acpp::vless {
namespace {

[[nodiscard]] bssl::UniquePtr<EVP_PKEY_CTX> NewMlKem768KeygenContext() noexcept {
    bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_KEM, nullptr));
    if (!ctx ||
        EVP_PKEY_keygen_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_kem_set_params(ctx.get(), NID_MLKEM768) != 1) {
        return {};
    }
    return ctx;
}

[[nodiscard]] std::shared_ptr<EVP_PKEY> ShareKey(
    bssl::UniquePtr<EVP_PKEY> key) noexcept {
    if (!key) {
        return nullptr;
    }
    return std::shared_ptr<EVP_PKEY>(key.release(), EVP_PKEY_free);
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
    auto ctx = NewMlKem768KeygenContext();
    if (!ctx) {
        return nullptr;
    }
    EVP_PKEY* raw = nullptr;
    size_t seed_len = seed.size();
    if (EVP_PKEY_keygen_deterministic(
            ctx.get(),
            &raw,
            seed.data(),
            &seed_len) != 1) {
        EVP_PKEY_free(raw);
        return nullptr;
    }
    return ShareKey(bssl::UniquePtr<EVP_PKEY>(raw));
}

std::shared_ptr<EVP_PKEY>
CreateVlessMlKem768PublicKey(
    std::span<const uint8_t> public_key) noexcept {
    if (public_key.size() != kVlessMlKem768PublicKeySize) {
        return nullptr;
    }
    return ShareKey(bssl::UniquePtr<EVP_PKEY>(EVP_PKEY_kem_new_raw_public_key(
        NID_MLKEM768,
        public_key.data(),
        public_key.size())));
}

bssl::UniquePtr<EVP_PKEY> GenerateVlessMlKem768PrivateKey() noexcept {
    auto ctx = NewMlKem768KeygenContext();
    if (!ctx) {
        return {};
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
        EVP_PKEY_free(raw);
        return {};
    }
    return bssl::UniquePtr<EVP_PKEY>(raw);
}

std::optional<std::array<uint8_t, kVlessMlKem768PublicKeySize>>
DeriveVlessMlKem768PublicKey(const EVP_PKEY* key) noexcept {
    if (!key) {
        return std::nullopt;
    }

    size_t public_len = 0;
    if (EVP_PKEY_get_raw_public_key(key, nullptr, &public_len) != 1 ||
        public_len != kVlessMlKem768PublicKeySize) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessMlKem768PublicKeySize> public_key{};
    public_len = public_key.size();
    if (EVP_PKEY_get_raw_public_key(
            key,
            public_key.data(),
            &public_len) != 1 ||
        public_len != public_key.size()) {
        return std::nullopt;
    }
    return public_key;
}

std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(EVP_PKEY* public_key) noexcept {
    if (!public_key) {
        return std::nullopt;
    }

    bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(public_key, nullptr));
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
    shared_len = result.shared_secret.bytes.size();
    if (EVP_PKEY_encapsulate(
            ctx.get(),
            result.ciphertext.data(),
            &ciphertext_len,
            result.shared_secret.bytes.data(),
            &shared_len) != 1 ||
        ciphertext_len != result.ciphertext.size() ||
        shared_len != result.shared_secret.bytes.size()) {
        return std::nullopt;
    }
    return result;
}

std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(std::span<const uint8_t> public_key) noexcept {
    if (public_key.size() != kVlessMlKem768PublicKeySize) {
        return std::nullopt;
    }

    bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_kem_new_raw_public_key(
        NID_MLKEM768,
        public_key.data(),
        public_key.size()));
    return EncapsulateVlessMlKem768(key.get());
}

bool DecapsulateVlessMlKem768(
    EVP_PKEY* private_key,
    std::span<const uint8_t> ciphertext,
    std::span<uint8_t, kVlessMlKem768SharedSecretSize> out_shared) noexcept {
    if (!private_key || ciphertext.size() != kVlessMlKem768CiphertextSize) {
        return false;
    }

    bssl::UniquePtr<EVP_PKEY_CTX> ctx(EVP_PKEY_CTX_new(private_key, nullptr));
    if (!ctx) {
        return false;
    }

    size_t shared_len = out_shared.size();
    return EVP_PKEY_decapsulate(
               ctx.get(),
               out_shared.data(),
               &shared_len,
               ciphertext.data(),
               ciphertext.size()) == 1 &&
           shared_len == out_shared.size();
}

}  // namespace acpp::vless
