#include "proxy/vless/vless_encryption.hpp"
#include "common/byte_reader.hpp"
#include "common/scoped_cleanse.hpp"

#include <blake3.h>
#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <utility>
namespace proxy {

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

SharedEvpPkey
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
    return SharedEvpPkey{std::move(key)};
}

SharedEvpPkey
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
    return SharedEvpPkey{std::move(key)};
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

// ============================================================================
// AEAD Record Framing
// ============================================================================

namespace {

[[nodiscard]] const EVP_AEAD* ResolveAead(
    VlessEncryptionAeadCipher cipher) noexcept {
    switch (cipher) {
    case VlessEncryptionAeadCipher::Aes256Gcm:
        return EVP_aead_aes_256_gcm();
    case VlessEncryptionAeadCipher::Chacha20Poly1305:
        return EVP_aead_chacha20_poly1305();
    }
    return nullptr;
}

[[nodiscard]] std::array<uint8_t, kVlessEncryptionAeadKeySize>
DeriveAeadKey(std::span<const uint8_t> context,
              std::span<const uint8_t> key) noexcept {
    std::array<uint8_t, kVlessEncryptionAeadKeySize> out{};
    blake3_hasher hasher;
    blake3_hasher_init_derive_key_raw(
        &hasher,
        context.empty() ? nullptr : context.data(),
        context.size());
    if (!key.empty()) {
        blake3_hasher_update(&hasher, key.data(), key.size());
    }
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    OPENSSL_cleanse(&hasher, sizeof(hasher));
    return out;
}

}  // namespace

std::array<uint8_t, kVlessEncryptionLengthSize>
EncodeVlessEncryptionLength(size_t length) noexcept {
    return {
        static_cast<uint8_t>((length >> 8) & 0xffu),
        static_cast<uint8_t>(length & 0xffu),
    };
}

uint16_t DecodeVlessEncryptionLength(
    std::span<const uint8_t, kVlessEncryptionLengthSize> encoded) noexcept {
    return common::LoadU16BE(encoded.data());
}

bool EncodeVlessEncryptionRecordHeader(
    std::span<uint8_t, kVlessEncryptionRecordHeaderSize> header,
    size_t ciphertext_length) noexcept {
    if (ciphertext_length < kVlessEncryptionMinRecordCiphertextSize ||
        ciphertext_length > kVlessEncryptionMaxRecordCiphertextSize) {
        return false;
    }
    header[0] = 23;
    header[1] = 3;
    header[2] = 3;
    header[3] = static_cast<uint8_t>((ciphertext_length >> 8) & 0xffu);
    header[4] = static_cast<uint8_t>(ciphertext_length & 0xffu);
    return true;
}

std::optional<uint16_t> DecodeVlessEncryptionRecordHeader(
    std::span<const uint8_t, kVlessEncryptionRecordHeaderSize> header) noexcept {
    const uint16_t length = common::LoadU16BE(&header[3]);
    if (header[0] != 23 || header[1] != 3 || header[2] != 3 ||
        length < kVlessEncryptionMinRecordCiphertextSize ||
        length > kVlessEncryptionMaxRecordCiphertextSize) {
        return std::nullopt;
    }
    return length;
}

void IncreaseVlessEncryptionNonce(
    std::span<uint8_t, kVlessEncryptionNonceSize> nonce) noexcept {
    for (size_t i = 0; i < nonce.size(); ++i) {
        uint8_t& value = nonce[nonce.size() - 1 - i];
        ++value;
        if (value != 0) {
            break;
        }
    }
}

bool IsVlessEncryptionMaxNonce(
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce) noexcept {
    return std::ranges::all_of(nonce, [](uint8_t value) {
        return value == 0xffu;
    });
}

std::optional<VlessEncryptionAead> VlessEncryptionAead::Create(
    std::span<const uint8_t> context,
    std::span<const uint8_t> key,
    VlessEncryptionAeadCipher cipher) noexcept {
    const EVP_AEAD* algorithm = ResolveAead(cipher);
    if (!algorithm) {
        return std::nullopt;
    }

    VlessEncryptionAead aead;
    auto derived = DeriveAeadKey(context, key);
    aead.cipher_ = cipher;
    bool ready = false;
    try {
        ready = aead.aead_.Configure(algorithm, derived);
    } catch (const std::bad_alloc&) {
        ready = false;
    }
    OPENSSL_cleanse(derived.data(), derived.size());
    if (!ready) return std::nullopt;
    return aead;
}

std::optional<size_t> VlessEncryptionAead::Seal(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    if (output.size() < kVlessEncryptionTagSize ||
        output.size() - kVlessEncryptionTagSize < plaintext.size()) {
        return std::nullopt;
    }
    IncreaseVlessEncryptionNonce(nonce_);
    return SealWithNonce(nonce_, plaintext, additional_data, output);
}

std::optional<size_t> VlessEncryptionAead::SealWithNonce(
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    return aead_.Seal(nonce, plaintext, additional_data, output);
}

std::optional<size_t> VlessEncryptionAead::Open(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    if (ciphertext.size() < kVlessEncryptionTagSize ||
        output.size() < ciphertext.size() - kVlessEncryptionTagSize) {
        return std::nullopt;
    }
    IncreaseVlessEncryptionNonce(nonce_);
    return OpenWithNonce(nonce_, ciphertext, additional_data, output);
}

std::optional<size_t> VlessEncryptionAead::OpenWithNonce(
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    return aead_.Open(nonce, ciphertext, additional_data, output);
}

std::optional<size_t> SealVlessEncryptionRecord(
    VlessEncryptionAead& aead,
    std::span<const uint8_t> plaintext,
    std::span<uint8_t> output) noexcept {
    if (plaintext.empty() ||
        plaintext.size() > kVlessEncryptionMaxPlaintextSize ||
        output.size() <
            kVlessEncryptionRecordHeaderSize + plaintext.size() +
                kVlessEncryptionTagSize) {
        return std::nullopt;
    }

    auto header = std::span<uint8_t, kVlessEncryptionRecordHeaderSize>(
        output.data(),
        kVlessEncryptionRecordHeaderSize);
    const size_t ciphertext_length = plaintext.size() + kVlessEncryptionTagSize;
    if (!EncodeVlessEncryptionRecordHeader(header, ciphertext_length)) {
        return std::nullopt;
    }

    auto ciphertext = output.subspan(kVlessEncryptionRecordHeaderSize);
    auto sealed = aead.Seal(plaintext, header, ciphertext);
    if (!sealed || *sealed != ciphertext_length) {
        return std::nullopt;
    }
    return kVlessEncryptionRecordHeaderSize + ciphertext_length;
}

std::optional<size_t> OpenVlessEncryptionRecord(
    VlessEncryptionAead& aead,
    std::span<const uint8_t, kVlessEncryptionRecordHeaderSize> header,
    std::span<const uint8_t> ciphertext,
    std::span<uint8_t> output) noexcept {
    const auto length = DecodeVlessEncryptionRecordHeader(header);
    if (!length || ciphertext.size() != *length) {
        return std::nullopt;
    }
    return aead.Open(ciphertext, header, output);
}

// ============================================================================
// AES-256-CTR Header / Relay XOR
// ============================================================================

namespace {

constexpr char kVlessCtrContext[] = "VLESS";
constexpr size_t kVlessEncryptionCtrKeySize = 32;

using CtrKey = std::array<uint8_t, kVlessEncryptionCtrKeySize>;

[[nodiscard]] bool FitsEvpInt(size_t value) noexcept {
    return value <= static_cast<size_t>(std::numeric_limits<int>::max());
}

[[nodiscard]] CtrKey DeriveCtrKey(std::span<const uint8_t> key) noexcept {
    CtrKey out{};
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, kVlessCtrContext);
    if (!key.empty()) {
        blake3_hasher_update(&hasher, key.data(), key.size());
    }
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    OPENSSL_cleanse(&hasher, sizeof(hasher));
    return out;
}

[[nodiscard]] bool InitCtr(EVP_CIPHER_CTX* ctx,
                           std::span<const uint8_t> key,
                           std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv) noexcept {
    auto derived = DeriveCtrKey(key);
    const bool ok = EVP_EncryptInit_ex(
                        ctx,
                        EVP_aes_256_ctr(),
                        nullptr,
                        derived.data(),
                        iv.data()) == 1;
    OPENSSL_cleanse(derived.data(), derived.size());
    if (!ok) {
        ERR_clear_error();
    }
    return ok;
}

[[nodiscard]] bool CtrXorInPlace(EVP_CIPHER_CTX* ctx,
                                 std::span<uint8_t> data) noexcept {
    if (!FitsEvpInt(data.size())) {
        return false;
    }
    if (data.empty()) {
        return true;
    }
    int out_len = 0;
    if (EVP_EncryptUpdate(
            ctx,
            data.data(),
            &out_len,
            data.data(),
            static_cast<int>(data.size())) != 1 ||
        out_len != static_cast<int>(data.size())) {
        ERR_clear_error();
        return false;
    }
    return true;
}

}  // namespace

std::optional<VlessEncryptionCtr> VlessEncryptionCtr::Create(
    std::span<const uint8_t> key,
    std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv) noexcept {
    bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        ERR_clear_error();
        return std::nullopt;
    }
    if (!InitCtr(ctx.get(), key, iv)) {
        return std::nullopt;
    }
    return VlessEncryptionCtr(std::move(ctx));
}

bool VlessEncryptionCtr::XorInPlace(std::span<uint8_t> data) noexcept {
    return CtrXorInPlace(ctx_.get(), data);
}

bool XorVlessEncryptionInPlace(
    std::span<const uint8_t> key,
    std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv,
    std::span<uint8_t> data) noexcept {
    if (data.empty()) {
        return true;
    }
    thread_local bssl::UniquePtr<EVP_CIPHER_CTX> tls_ctx;
    if (!tls_ctx) {
        tls_ctx.reset(EVP_CIPHER_CTX_new());
        if (!tls_ctx) {
            ERR_clear_error();
            return false;
        }
    }
    const bool ok = InitCtr(tls_ctx.get(), key, iv) &&
                    CtrXorInPlace(tls_ctx.get(), data);
    EVP_CIPHER_CTX_reset(tls_ctx.get());
    return ok;
}

std::optional<VlessEncryptionHeaderXor> VlessEncryptionHeaderXor::Create(
    std::span<const uint8_t> key,
    std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv) noexcept {
    auto ctr = VlessEncryptionCtr::Create(key, iv);
    if (!ctr) {
        return std::nullopt;
    }
    return VlessEncryptionHeaderXor(std::move(*ctr));
}

bool VlessEncryptionHeaderXor::XorOutboundInPlace(
    std::span<uint8_t> data) noexcept {
    return Transform(data, false);
}

bool VlessEncryptionHeaderXor::XorInboundInPlace(
    std::span<uint8_t> data) noexcept {
    return Transform(data, true);
}

bool VlessEncryptionHeaderXor::Transform(std::span<uint8_t> data,
                                         bool inbound) noexcept {
    while (!data.empty()) {
        if (skip_ > 0) {
            const size_t n = std::min(skip_, data.size());
            skip_ -= n;
            data = data.subspan(n);
            continue;
        }

        const size_t need = header_.size() - header_len_;
        const size_t n = std::min(need, data.size());
        auto header_part = data.first(n);
        // The record length is read from the plaintext header in both
        // directions, so copy after unmasking inbound and before masking
        // outbound.
        if (inbound && !ctr_.XorInPlace(header_part)) {
            return false;
        }
        std::copy(
            header_part.begin(),
            header_part.end(),
            header_.begin() + static_cast<std::ptrdiff_t>(header_len_));
        if (!inbound && !ctr_.XorInPlace(header_part)) {
            return false;
        }

        header_len_ += n;
        data = data.subspan(n);
        if (header_len_ < header_.size()) {
            continue;
        }
        if (!FinishHeader()) {
            return false;
        }
    }
    return true;
}

bool VlessEncryptionHeaderXor::FinishHeader() noexcept {
    auto length = DecodeVlessEncryptionRecordHeader(header_);
    if (!length) {
        return false;
    }
    skip_ = *length;
    header_len_ = 0;
    return true;
}

// ============================================================================
// Handshake Protocol
// ============================================================================
}  // namespace proxy
