#include "vless_encryption_record.hpp"

#include <blake3.h>
#include <openssl/aead.h>
#include <openssl/err.h>
#include <openssl/mem.h>

#include <algorithm>

namespace vless {
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
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(encoded[0]) << 8) |
        static_cast<uint16_t>(encoded[1]));
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
    const auto length = static_cast<uint16_t>(
        (static_cast<uint16_t>(header[3]) << 8) |
        static_cast<uint16_t>(header[4]));
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
    aead.aead_ctx_.reset(EVP_AEAD_CTX_new(
        algorithm, derived.data(), derived.size(), kVlessEncryptionTagSize));
    OPENSSL_cleanse(derived.data(), derived.size());
    if (!aead.aead_ctx_) {
        ERR_clear_error();
        return std::nullopt;
    }
    return aead;
}

std::optional<size_t> VlessEncryptionAead::Seal(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    if (!aead_ctx_ || output.size() < kVlessEncryptionTagSize ||
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
    if (!aead_ctx_ || output.size() < kVlessEncryptionTagSize ||
        output.size() - kVlessEncryptionTagSize < plaintext.size()) {
        return std::nullopt;
    }
    size_t out_len = 0;
    if (EVP_AEAD_CTX_seal(
            aead_ctx_.get(),
            output.data(),
            &out_len,
            output.size(),
            nonce.data(),
            nonce.size(),
            plaintext.data(),
            plaintext.size(),
            additional_data.data(),
            additional_data.size()) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }
    return out_len;
}

std::optional<size_t> VlessEncryptionAead::Open(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    if (!aead_ctx_ || ciphertext.size() < kVlessEncryptionTagSize ||
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
    if (!aead_ctx_ || ciphertext.size() < kVlessEncryptionTagSize ||
        output.size() < ciphertext.size() - kVlessEncryptionTagSize) {
        return std::nullopt;
    }
    size_t out_len = 0;
    if (EVP_AEAD_CTX_open(
            aead_ctx_.get(),
            output.data(),
            &out_len,
            output.size(),
            nonce.data(),
            nonce.size(),
            ciphertext.data(),
            ciphertext.size(),
            additional_data.data(),
            additional_data.size()) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }
    return out_len;
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

}  // namespace vless
