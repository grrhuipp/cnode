#include "vless_encryption_record.hpp"

#include <blake3.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace acpp::vless {
namespace {

[[nodiscard]] const EVP_CIPHER* ResolveCipher(
    VlessEncryptionAeadCipher cipher) noexcept {
    switch (cipher) {
    case VlessEncryptionAeadCipher::Aes256Gcm:
        return EVP_aes_256_gcm();
    case VlessEncryptionAeadCipher::Chacha20Poly1305:
        return EVP_chacha20_poly1305();
    }
    return nullptr;
}

[[nodiscard]] bool FitsEvpInt(size_t value) noexcept {
    return value <= static_cast<size_t>(std::numeric_limits<int>::max());
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
    return out;
}

[[nodiscard]] bool AeadEncrypt(EVP_CIPHER_CTX* ctx,
                               const EVP_CIPHER* cipher,
                               std::span<const uint8_t> key,
                               std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
                               std::span<const uint8_t> plaintext,
                               std::span<const uint8_t> additional_data,
                               std::span<uint8_t> output) noexcept {
    if (!ctx || !cipher ||
        key.size() != kVlessEncryptionAeadKeySize ||
        output.size() < plaintext.size() + kVlessEncryptionTagSize ||
        !FitsEvpInt(plaintext.size()) ||
        !FitsEvpInt(additional_data.size())) {
        return false;
    }

    EVP_CIPHER_CTX_reset(ctx);
    int out_len = 0;
    int final_len = 0;

    if (EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_AEAD_SET_IVLEN,
            static_cast<int>(nonce.size()),
            nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        return false;
    }
    if (!additional_data.empty() &&
        EVP_EncryptUpdate(
            ctx,
            nullptr,
            &out_len,
            additional_data.data(),
            static_cast<int>(additional_data.size())) != 1) {
        return false;
    }
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(
            ctx,
            output.data(),
            &out_len,
            plaintext.data(),
            static_cast<int>(plaintext.size())) != 1) {
        return false;
    }
    if (EVP_EncryptFinal_ex(ctx, output.data() + out_len, &final_len) != 1) {
        return false;
    }
    out_len += final_len;
    return out_len == static_cast<int>(plaintext.size()) &&
           EVP_CIPHER_CTX_ctrl(
               ctx,
               EVP_CTRL_AEAD_GET_TAG,
               static_cast<int>(kVlessEncryptionTagSize),
               output.data() + out_len) == 1;
}

[[nodiscard]] std::optional<size_t> AeadDecrypt(
    EVP_CIPHER_CTX* ctx,
    const EVP_CIPHER* cipher,
    std::span<const uint8_t> key,
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    if (!ctx || !cipher ||
        key.size() != kVlessEncryptionAeadKeySize ||
        ciphertext.size() < kVlessEncryptionTagSize ||
        !FitsEvpInt(ciphertext.size() - kVlessEncryptionTagSize) ||
        !FitsEvpInt(additional_data.size())) {
        return std::nullopt;
    }
    const size_t plaintext_len = ciphertext.size() - kVlessEncryptionTagSize;
    if (output.size() < plaintext_len) {
        return std::nullopt;
    }

    EVP_CIPHER_CTX_reset(ctx);
    int out_len = 0;
    int final_len = 0;

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_AEAD_SET_IVLEN,
            static_cast<int>(nonce.size()),
            nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        return std::nullopt;
    }
    if (!additional_data.empty() &&
        EVP_DecryptUpdate(
            ctx,
            nullptr,
            &out_len,
            additional_data.data(),
            static_cast<int>(additional_data.size())) != 1) {
        return std::nullopt;
    }
    if (plaintext_len > 0 &&
        EVP_DecryptUpdate(
            ctx,
            output.data(),
            &out_len,
            ciphertext.data(),
            static_cast<int>(plaintext_len)) != 1) {
        return std::nullopt;
    }
    uint8_t final_dummy = 0;
    uint8_t* final_output = plaintext_len == 0
        ? &final_dummy
        : output.data() + out_len;
    if (EVP_CIPHER_CTX_ctrl(
            ctx,
            EVP_CTRL_AEAD_SET_TAG,
            static_cast<int>(kVlessEncryptionTagSize),
            const_cast<uint8_t*>(ciphertext.data() + plaintext_len)) != 1 ||
        EVP_DecryptFinal_ex(ctx, final_output, &final_len) != 1) {
        return std::nullopt;
    }

    out_len += final_len;
    if (out_len != static_cast<int>(plaintext_len)) {
        return std::nullopt;
    }
    return static_cast<size_t>(out_len);
}

}  // namespace

std::array<uint8_t, kVlessEncryptionLengthSize>
EncodeVlessEncryptionLength(size_t length) noexcept {
    return {
        static_cast<uint8_t>((length >> 8) & 0xffu),
        static_cast<uint8_t>(length & 0xffu),
    };
}

std::optional<uint16_t> DecodeVlessEncryptionLength(
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

VlessEncryptionAead::~VlessEncryptionAead() noexcept {
    Close();
}

VlessEncryptionAead::VlessEncryptionAead(
    VlessEncryptionAead&& other) noexcept
    : key_(other.key_)
    , nonce_(other.nonce_)
    , cipher_(other.cipher_)
    , enc_ctx_(std::exchange(other.enc_ctx_, nullptr))
    , dec_ctx_(std::exchange(other.dec_ctx_, nullptr)) {}

VlessEncryptionAead& VlessEncryptionAead::operator=(
    VlessEncryptionAead&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    Close();
    key_ = other.key_;
    nonce_ = other.nonce_;
    cipher_ = other.cipher_;
    enc_ctx_ = std::exchange(other.enc_ctx_, nullptr);
    dec_ctx_ = std::exchange(other.dec_ctx_, nullptr);
    return *this;
}

std::optional<VlessEncryptionAead> VlessEncryptionAead::Create(
    std::span<const uint8_t> context,
    std::span<const uint8_t> key,
    VlessEncryptionAeadCipher cipher) noexcept {
    if (!ResolveCipher(cipher)) {
        return std::nullopt;
    }

    VlessEncryptionAead aead;
    aead.key_ = DeriveAeadKey(context, key);
    aead.cipher_ = cipher;
    aead.enc_ctx_ = EVP_CIPHER_CTX_new();
    aead.dec_ctx_ = EVP_CIPHER_CTX_new();
    if (!aead.enc_ctx_ || !aead.dec_ctx_) {
        return std::nullopt;
    }
    return aead;
}

std::optional<size_t> VlessEncryptionAead::Seal(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    IncreaseVlessEncryptionNonce(nonce_);
    return SealWithNonce(nonce_, plaintext, additional_data, output);
}

std::optional<size_t> VlessEncryptionAead::SealWithNonce(
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    const EVP_CIPHER* cipher = ResolveCipher(cipher_);
    if (!AeadEncrypt(
            static_cast<EVP_CIPHER_CTX*>(enc_ctx_),
            cipher,
            key_,
            nonce,
            plaintext,
            additional_data,
            output)) {
        return std::nullopt;
    }
    return plaintext.size() + kVlessEncryptionTagSize;
}

std::optional<size_t> VlessEncryptionAead::Open(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    IncreaseVlessEncryptionNonce(nonce_);
    return OpenWithNonce(nonce_, ciphertext, additional_data, output);
}

std::optional<size_t> VlessEncryptionAead::OpenWithNonce(
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    return AeadDecrypt(
        static_cast<EVP_CIPHER_CTX*>(dec_ctx_),
        ResolveCipher(cipher_),
        key_,
        nonce,
        ciphertext,
        additional_data,
        output);
}

void VlessEncryptionAead::Close() noexcept {
    if (enc_ctx_) {
        EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(enc_ctx_));
        enc_ctx_ = nullptr;
    }
    if (dec_ctx_) {
        EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(dec_ctx_));
        dec_ctx_ = nullptr;
    }
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

}  // namespace acpp::vless
