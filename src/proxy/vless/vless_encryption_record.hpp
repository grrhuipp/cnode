#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <openssl/aead.h>

namespace acpp::vless {

inline constexpr size_t kVlessEncryptionLengthSize = 2;
inline constexpr size_t kVlessEncryptionRecordHeaderSize = 5;
inline constexpr size_t kVlessEncryptionNonceSize = 12;
inline constexpr size_t kVlessEncryptionTagSize = 16;
inline constexpr size_t kVlessEncryptionMaxPlaintextSize = 8192;
inline constexpr size_t kVlessEncryptionMinRecordCiphertextSize =
    1 + kVlessEncryptionTagSize;
inline constexpr size_t kVlessEncryptionMaxRecordCiphertextSize = 16640;
inline constexpr size_t kVlessEncryptionAeadKeySize = 32;

using VlessEncryptionNonce =
    std::array<uint8_t, kVlessEncryptionNonceSize>;

enum class VlessEncryptionAeadCipher : uint8_t {
    Aes256Gcm,
    Chacha20Poly1305,
};

[[nodiscard]] std::array<uint8_t, kVlessEncryptionLengthSize>
EncodeVlessEncryptionLength(size_t length) noexcept;

[[nodiscard]] uint16_t DecodeVlessEncryptionLength(
    std::span<const uint8_t, kVlessEncryptionLengthSize> encoded) noexcept;

[[nodiscard]] bool EncodeVlessEncryptionRecordHeader(
    std::span<uint8_t, kVlessEncryptionRecordHeaderSize> header,
    size_t ciphertext_length) noexcept;

[[nodiscard]] std::optional<uint16_t> DecodeVlessEncryptionRecordHeader(
    std::span<const uint8_t, kVlessEncryptionRecordHeaderSize> header) noexcept;

void IncreaseVlessEncryptionNonce(
    std::span<uint8_t, kVlessEncryptionNonceSize> nonce) noexcept;

[[nodiscard]] bool IsVlessEncryptionMaxNonce(
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce) noexcept;

class VlessEncryptionAead {
public:
    VlessEncryptionAead() noexcept { EVP_AEAD_CTX_zero(&aead_ctx_); }
    ~VlessEncryptionAead() noexcept {
        if (initialized_) {
            EVP_AEAD_CTX_cleanup(&aead_ctx_);
        }
    }

    VlessEncryptionAead(const VlessEncryptionAead&) = delete;
    VlessEncryptionAead& operator=(const VlessEncryptionAead&) = delete;

    VlessEncryptionAead(VlessEncryptionAead&& other) noexcept
        : nonce_(other.nonce_)
        , cipher_(other.cipher_) {
        EVP_AEAD_CTX_zero(&aead_ctx_);
        if (other.initialized_ && EVP_AEAD_CTX_copy(&aead_ctx_, &other.aead_ctx_) == 1) {
            initialized_ = true;
            EVP_AEAD_CTX_cleanup(&other.aead_ctx_);
            other.initialized_ = false;
        }
    }
    VlessEncryptionAead& operator=(VlessEncryptionAead&& other) noexcept {
        if (this != &other) {
            if (initialized_) {
                EVP_AEAD_CTX_cleanup(&aead_ctx_);
                initialized_ = false;
            }
            EVP_AEAD_CTX_zero(&aead_ctx_);
            nonce_ = other.nonce_;
            cipher_ = other.cipher_;
            if (other.initialized_ && EVP_AEAD_CTX_copy(&aead_ctx_, &other.aead_ctx_) == 1) {
                initialized_ = true;
                EVP_AEAD_CTX_cleanup(&other.aead_ctx_);
                other.initialized_ = false;
            }
        }
        return *this;
    }

    [[nodiscard]] static std::optional<VlessEncryptionAead> Create(
        std::span<const uint8_t> context,
        std::span<const uint8_t> key,
        VlessEncryptionAeadCipher cipher) noexcept;

    [[nodiscard]] std::optional<size_t> Seal(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> additional_data,
        std::span<uint8_t> output) noexcept;

    [[nodiscard]] std::optional<size_t> SealWithNonce(
        std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> additional_data,
        std::span<uint8_t> output) noexcept;

    [[nodiscard]] std::optional<size_t> Open(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> additional_data,
        std::span<uint8_t> output) noexcept;

    [[nodiscard]] std::optional<size_t> OpenWithNonce(
        std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> additional_data,
        std::span<uint8_t> output) noexcept;

    [[nodiscard]] const VlessEncryptionNonce& Nonce() const noexcept {
        return nonce_;
    }

    [[nodiscard]] VlessEncryptionAeadCipher Cipher() const noexcept {
        return cipher_;
    }

private:
    VlessEncryptionNonce nonce_{};
    VlessEncryptionAeadCipher cipher_ = VlessEncryptionAeadCipher::Aes256Gcm;
    EVP_AEAD_CTX aead_ctx_{};
    bool initialized_ = false;
};

[[nodiscard]] std::optional<size_t> SealVlessEncryptionRecord(
    VlessEncryptionAead& aead,
    std::span<const uint8_t> plaintext,
    std::span<uint8_t> output) noexcept;

[[nodiscard]] std::optional<size_t> OpenVlessEncryptionRecord(
    VlessEncryptionAead& aead,
    std::span<const uint8_t, kVlessEncryptionRecordHeaderSize> header,
    std::span<const uint8_t> ciphertext,
    std::span<uint8_t> output) noexcept;

}  // namespace acpp::vless
