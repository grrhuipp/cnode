#pragma once

#include <openssl/aead.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <span>

namespace proxy {

enum class AeadDirection { Encrypt, Decrypt };

// The key schedule is prepared once; records use BoringSSL's atomic AEAD API.
// Callers retain ciphertext until the whole record is available and publish
// plaintext only after authentication succeeds.
template<AeadDirection Direction>
class AeadContext {
public:
    static constexpr size_t kNonceSize = 12;
    static constexpr size_t kTagSize = 16;

    AeadContext() noexcept = default;
    AeadContext(const AeadContext&) = delete;
    AeadContext& operator=(const AeadContext&) = delete;
    AeadContext(AeadContext&&) noexcept = default;
    AeadContext& operator=(AeadContext&&) noexcept = default;

    bool Configure(const EVP_AEAD* cipher, std::span<const uint8_t> key) {
        ready_ = false;
        if (!cipher || key.size() != EVP_AEAD_key_length(cipher) ||
            EVP_AEAD_nonce_length(cipher) != kNonceSize) return false;
        if (!ctx_) {
            ctx_.reset(EVP_AEAD_CTX_new(cipher, key.data(), key.size(), kTagSize));
            if (!ctx_) throw std::bad_alloc();
        } else {
            // Authentication trials replace the key without reallocating the context.
            EVP_AEAD_CTX_cleanup(ctx_.get());
            EVP_AEAD_CTX_zero(ctx_.get());
            if (EVP_AEAD_CTX_init(ctx_.get(), cipher, key.data(), key.size(),
                                  kTagSize, nullptr) != 1) return false;
        }
        ready_ = true;
        return true;
    }

    std::optional<size_t> Process(std::span<const uint8_t, kNonceSize> nonce,
                                 std::span<const uint8_t> input,
                                 std::span<const uint8_t> aad,
                                 std::span<uint8_t> output) noexcept {
        if (!ready_ || !ctx_ || input.size() > INT_MAX || aad.size() > INT_MAX)
            return std::nullopt;
        size_t written = 0;
        if constexpr (Direction == AeadDirection::Encrypt) {
            if (output.size() < kTagSize || output.size() - kTagSize < input.size() ||
                EVP_AEAD_CTX_seal(ctx_.get(), output.data(), &written, output.size(),
                                  nonce.data(), nonce.size(), input.data(), input.size(),
                                  aad.data(), aad.size()) != 1) return std::nullopt;
        } else {
            if (input.size() < kTagSize || output.size() < input.size() - kTagSize ||
                EVP_AEAD_CTX_open(ctx_.get(), output.data(), &written, output.size(),
                                  nonce.data(), nonce.size(), input.data(), input.size(),
                                  aad.data(), aad.size()) != 1) return std::nullopt;
        }
        return written;
    }

private:
    std::unique_ptr<EVP_AEAD_CTX, decltype(&EVP_AEAD_CTX_free)> ctx_{nullptr, EVP_AEAD_CTX_free};
    bool ready_ = false;
};

using AeadEncryptor = AeadContext<AeadDirection::Encrypt>;
using AeadDecryptor = AeadContext<AeadDirection::Decrypt>;

} // namespace proxy
