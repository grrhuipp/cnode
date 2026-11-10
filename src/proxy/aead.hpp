#pragma once

#include <openssl/aead.h>
#include <openssl/mem.h>

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
    bssl::UniquePtr<EVP_AEAD_CTX> ctx_;
    bool ready_ = false;
};

using AeadEncryptor = AeadContext<AeadDirection::Encrypt>;
using AeadDecryptor = AeadContext<AeadDirection::Decrypt>;

// Stack-owned single-operation AEAD context. EVP_AEAD_CTX_init accepts
// uninitialized storage (and zeroes it even on failure), while the destructor
// guarantees cleanup and cleanse after each one-shot operation.
struct ScopedAeadCtx {
    EVP_AEAD_CTX ctx;
    ScopedAeadCtx() noexcept = default;
    ScopedAeadCtx(const ScopedAeadCtx&) = delete;
    ScopedAeadCtx& operator=(const ScopedAeadCtx&) = delete;
    ~ScopedAeadCtx() noexcept {
        EVP_AEAD_CTX_cleanup(&ctx);
        OPENSSL_cleanse(&ctx, sizeof(ctx));
    }
};

[[nodiscard]] inline bool SealOneShotAead(
    const EVP_AEAD* cipher,
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    std::span<uint8_t> output,
    size_t tag_size = 16) noexcept {
    if (!cipher || output.size() < tag_size || output.size() - tag_size < plaintext.size()) {
        return false;
    }
    ScopedAeadCtx aead;
    size_t written = 0;
    const size_t expected = plaintext.size() + tag_size;
    return EVP_AEAD_CTX_init(&aead.ctx, cipher, key.data(), key.size(),
                             tag_size, nullptr) == 1 &&
           EVP_AEAD_CTX_seal(&aead.ctx, output.data(), &written, output.size(),
                             nonce.data(), nonce.size(),
                             plaintext.data(), plaintext.size(),
                             aad.data(), aad.size()) == 1 &&
           written == expected;
}

[[nodiscard]] inline bool SealScatterOneShotAead(
    const EVP_AEAD* cipher,
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    uint8_t* ciphertext,
    std::span<uint8_t> tag) noexcept {
    if (!cipher || tag.empty()) {
        return false;
    }
    ScopedAeadCtx aead;
    size_t tag_len = 0;
    return EVP_AEAD_CTX_init(&aead.ctx, cipher, key.data(), key.size(),
                             tag.size(), nullptr) == 1 &&
           EVP_AEAD_CTX_seal_scatter(&aead.ctx, ciphertext,
                                     tag.data(), &tag_len, tag.size(),
                                     nonce.data(), nonce.size(),
                                     plaintext.data(), plaintext.size(),
                                     nullptr, 0,
                                     aad.data(), aad.size()) == 1 &&
           tag_len == tag.size();
}

[[nodiscard]] inline bool OpenOneShotAead(
    const EVP_AEAD* cipher,
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> aad,
    std::span<uint8_t> output,
    size_t& out_len,
    size_t tag_size = 16) noexcept {
    out_len = 0;
    if (!cipher || ciphertext.size() < tag_size ||
        output.size() < ciphertext.size() - tag_size) {
        return false;
    }
    ScopedAeadCtx aead;
    size_t written = 0;
    if (EVP_AEAD_CTX_init(&aead.ctx, cipher, key.data(), key.size(),
                          tag_size, nullptr) != 1 ||
        EVP_AEAD_CTX_open(&aead.ctx, output.data(), &written, output.size(),
                          nonce.data(), nonce.size(),
                          ciphertext.data(), ciphertext.size(),
                          aad.data(), aad.size()) != 1) {
        return false;
    }
    out_len = written;
    return true;
}

} // namespace proxy
