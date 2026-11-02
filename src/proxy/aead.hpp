#pragma once

#include <openssl/evp.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <utility>

namespace acpp::proxy {

enum class AeadDirection { Encrypt, Decrypt };

// Own the EVP algorithm/key schedule once. Each record reinitializes only its
// nonce; no reset or key copy is needed between records, including failed opens.
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

    bool Configure(const EVP_CIPHER* cipher, std::span<const uint8_t> key) {
        ready_ = false;
        if (!cipher || key.size() != static_cast<size_t>(EVP_CIPHER_key_length(cipher))) return false;
        if (!ctx_) {
            ctx_.reset(EVP_CIPHER_CTX_new());
            if (!ctx_) throw std::bad_alloc();
            cipher_ = nullptr;
        }
        constexpr int encrypt = Direction == AeadDirection::Encrypt;
        // A trial authenticator can replace the key while retaining its context
        // and algorithm allocation. Record processing never calls Configure.
        const auto* initialization_cipher = cipher_ == cipher ? nullptr : cipher;
        cipher_ = nullptr;
        if (EVP_CipherInit_ex(ctx_.get(), initialization_cipher,
                              nullptr, key.data(), nullptr, encrypt) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_AEAD_SET_IVLEN, kNonceSize, nullptr) != 1) return false;
        cipher_ = cipher;
        ready_ = true;
        return true;
    }

    bool Begin(std::span<const uint8_t, kNonceSize> nonce,
               std::span<const uint8_t> aad = {}) noexcept {
        if (!ready_ || !ctx_ || aad.size() > INT_MAX ||
            EVP_CipherInit_ex(ctx_.get(), nullptr, nullptr, nullptr, nonce.data(), -1) != 1) return false;
        if (!aad.empty()) {
            int written = 0;
            if (EVP_CipherUpdate(ctx_.get(), nullptr, &written, aad.data(), static_cast<int>(aad.size())) != 1) return false;
        }
        return true;
    }

    bool Update(std::span<const uint8_t> input, std::span<uint8_t> output) noexcept {
        if (!ready_ || !ctx_ || input.size() > INT_MAX || output.size() < input.size()) return false;
        if (input.empty()) return true; // Null input is EVP's finalization signal.
        int written = 0;
        return EVP_CipherUpdate(ctx_.get(), output.data(), &written, input.data(),
                                static_cast<int>(input.size())) == 1 &&
            written >= 0 && static_cast<size_t>(written) == input.size();
    }

    bool Finish(std::span<uint8_t, kTagSize> tag) noexcept
        requires (Direction == AeadDirection::Encrypt) {
        uint8_t final[EVP_MAX_BLOCK_LENGTH];
        int written = 0;
        return ready_ && ctx_ && EVP_EncryptFinal_ex(ctx_.get(), final, &written) == 1 && written == 0 &&
            EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_AEAD_GET_TAG, kTagSize, tag.data()) == 1;
    }

    bool Finish(std::span<const uint8_t, kTagSize> tag) noexcept
        requires (Direction == AeadDirection::Decrypt) {
        uint8_t final[EVP_MAX_BLOCK_LENGTH];
        int written = 0;
        return ready_ && ctx_ && EVP_CIPHER_CTX_ctrl(ctx_.get(), EVP_CTRL_AEAD_SET_TAG, kTagSize,
                                           const_cast<uint8_t*>(tag.data())) == 1 &&
            EVP_DecryptFinal_ex(ctx_.get(), final, &written) == 1 && written == 0;
    }

    std::optional<size_t> Process(std::span<const uint8_t, kNonceSize> nonce,
                                 std::span<const uint8_t> input,
                                 std::span<const uint8_t> aad,
                                 std::span<uint8_t> output) noexcept {
        if constexpr (Direction == AeadDirection::Encrypt) {
            if (input.size() > INT_MAX || output.size() < kTagSize ||
                output.size() - kTagSize < input.size() || !Begin(nonce, aad) || !Update(input, output) ||
                !Finish(std::span<uint8_t, kTagSize>(output.data() + input.size(), kTagSize))) return std::nullopt;
            return input.size() + kTagSize;
        } else {
            if (input.size() < kTagSize) return std::nullopt;
            const size_t size = input.size() - kTagSize;
            if (output.size() < size || !Begin(nonce, aad) || !Update(input.first(size), output) ||
                !Finish(std::span<const uint8_t, kTagSize>(input.data() + size, kTagSize))) return std::nullopt;
            return size;
        }
    }

private:
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx_{nullptr, EVP_CIPHER_CTX_free};
    const EVP_CIPHER* cipher_ = nullptr;
    bool ready_ = false;
};

using AeadEncryptor = AeadContext<AeadDirection::Encrypt>;
using AeadDecryptor = AeadContext<AeadDirection::Decrypt>;

} // namespace acpp::proxy
