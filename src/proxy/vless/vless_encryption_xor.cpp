#include "vless_encryption_xor.hpp"

#include <blake3.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>

#include <algorithm>
#include <limits>
#include <utility>
namespace vless {
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

}  // namespace vless
