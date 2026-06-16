#include "vless_encryption_xor.hpp"

#include <blake3.h>
#include <openssl/evp.h>

#include <algorithm>
#include <limits>
#include <utility>

namespace acpp::vless {
namespace {

constexpr char kVlessCtrContext[] = "VLESS";

[[nodiscard]] bool FitsEvpInt(size_t value) noexcept {
    return value <= static_cast<size_t>(std::numeric_limits<int>::max());
}

}  // namespace

VlessEncryptionCtr::~VlessEncryptionCtr() noexcept {
    Close();
}

VlessEncryptionCtr::VlessEncryptionCtr(
    VlessEncryptionCtr&& other) noexcept
    : ctx_(std::exchange(other.ctx_, nullptr)) {}

VlessEncryptionCtr& VlessEncryptionCtr::operator=(
    VlessEncryptionCtr&& other) noexcept {
    if (this == &other) {
        return *this;
    }
    Close();
    ctx_ = std::exchange(other.ctx_, nullptr);
    return *this;
}

std::optional<VlessEncryptionCtr> VlessEncryptionCtr::Create(
    std::span<const uint8_t> key,
    std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv) noexcept {
    auto derived = DeriveVlessEncryptionCtrKey(key);
    if (!derived) {
        return std::nullopt;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return std::nullopt;
    }
    if (EVP_EncryptInit_ex(
            ctx,
            EVP_aes_256_ctr(),
            nullptr,
            derived->data(),
            iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    return VlessEncryptionCtr(ctx);
}

bool VlessEncryptionCtr::XorInPlace(std::span<uint8_t> data) noexcept {
    if (data.empty()) {
        return true;
    }
    return Xor(data, data);
}

bool VlessEncryptionCtr::Xor(std::span<const uint8_t> input,
                             std::span<uint8_t> output) noexcept {
    if (!ctx_ || output.size() < input.size() || !FitsEvpInt(input.size())) {
        return false;
    }
    if (input.empty()) {
        return true;
    }

    int out_len = 0;
    return EVP_EncryptUpdate(
               static_cast<EVP_CIPHER_CTX*>(ctx_),
               output.data(),
               &out_len,
               input.data(),
               static_cast<int>(input.size())) == 1 &&
           out_len == static_cast<int>(input.size());
}

void VlessEncryptionCtr::Close() noexcept {
    if (ctx_) {
        EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX*>(ctx_));
        ctx_ = nullptr;
    }
}

std::optional<std::array<uint8_t, kVlessEncryptionCtrKeySize>>
DeriveVlessEncryptionCtrKey(std::span<const uint8_t> key) noexcept {
    std::array<uint8_t, kVlessEncryptionCtrKeySize> out{};
    blake3_hasher hasher;
    blake3_hasher_init_derive_key(&hasher, kVlessCtrContext);
    if (!key.empty()) {
        blake3_hasher_update(&hasher, key.data(), key.size());
    }
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    return out;
}

bool XorVlessEncryptionInPlace(
    std::span<const uint8_t> key,
    std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv,
    std::span<uint8_t> data) noexcept {
    auto ctr = VlessEncryptionCtr::Create(key, iv);
    return ctr && ctr->XorInPlace(data);
}

std::optional<VlessEncryptionHeaderXor> VlessEncryptionHeaderXor::Create(
    std::span<const uint8_t> key,
    std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv,
    size_t initial_skip) noexcept {
    auto ctr = VlessEncryptionCtr::Create(key, iv);
    if (!ctr) {
        return std::nullopt;
    }
    return VlessEncryptionHeaderXor(std::move(*ctr), initial_skip);
}

VlessEncryptionHeaderXor::VlessEncryptionHeaderXor(
    VlessEncryptionCtr ctr,
    size_t initial_skip) noexcept
    : ctr_(std::move(ctr))
    , skip_(initial_skip) {}

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

}  // namespace acpp::vless
