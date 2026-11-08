#pragma once

#include "vless_encryption_record.hpp"

#include <openssl/cipher.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace vless {

inline constexpr size_t kVlessEncryptionCtrIvSize = 16;

class VlessEncryptionCtr {
public:
    [[nodiscard]] static std::optional<VlessEncryptionCtr> Create(
        std::span<const uint8_t> key,
        std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv) noexcept;

    [[nodiscard]] bool XorInPlace(std::span<uint8_t> data) noexcept;

private:
    explicit VlessEncryptionCtr(bssl::UniquePtr<EVP_CIPHER_CTX> ctx) noexcept
        : ctx_(std::move(ctx)) {}

    bssl::UniquePtr<EVP_CIPHER_CTX> ctx_;
};

[[nodiscard]] bool XorVlessEncryptionInPlace(
    std::span<const uint8_t> key,
    std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv,
    std::span<uint8_t> data) noexcept;

class VlessEncryptionHeaderXor {
public:
    [[nodiscard]] static std::optional<VlessEncryptionHeaderXor> Create(
        std::span<const uint8_t> key,
        std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv) noexcept;

    [[nodiscard]] bool XorOutboundInPlace(std::span<uint8_t> data) noexcept;
    [[nodiscard]] bool XorInboundInPlace(std::span<uint8_t> data) noexcept;

private:
    explicit VlessEncryptionHeaderXor(VlessEncryptionCtr ctr) noexcept
        : ctr_(std::move(ctr)) {}

    [[nodiscard]] bool Transform(std::span<uint8_t> data,
                                 bool inbound) noexcept;
    [[nodiscard]] bool FinishHeader() noexcept;

    VlessEncryptionCtr ctr_;
    std::array<uint8_t, kVlessEncryptionRecordHeaderSize> header_{};
    size_t header_len_ = 0;
    size_t skip_ = 0;
};

}  // namespace vless
