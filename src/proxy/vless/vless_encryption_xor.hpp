#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace acpp::vless {

inline constexpr size_t kVlessEncryptionCtrKeySize = 32;
inline constexpr size_t kVlessEncryptionCtrIvSize = 16;

class VlessEncryptionCtr {
public:
    VlessEncryptionCtr() noexcept = default;
    ~VlessEncryptionCtr() noexcept;

    VlessEncryptionCtr(const VlessEncryptionCtr&) = delete;
    VlessEncryptionCtr& operator=(const VlessEncryptionCtr&) = delete;

    VlessEncryptionCtr(VlessEncryptionCtr&& other) noexcept;
    VlessEncryptionCtr& operator=(VlessEncryptionCtr&& other) noexcept;

    [[nodiscard]] static std::optional<VlessEncryptionCtr> Create(
        std::span<const uint8_t> key,
        std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv) noexcept;

    [[nodiscard]] bool XorInPlace(std::span<uint8_t> data) noexcept;

    [[nodiscard]] bool Xor(std::span<const uint8_t> input,
                           std::span<uint8_t> output) noexcept;

private:
    explicit VlessEncryptionCtr(void* ctx) noexcept : ctx_(ctx) {}

    void Close() noexcept;

    void* ctx_ = nullptr;
};

[[nodiscard]] std::optional<std::array<uint8_t, kVlessEncryptionCtrKeySize>>
DeriveVlessEncryptionCtrKey(std::span<const uint8_t> key) noexcept;

[[nodiscard]] bool XorVlessEncryptionInPlace(
    std::span<const uint8_t> key,
    std::span<const uint8_t, kVlessEncryptionCtrIvSize> iv,
    std::span<uint8_t> data) noexcept;

}  // namespace acpp::vless
