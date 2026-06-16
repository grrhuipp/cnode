#pragma once

#include "vless_encryption.hpp"
#include "vless_encryption_crypto.hpp"
#include "vless_encryption_xor.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace acpp::vless {

inline constexpr size_t kVlessEncryptionIvSize = kVlessEncryptionCtrIvSize;

struct VlessEncryptionClientNfsHello {
    std::array<uint8_t, kVlessEncryptionIvSize> iv{};
    std::vector<uint8_t> relays;
    std::vector<uint8_t> nfs_key;
    std::vector<uint8_t> bytes;
};

struct VlessEncryptionServerNfsOpenResult {
    std::array<uint8_t, kVlessEncryptionIvSize> iv{};
    std::vector<uint8_t> relays;
    std::vector<uint8_t> nfs_key;
};

[[nodiscard]] std::optional<size_t> VlessEncryptionRelaysLength(
    const VlessEncryptionConfig& config) noexcept;

[[nodiscard]] std::optional<VlessEncryptionClientNfsHello>
BuildVlessEncryptionClientNfsHello(
    const VlessEncryptionConfig& config) noexcept;

[[nodiscard]] std::optional<VlessEncryptionServerNfsOpenResult>
OpenVlessEncryptionClientNfsHello(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t> iv_and_relays) noexcept;

}  // namespace acpp::vless
