#pragma once

#include "vless_encryption.hpp"
#include "vless_encryption_crypto.hpp"
#include "vless_encryption_record.hpp"
#include "vless_encryption_xor.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace acpp::vless {

inline constexpr size_t kVlessEncryptionIvSize = kVlessEncryptionCtrIvSize;
inline constexpr size_t kVlessEncryptionTicketSize = 16;
inline constexpr size_t kVlessEncryptionEncryptedLengthSize =
    kVlessEncryptionLengthSize + kVlessEncryptionTagSize;
inline constexpr size_t kVlessEncryptionPfsKeySize =
    kVlessMlKem768SharedSecretSize + kVlessX25519KeySize;
inline constexpr size_t kVlessEncryptionClientPfsPublicSize =
    kVlessMlKem768PublicKeySize + kVlessX25519KeySize;
inline constexpr size_t kVlessEncryptionEncryptedClientPfsPublicSize =
    kVlessEncryptionClientPfsPublicSize + kVlessEncryptionTagSize;
inline constexpr size_t kVlessEncryptionClientPfsHelloSize =
    kVlessEncryptionEncryptedLengthSize +
    kVlessEncryptionEncryptedClientPfsPublicSize;
inline constexpr size_t kVlessEncryptionServerPfsPublicSize =
    kVlessMlKem768CiphertextSize + kVlessX25519KeySize;
inline constexpr size_t kVlessEncryptionEncryptedServerPfsPublicSize =
    kVlessEncryptionServerPfsPublicSize + kVlessEncryptionTagSize;
inline constexpr size_t kVlessEncryptionEncryptedTicketSize =
    kVlessEncryptionTicketSize + kVlessEncryptionTagSize;
inline constexpr size_t kVlessEncryptionMinPaddingLength =
    kVlessEncryptionEncryptedLengthSize + kVlessEncryptionTagSize + 1;
inline constexpr size_t kVlessEncryptionMaxPaddingLength =
    kVlessEncryptionEncryptedLengthSize + 65535;

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

struct VlessEncryptionClientPfsHello {
    std::array<uint8_t, kVlessMlKem768SeedSize> mlkem_seed{};
    std::array<uint8_t, kVlessX25519KeySize> x25519_private_key{};
    std::array<uint8_t, kVlessEncryptionClientPfsPublicSize> public_key{};
    std::array<uint8_t, kVlessEncryptionClientPfsHelloSize> encrypted{};
};

struct VlessEncryptionServerPfsResponse {
    std::array<uint8_t, kVlessEncryptionServerPfsPublicSize> public_key{};
    std::array<uint8_t, kVlessEncryptionEncryptedServerPfsPublicSize>
        encrypted_public_key{};
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
    std::array<uint8_t, kVlessEncryptionEncryptedTicketSize> encrypted_ticket{};
    std::vector<uint8_t> pfs_key;
    std::vector<uint8_t> united_key;
    uint16_t ticket_seconds = 0;
};

struct VlessEncryptionClientPfsOpenResult {
    std::array<uint8_t, kVlessEncryptionServerPfsPublicSize>
        server_public_key{};
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
    std::vector<uint8_t> pfs_key;
    std::vector<uint8_t> united_key;
    uint16_t ticket_seconds = 0;
};

struct VlessEncryptionPaddingPlan {
    size_t total_length = 0;
    std::vector<size_t> fragment_lengths;
    std::vector<uint32_t> gaps_ms;
};

struct VlessEncryptionEncryptedPadding {
    VlessEncryptionPaddingPlan plan;
    std::vector<uint8_t> bytes;
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

[[nodiscard]] std::optional<VlessEncryptionClientPfsHello>
BuildVlessEncryptionClientPfsHello(
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    std::span<const uint8_t> nfs_key,
    VlessEncryptionAeadCipher cipher) noexcept;

[[nodiscard]] std::optional<
    std::array<uint8_t, kVlessEncryptionClientPfsPublicSize>>
OpenVlessEncryptionClientPfsHello(
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    std::span<const uint8_t> nfs_key,
    std::span<const uint8_t, kVlessEncryptionClientPfsHelloSize> encrypted,
    VlessEncryptionAeadCipher cipher) noexcept;

[[nodiscard]] std::optional<VlessEncryptionServerPfsResponse>
BuildVlessEncryptionServerPfsResponse(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    std::span<const uint8_t> nfs_key,
    std::span<const uint8_t, kVlessEncryptionClientPfsPublicSize>
        client_public_key,
    VlessEncryptionAeadCipher cipher) noexcept;

[[nodiscard]] std::optional<VlessEncryptionClientPfsOpenResult>
OpenVlessEncryptionServerPfsResponse(
    const VlessEncryptionClientPfsHello& client_hello,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    std::span<const uint8_t> nfs_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedServerPfsPublicSize>
        encrypted_public_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket,
    VlessEncryptionAeadCipher cipher) noexcept;

[[nodiscard]] std::optional<VlessEncryptionPaddingPlan>
BuildVlessEncryptionPaddingPlan(
    const VlessEncryptionConfig& config) noexcept;

[[nodiscard]] std::optional<std::vector<uint8_t>>
SealVlessEncryptionPadding(VlessEncryptionAead& aead,
                           size_t padding_length) noexcept;

[[nodiscard]] std::optional<VlessEncryptionEncryptedPadding>
BuildVlessEncryptionPadding(const VlessEncryptionConfig& config,
                            VlessEncryptionAead& aead) noexcept;

}  // namespace acpp::vless
