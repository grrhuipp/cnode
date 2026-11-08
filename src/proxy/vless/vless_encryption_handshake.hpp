#pragma once

#include "vless_encryption.hpp"
#include "vless_encryption_crypto.hpp"
#include "vless_encryption_record.hpp"
#include "vless_encryption_xor.hpp"

#include "common/allocator.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace vless {

inline constexpr size_t kVlessEncryptionIvSize = kVlessEncryptionCtrIvSize;
inline constexpr size_t kVlessEncryptionTicketSize = 16;
inline constexpr size_t kVlessEncryptionServerRandomSize = 16;
inline constexpr size_t kVlessEncryptionEncryptedLengthSize =
    kVlessEncryptionLengthSize + kVlessEncryptionTagSize;
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
inline constexpr size_t kVlessEncryptionZeroRttRequestSize =
    kVlessEncryptionEncryptedLengthSize + kVlessEncryptionEncryptedTicketSize;
inline constexpr size_t kVlessEncryptionMinPaddingLength =
    kVlessEncryptionEncryptedLengthSize + kVlessEncryptionTagSize + 1;
inline constexpr size_t kVlessEncryptionMaxPaddingLength =
    kVlessEncryptionEncryptedLengthSize + 65535;

struct VlessEncryptionClientNfsHello {
    std::array<uint8_t, kVlessEncryptionIvSize> iv{};
    VlessEncryptionNfsKey nfs_key;
    // iv followed by the obfuscated relays.
    memory::ByteVector bytes;
};

struct VlessEncryptionServerNfsOpenResult {
    std::array<uint8_t, kVlessEncryptionIvSize> iv{};
    VlessEncryptionNfsKey nfs_key;
};

struct VlessEncryptionClientPfsHello {
    bssl::UniquePtr<EVP_PKEY> mlkem_private_key;
    VlessSecretBytes<kVlessX25519KeySize> x25519_private_key;
    std::array<uint8_t, kVlessEncryptionClientPfsPublicSize> public_key{};
    memory::ByteVector encrypted;
};

struct VlessEncryptionServerPfsResponse {
    memory::ByteVector encrypted_public_key;
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
    std::array<uint8_t, kVlessEncryptionEncryptedTicketSize> encrypted_ticket{};
    VlessEncryptionPfsKey pfs_key;
    VlessEncryptionUnitedKey united_key;
    VlessEncryptionAead write_aead;
    uint16_t ticket_seconds = 0;
};

struct VlessEncryptionClientPfsOpenResult {
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
    VlessEncryptionPfsKey pfs_key;
    VlessEncryptionUnitedKey united_key;
    VlessEncryptionAead read_aead;
    uint16_t ticket_seconds = 0;
};

struct VlessEncryptionClientZeroRttRequest {
    // Sealed length followed by the sealed ticket.
    std::array<uint8_t, kVlessEncryptionZeroRttRequestSize> bytes{};
    VlessEncryptionUnitedKey united_key;

    [[nodiscard]] std::span<const uint8_t, kVlessEncryptionEncryptedTicketSize>
    EncryptedTicket() const noexcept {
        return std::span<const uint8_t, kVlessEncryptionZeroRttRequestSize>(bytes)
            .subspan<kVlessEncryptionEncryptedLengthSize>();
    }
};

struct VlessEncryptionServerZeroRttAccept {
    std::array<uint8_t, kVlessEncryptionServerRandomSize> server_random{};
    VlessEncryptionUnitedKey united_key;
};

[[nodiscard]] std::optional<size_t> VlessEncryptionRelaysLength(
    const VlessEncryptionConfig& config) noexcept;

[[nodiscard]] std::optional<VlessEncryptionClientNfsHello>
BuildVlessEncryptionClientNfsHello(
    const VlessEncryptionConfig& config) noexcept;

// Unmasks the relays in place.
[[nodiscard]] std::optional<VlessEncryptionServerNfsOpenResult>
OpenVlessEncryptionClientNfsHello(
    const VlessEncryptionConfig& config,
    std::span<uint8_t> iv_and_relays) noexcept;

[[nodiscard]] std::optional<VlessEncryptionClientPfsHello>
BuildVlessEncryptionClientPfsHello(
    VlessEncryptionAead& nfs_aead) noexcept;

[[nodiscard]] std::optional<VlessEncryptionServerPfsResponse>
BuildVlessEncryptionServerPfsResponse(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    const VlessEncryptionNfsKey& nfs_key,
    std::span<const uint8_t, kVlessEncryptionClientPfsPublicSize>
        client_public_key,
    VlessEncryptionAeadCipher cipher) noexcept;

[[nodiscard]] std::optional<VlessEncryptionClientPfsOpenResult>
OpenVlessEncryptionServerPfsResponse(
    const VlessEncryptionClientPfsHello& client_hello,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    const VlessEncryptionNfsKey& nfs_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedServerPfsPublicSize>
        encrypted_public_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket,
    VlessEncryptionAeadCipher cipher) noexcept;

[[nodiscard]] std::optional<memory::ByteVector> BuildVlessEncryptionPadding(
    const VlessEncryptionConfig& config,
    VlessEncryptionAead& aead) noexcept;

[[nodiscard]] std::optional<VlessEncryptionClientZeroRttRequest>
BuildVlessEncryptionClientZeroRttRequest(
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    const VlessEncryptionNfsKey& nfs_key,
    const VlessEncryptionPfsKey& pfs_key,
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    VlessEncryptionAeadCipher cipher) noexcept;

// The caller has already opened the request and matched its ticket.
[[nodiscard]] std::optional<VlessEncryptionServerZeroRttAccept>
AcceptVlessEncryptionClientZeroRtt(
    const VlessEncryptionNfsKey& nfs_key,
    const VlessEncryptionPfsKey& pfs_key) noexcept;

}  // namespace vless
