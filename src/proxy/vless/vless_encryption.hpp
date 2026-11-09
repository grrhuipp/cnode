#pragma once

#include "common/allocator.hpp"
#include "common/unsafe.hpp"

#include <openssl/aead.h>
#include <openssl/base.h>
#include <openssl/cipher.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/mlkem.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>
namespace vless {

enum class VlessEncryptionMode : uint8_t {
    Native,
    XorPub,
    Random,
};

enum class VlessEncryptionRole : uint8_t {
    Client,
    Server,
};

enum class VlessEncryptionParseError : uint8_t {
    None,
    UnsupportedName,
    TooFewParts,
    InvalidMode,
    InvalidRtt,
    InvalidSeconds,
    InvalidBase64,
    InvalidKeyLength,
    InvalidKeyMaterial,
    EmptyKeys,
    InvalidPadding,
    PaddingTooLarge,
};

struct VlessEncryptionPadding {
    int probability = 0;
    int from = 0;
    int to = 0;
};

struct VlessClientPfsKey {
    std::vector<uint8_t> public_key;
    std::shared_ptr<EVP_PKEY> mlkem_key;
};

struct VlessServerPfsKey {
    std::vector<uint8_t> private_key;
    std::vector<uint8_t> public_key;
    std::shared_ptr<EVP_PKEY> mlkem_key;

    VlessServerPfsKey() = default;
    VlessServerPfsKey(std::vector<uint8_t> priv,
                      std::vector<uint8_t> pub,
                      std::shared_ptr<EVP_PKEY> mlkem) noexcept
        : private_key(std::move(priv))
        , public_key(std::move(pub))
        , mlkem_key(std::move(mlkem)) {}
    VlessServerPfsKey(const VlessServerPfsKey&) = default;
    VlessServerPfsKey& operator=(const VlessServerPfsKey&) = default;
    VlessServerPfsKey(VlessServerPfsKey&&) noexcept = default;
    VlessServerPfsKey& operator=(VlessServerPfsKey&&) noexcept = default;
    ~VlessServerPfsKey() noexcept {
        if (!private_key.empty()) {
            ::SecureZeroMemory(private_key.data(), private_key.size());
        }
    }
};

struct VlessEncryptionConfig {
    VlessEncryptionRole role = VlessEncryptionRole::Client;
    VlessEncryptionMode mode = VlessEncryptionMode::Native;
    bool zero_rtt = false;
    int64_t seconds_from = 0;
    int64_t seconds_to = 0;
    std::vector<VlessClientPfsKey> client_keys;
    std::vector<VlessServerPfsKey> server_keys;
    std::vector<VlessEncryptionPadding> padding_lens;
};

struct VlessEncryptionParseResult {
    std::optional<VlessEncryptionConfig> config;
    VlessEncryptionParseError error = VlessEncryptionParseError::None;

    [[nodiscard]] explicit operator bool() const noexcept {
        return config.has_value() && error == VlessEncryptionParseError::None;
    }
};

[[nodiscard]] bool IsNoVlessEncryption(std::string_view value) noexcept;

[[nodiscard]] VlessEncryptionParseResult ParseVlessClientEncryption(
    std::string_view encryption);

[[nodiscard]] VlessEncryptionParseResult ParseVlessServerDecryption(
    std::string_view decryption);

[[nodiscard]] std::string_view VlessEncryptionParseErrorMessage(
    VlessEncryptionParseError error) noexcept;


// ============================================================================
// Key Exchange (X25519 & ML-KEM-768)
// ============================================================================

inline constexpr size_t kVlessX25519KeySize = 32;
inline constexpr size_t kVlessMlKem768SeedSize = 64;
inline constexpr size_t kVlessMlKem768PublicKeySize = 1184;
inline constexpr size_t kVlessMlKem768CiphertextSize = 1088;
inline constexpr size_t kVlessMlKem768SharedSecretSize = 32;
static_assert(kVlessMlKem768SeedSize == MLKEM_SEED_BYTES);
static_assert(kVlessMlKem768PublicKeySize == MLKEM768_PUBLIC_KEY_BYTES);
static_assert(kVlessMlKem768CiphertextSize == MLKEM768_CIPHERTEXT_BYTES);
static_assert(kVlessMlKem768SharedSecretSize == MLKEM_SHARED_SECRET_BYTES);

// The NFS key is a single X25519 or ML-KEM-768 shared secret.
inline constexpr size_t kVlessEncryptionNfsKeySize = kVlessX25519KeySize;
static_assert(kVlessEncryptionNfsKeySize == kVlessMlKem768SharedSecretSize);
inline constexpr size_t kVlessEncryptionPfsKeySize =
    kVlessMlKem768SharedSecretSize + kVlessX25519KeySize;
inline constexpr size_t kVlessEncryptionUnitedKeySize =
    kVlessEncryptionPfsKeySize + kVlessEncryptionNfsKeySize;

// Fixed-size key material that wipes its storage on destruction. Copies are
// independent and each wipes itself, so moves deliberately degrade to copies.
template <size_t N>
struct VlessSecretBytes {
    std::array<uint8_t, N> bytes{};

    VlessSecretBytes() noexcept = default;
    VlessSecretBytes(const VlessSecretBytes&) noexcept = default;
    VlessSecretBytes& operator=(const VlessSecretBytes&) noexcept = default;
    ~VlessSecretBytes() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

using VlessEncryptionNfsKey = VlessSecretBytes<kVlessEncryptionNfsKeySize>;
using VlessEncryptionPfsKey = VlessSecretBytes<kVlessEncryptionPfsKeySize>;
using VlessEncryptionUnitedKey = VlessSecretBytes<kVlessEncryptionUnitedKeySize>;

struct VlessX25519KeyPair {
    std::array<uint8_t, kVlessX25519KeySize> public_key{};
    VlessSecretBytes<kVlessX25519KeySize> private_key;
};

struct VlessMlKem768Encapsulation {
    std::array<uint8_t, kVlessMlKem768CiphertextSize> ciphertext{};
    VlessSecretBytes<kVlessMlKem768SharedSecretSize> shared_secret;
};

[[nodiscard]] VlessX25519KeyPair GenerateVlessX25519KeyPair() noexcept;

[[nodiscard]] bool DeriveVlessX25519PublicKey(
    std::span<const uint8_t> private_key,
    std::span<uint8_t, kVlessX25519KeySize> out_public_key) noexcept;

[[nodiscard]] bool ComputeVlessX25519SharedKey(
    std::span<const uint8_t> private_key,
    std::span<const uint8_t> peer_public_key,
    std::span<uint8_t, kVlessX25519KeySize> out_shared) noexcept;

// EVP_PKEY owns the expanded ML-KEM key and seed; EVP_PKEY_free wipes both.
// Configuration keys share ownership, while each PFS hello owns its own key.
[[nodiscard]] std::shared_ptr<EVP_PKEY>
CreateVlessMlKem768PrivateKeyFromSeed(std::span<const uint8_t> seed) noexcept;

[[nodiscard]] std::shared_ptr<EVP_PKEY>
CreateVlessMlKem768PublicKey(std::span<const uint8_t> public_key) noexcept;

[[nodiscard]] bssl::UniquePtr<EVP_PKEY> GenerateVlessMlKem768PrivateKey() noexcept;

[[nodiscard]] std::optional<
    std::array<uint8_t, kVlessMlKem768PublicKeySize>>
DeriveVlessMlKem768PublicKey(const EVP_PKEY* key) noexcept;

[[nodiscard]] std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(const EVP_PKEY* public_key) noexcept;

[[nodiscard]] std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(std::span<const uint8_t> public_key) noexcept;

[[nodiscard]] bool DecapsulateVlessMlKem768(
    const EVP_PKEY* private_key,
    std::span<const uint8_t> ciphertext,
    std::span<uint8_t, kVlessMlKem768SharedSecretSize> out_shared) noexcept;

// ============================================================================
// AEAD Record Framing
// ============================================================================

inline constexpr size_t kVlessEncryptionLengthSize = 2;
inline constexpr size_t kVlessEncryptionRecordHeaderSize = 5;
inline constexpr size_t kVlessEncryptionNonceSize = 12;
inline constexpr size_t kVlessEncryptionTagSize = 16;
inline constexpr size_t kVlessEncryptionMaxPlaintextSize = 8192;
inline constexpr size_t kVlessEncryptionMinRecordCiphertextSize =
    1 + kVlessEncryptionTagSize;
inline constexpr size_t kVlessEncryptionMaxRecordCiphertextSize = 16640;
inline constexpr size_t kVlessEncryptionAeadKeySize = 32;

using VlessEncryptionNonce =
    std::array<uint8_t, kVlessEncryptionNonceSize>;

enum class VlessEncryptionAeadCipher : uint8_t {
    Aes256Gcm,
    Chacha20Poly1305,
};

[[nodiscard]] std::array<uint8_t, kVlessEncryptionLengthSize>
EncodeVlessEncryptionLength(size_t length) noexcept;

[[nodiscard]] uint16_t DecodeVlessEncryptionLength(
    std::span<const uint8_t, kVlessEncryptionLengthSize> encoded) noexcept;

[[nodiscard]] bool EncodeVlessEncryptionRecordHeader(
    std::span<uint8_t, kVlessEncryptionRecordHeaderSize> header,
    size_t ciphertext_length) noexcept;

[[nodiscard]] std::optional<uint16_t> DecodeVlessEncryptionRecordHeader(
    std::span<const uint8_t, kVlessEncryptionRecordHeaderSize> header) noexcept;

void IncreaseVlessEncryptionNonce(
    std::span<uint8_t, kVlessEncryptionNonceSize> nonce) noexcept;

[[nodiscard]] bool IsVlessEncryptionMaxNonce(
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce) noexcept;

class VlessEncryptionAead {
public:
    VlessEncryptionAead() noexcept = default;
    ~VlessEncryptionAead() noexcept = default;

    VlessEncryptionAead(const VlessEncryptionAead&) = delete;
    VlessEncryptionAead& operator=(const VlessEncryptionAead&) = delete;

    VlessEncryptionAead(VlessEncryptionAead&&) noexcept = default;
    VlessEncryptionAead& operator=(VlessEncryptionAead&&) noexcept = default;

    [[nodiscard]] static std::optional<VlessEncryptionAead> Create(
        std::span<const uint8_t> context,
        std::span<const uint8_t> key,
        VlessEncryptionAeadCipher cipher) noexcept;

    [[nodiscard]] std::optional<size_t> Seal(
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> additional_data,
        std::span<uint8_t> output) noexcept;

    [[nodiscard]] std::optional<size_t> SealWithNonce(
        std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> additional_data,
        std::span<uint8_t> output) noexcept;

    [[nodiscard]] std::optional<size_t> Open(
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> additional_data,
        std::span<uint8_t> output) noexcept;

    [[nodiscard]] std::optional<size_t> OpenWithNonce(
        std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
        std::span<const uint8_t> ciphertext,
        std::span<const uint8_t> additional_data,
        std::span<uint8_t> output) noexcept;

    [[nodiscard]] const VlessEncryptionNonce& Nonce() const noexcept {
        return nonce_;
    }

    [[nodiscard]] VlessEncryptionAeadCipher Cipher() const noexcept {
        return cipher_;
    }

private:
    VlessEncryptionNonce nonce_{};
    VlessEncryptionAeadCipher cipher_ = VlessEncryptionAeadCipher::Aes256Gcm;
    // Allocated once on creation; moves transfer ownership without copying keys.
    bssl::UniquePtr<EVP_AEAD_CTX> aead_ctx_;
};

[[nodiscard]] std::optional<size_t> SealVlessEncryptionRecord(
    VlessEncryptionAead& aead,
    std::span<const uint8_t> plaintext,
    std::span<uint8_t> output) noexcept;

[[nodiscard]] std::optional<size_t> OpenVlessEncryptionRecord(
    VlessEncryptionAead& aead,
    std::span<const uint8_t, kVlessEncryptionRecordHeaderSize> header,
    std::span<const uint8_t> ciphertext,
    std::span<uint8_t> output) noexcept;

// ============================================================================
// AES-256-CTR Header / Relay XOR
// ============================================================================

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

// ============================================================================
// Handshake Protocol
// ============================================================================

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
    std::array<uint8_t, kVlessEncryptionClientPfsHelloSize> encrypted{};
};

struct VlessEncryptionServerPfsResponse {
    std::array<uint8_t, kVlessEncryptionEncryptedServerPfsPublicSize> encrypted_public_key{};
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
