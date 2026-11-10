#pragma once

#include "common/allocator.hpp"
#include "common/unsafe.hpp"
#include "common/asio_types.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/error.hpp"
#include "transport/link.hpp"
#include <tl/expected.hpp>

#include <openssl/aead.h>
#include <openssl/base.h>
#include <openssl/cipher.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/mlkem.h>

#include <openssl/siphash.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <variant>
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

// ============================================================================
// Runtime Handshake, Record I/O & 0-RTT Ticket Store
// ============================================================================

class VlessBufferedReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return src_.ReadEofAction(); }
    [[nodiscard]] bool EnableRawRead() noexcept override { return src_.EnableRawRead(); }

    explicit VlessBufferedReader(transport::MultiBufferReader& src) noexcept
        : src_(src) {}

    // Drains already buffered bytes only; true once `done` reaches `len`.
    [[nodiscard]] bool ReadBuffered(uint8_t* data, size_t len, size_t& done) noexcept {
        while (done < len && pending_.byte_size() != 0) {
            const size_t n = pending_.ConsumePrefixTo(
                std::span<uint8_t>(data + done, len - done));
            if (n == 0) {
                break;
            }
            done += n;
        }
        return done >= len;
    }

    net::awaitable<bool> ReadExact(uint8_t* data,
                                   size_t len,
                                   bool eof_ok_at_start = false,
                                   size_t* progress = nullptr) {
        size_t local_done = 0;
        size_t& done = progress ? *progress : local_done;
        while (!ReadBuffered(data, len, done)) {
            buf::MultiBuffer mb = co_await src_.ReadMultiBuffer();
            const bool received = mb.byte_size() != 0;
            if (received) mb.MoveTo(pending_);
            // Retain concurrently received bytes before observing cancellation.
            if ((co_await net::this_coro::cancellation_state).cancelled() !=
                net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            if (!received) {
                co_return done == 0 && eof_ok_at_start ? false : done == len;
            }
        }
        co_return true;
    }

    net::awaitable<bool> DiscardExact(size_t len, size_t* progress = nullptr) {
        size_t local_done = 0;
        size_t& done = progress ? *progress : local_done;
        while (done < len) {
            if (pending_.byte_size() != 0) {
                const size_t n = pending_.DropPrefixBytes(len - done);
                done += n;
                if (n > 0) {
                    continue;
                }
            }

            buf::MultiBuffer mb = co_await src_.ReadMultiBuffer();
            const bool received = mb.byte_size() != 0;
            if (received) mb.MoveTo(pending_);
            // Retain concurrently received bytes before observing cancellation.
            if ((co_await net::this_coro::cancellation_state).cancelled() !=
                net::cancellation_type::none) {
                throw IoSystemError(io_error::operation_aborted);
            }
            if (!received) {
                co_return done == len;
            }
        }
        co_return true;
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        if (pending_.byte_size() != 0) {
            return TakePending();
        }
        return src_.ReadMultiBuffer();
    }

private:
    net::awaitable<buf::MultiBuffer> TakePending() {
        co_return std::move(pending_);
    }

    transport::MultiBufferReader& src_;
    buf::MultiBuffer pending_;
};

inline net::awaitable<void> WriteVlessBytes(
    transport::MultiBufferWriter& writer,
    std::span<const uint8_t> data) {
    net::const_buffer buffer{data.data(), data.size()};
    co_await writer.WriteBuffers(std::span<const net::const_buffer>{&buffer, 1});
}

// 记录层只报告首个认证响应前的拒绝，不借用握手凭据。
// 宿主必须地址稳定，并比延迟读端活得更久；取消本身不构成拒绝。
struct VlessEncryptionTicketRejection {
    VlessEncryptionTicketRejection() noexcept = default;
    VlessEncryptionTicketRejection(const VlessEncryptionTicketRejection&) = delete;
    VlessEncryptionTicketRejection& operator=(const VlessEncryptionTicketRejection&) = delete;
    VlessEncryptionTicketRejection(VlessEncryptionTicketRejection&&) = delete;
    VlessEncryptionTicketRejection& operator=(VlessEncryptionTicketRejection&&) = delete;

    bool rejected = false;
};

// 0-RTT client read side: it is keyed by the server random that prefixes the
// first response bytes, which also seeds the header XOR when enabled.
struct VlessEncryptionDeferredRead {
    VlessEncryptionAeadCipher cipher = VlessEncryptionAeadCipher::Aes256Gcm;
    bool header_xor = false;
    VlessEncryptionTicketRejection* ticket_rejection = nullptr;
};
using VlessEncryptionReadKeys =
    std::variant<VlessEncryptionAead, VlessEncryptionDeferredRead>;

class VlessEncryptionReader final : public transport::MultiBufferReader {
public:
    transport::CancellationSource& Cancellation() noexcept override { return src_.Cancellation(); }
    transport::EofAction ReadEofAction() const noexcept override { return src_.ReadEofAction(); }

    // A deferred read side must not come with a header XOR; it derives its own.
    VlessEncryptionReader(memory::worker_memory& pool,
                          transport::MultiBufferReader& src,
                          VlessEncryptionReadKeys keys,
                          const VlessEncryptionUnitedKey& united_key,
                          std::optional<VlessEncryptionHeaderXor>
                              header_xor) noexcept;

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    [[nodiscard]] bool EnableRawRead() noexcept override;
    void RejectDeferredTicket() noexcept;

private:
    [[nodiscard]] VlessEncryptionAead& KeyDeferredRead(
        const VlessEncryptionDeferredRead& deferred);

    VlessBufferedReader src_;
    VlessEncryptionReadKeys keys_;
    VlessEncryptionUnitedKey united_key_;
    std::optional<VlessEncryptionHeaderXor> header_xor_;
    // Read progress survives a cancelled sniff continuation. Header XOR is
    // applied once, before waiting for the rest of the encrypted record.
    // `bytes_read_` tracks the server random until the read side is keyed.
    std::array<uint8_t, kVlessEncryptionCtrIvSize> server_random_{};
    std::array<uint8_t, kVlessEncryptionRecordHeaderSize> read_header_{};
    buf::ContiguousWriteBuffer read_record_;
    size_t header_read_ = 0;
    size_t bytes_read_ = 0;
    size_t encrypted_size_ = 0;
    bool raw_read_ = false;
    VlessEncryptionTicketRejection* unverified_ticket_ = nullptr;
};

class VlessEncryptionWriter final : public transport::MultiBufferWriter {
public:
    VlessEncryptionWriter(memory::worker_memory& pool,
                          transport::MultiBufferWriter& dst,
                          VlessEncryptionAead aead,
                          const VlessEncryptionUnitedKey& united_key,
                          std::optional<VlessEncryptionHeaderXor>
                              header_xor) noexcept;
    VlessEncryptionWriter(const VlessEncryptionWriter&) = delete;
    VlessEncryptionWriter& operator=(const VlessEncryptionWriter&) = delete;
    VlessEncryptionWriter(VlessEncryptionWriter&&) = delete;
    VlessEncryptionWriter& operator=(VlessEncryptionWriter&&) = delete;

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    net::awaitable<void> AsyncShutdownWrite() override;
    bool WriteShutdownClosesLink() const noexcept override {
        return dst_.WriteShutdownClosesLink();
    }

private:
    enum class State : uint8_t { Active, Finished, Failed };

    void CheckWritable() const;
    // By value: the range must stay in this frame until the write completes.
    template <typename BufferRange>
    net::awaitable<void> WriteEncrypted(BufferRange source);

    memory::worker_memory& pool_;
    transport::MultiBufferWriter& dst_;
    VlessEncryptionAead aead_;
    VlessEncryptionUnitedKey united_key_;
    std::optional<VlessEncryptionHeaderXor> header_xor_;
    State state_ = State::Active;
};

struct VlessEncryptionIssuedTicket {
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
    VlessEncryptionPfsKey pfs_key;
    uint16_t seconds = 0;
    std::chrono::steady_clock::time_point issued_at{};
};

struct VlessEncryptionRuntime {
    VlessEncryptionUnitedKey united_key;
    VlessEncryptionReadKeys read_keys;
    VlessEncryptionAead write_aead;
    std::optional<VlessEncryptionHeaderXor> read_xor;
    std::optional<VlessEncryptionHeaderXor> write_xor;
    // Server-only authentication binding; never changes the wire ticket format.
    std::optional<VlessEncryptionIssuedTicket> issued_ticket;
    std::optional<std::array<uint8_t, 16>> resumed_identity;
};

enum class VlessEncryptionHandshakeFailure {
    Closed,
    Truncated,
    Rejected,
};

// Transport failures (including cancellation) propagate as IoSystemError; only
// a server receiving no handshake bytes can report a normal Closed result.
using VlessEncryptionHandshakeResult =
    tl::expected<VlessEncryptionRuntime, VlessEncryptionHandshakeFailure>;

// Record layer installed over the raw connection after a completed handshake.
// `plain_reader` borrows `reader` and both borrow the raw endpoints, so the
// owner is address-stable and must outlive every borrowed raw endpoint use.
struct VlessEncryptedIo : memory::WorkerAllocated {
    VlessEncryptedIo(memory::worker_memory& pool,
                     VlessBufferedReader& raw_reader,
                     transport::MultiBufferWriter& raw_writer,
                     VlessEncryptionRuntime runtime);

    VlessEncryptedIo(const VlessEncryptedIo&) = delete;
    VlessEncryptedIo& operator=(const VlessEncryptedIo&) = delete;
    VlessEncryptedIo(VlessEncryptedIo&&) = delete;
    VlessEncryptedIo& operator=(VlessEncryptedIo&&) = delete;

    VlessEncryptionReader reader;
    VlessEncryptionWriter writer;
    VlessBufferedReader plain_reader;
};

struct VlessEncryptionClientTicketCache {
    VlessEncryptionPfsKey pfs_key;
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket{};
    std::chrono::steady_clock::time_point expires_at{};

    [[nodiscard]] bool Valid(std::chrono::steady_clock::time_point now) const noexcept;
    void Store(const VlessEncryptionClientPfsOpenResult& open,
               std::chrono::steady_clock::time_point now) noexcept;
    void Clear() noexcept {
        pfs_key = {};
        ticket = {};
        expires_at = {};
    }
};

// Executor-local 0-RTT ticket table. Tickets are server-chosen, but lookups and
// replay keys are peer-chosen, so buckets use a per-store SipHash key and key
// equality is constant time.
class VlessEncryptionServerTicketStore {
public:
    VlessEncryptionServerTicketStore();
    struct ResumedSession {
        VlessEncryptionPfsKey pfs_key;
        std::array<uint8_t, 16> identity;
    };

    // Records `nfs_key` against the ticket and refuses a repeated one.
    [[nodiscard]] std::optional<ResumedSession> Lookup(
        std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
        const VlessEncryptionNfsKey& nfs_key,
        std::chrono::steady_clock::time_point now);

    void Store(std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
               const VlessEncryptionPfsKey& pfs_key,
               uint16_t seconds,
               std::chrono::steady_clock::time_point now);
    [[nodiscard]] bool BindIdentity(
        std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
        const std::array<uint8_t, 16>& identity,
        std::chrono::steady_clock::time_point now);
    void Erase(std::span<const uint8_t, kVlessEncryptionTicketSize> ticket) noexcept;

private:
    static constexpr size_t kMaxSessions = 1024;
    // Upper bound of replay keys held across all sessions; reaching it evicts
    // the oldest sessions, the same policy as the session bound.
    static constexpr size_t kMaxSeenNfsKeys = 65536;
    static constexpr size_t kMaxSeenNfsKeysPerSession = 256;

    using TicketArray = std::array<uint8_t, kVlessEncryptionTicketSize>;
    // Replay keys are BLAKE3 digests so no NFS secret outlives its handshake.
    using NfsKeyDigest = std::array<uint8_t, 32>;

    struct KeyedHash {
        std::array<uint64_t, 2> key{};

        template <size_t N>
        [[nodiscard]] size_t operator()(const std::array<uint8_t, N>& value) const noexcept {
            return static_cast<size_t>(SIPHASH_24(key.data(), value.data(), N));
        }
    };

    struct ConstantTimeEqual {
        template <size_t N>
        [[nodiscard]] bool operator()(const std::array<uint8_t, N>& a,
                                      const std::array<uint8_t, N>& b) const noexcept {
            return CRYPTO_memcmp(a.data(), b.data(), N) == 0;
        }
    };

    struct Session {
        VlessEncryptionPfsKey pfs_key;
        std::chrono::steady_clock::time_point expires_at{};
        std::optional<std::array<uint8_t, 16>> identity;
        memory::UnorderedSet<NfsKeyDigest, KeyedHash, ConstantTimeEqual>
            seen_nfs_keys;
    };

    using SessionMap =
        memory::UnorderedMap<TicketArray, Session, KeyedHash, ConstantTimeEqual>;

    void Prune(std::chrono::steady_clock::time_point now);
    void EraseOldest();
    void Erase(SessionMap::iterator it) noexcept;

    SessionMap sessions_;
    memory::RingDeque<std::pair<TicketArray, std::chrono::steady_clock::time_point>> order_;
    size_t seen_nfs_keys_ = 0;
};

[[nodiscard]] net::awaitable<VlessEncryptionHandshakeResult>
RunVlessEncryptionClientHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    const VlessEncryptionConfig& config,
    VlessEncryptionClientTicketCache* ticket_cache,
    VlessEncryptionTicketRejection& ticket_rejection);

[[nodiscard]] net::awaitable<VlessEncryptionHandshakeResult>
RunVlessEncryptionServerHandshake(
    VlessBufferedReader& raw_reader,
    transport::MultiBufferWriter& raw_writer,
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string_view inbound_tag);

// Directory entries carry only routing/lifetime metadata. PFS secrets and the
// mutable replay set are accessed exclusively on the ticket owner's domain.

[[nodiscard]] net::awaitable<bool> AuthenticateVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string_view inbound_tag,
    VlessEncryptionIssuedTicket ticket,
    std::array<uint8_t, 16> identity);

[[nodiscard]] net::awaitable<std::optional<VlessEncryptionServerTicketStore::ResumedSession>>
LookupVlessTicket(
    std::shared_ptr<const VlessEncryptionConfig> config,
    std::string_view inbound_tag,
    std::array<uint8_t, kVlessEncryptionTicketSize> ticket,
    VlessEncryptionNfsKey nfs_key);
}  // namespace vless
