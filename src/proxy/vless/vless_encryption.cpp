#include "vless_encryption.hpp"

#include "common/allocator.hpp"
#include "common/binary_text_codec.hpp"
#include "transport/internet/http_headers.hpp"

#include <blake3.h>
#include <openssl/aead.h>
#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/mlkem.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <utility>
namespace vless {
namespace {

constexpr std::string_view kEncryptionName = "mlkem768x25519plus";
constexpr int kFirstPaddingMinProbability = 100;
constexpr int kFirstPaddingMinLength = 18 + 17;
constexpr int kMaxPaddingLength = 18 + 65535;

[[nodiscard]] bool ParseInt(std::string_view value, int64_t& out) noexcept {
    if (value.empty()) {
        return false;
    }
    int64_t parsed = 0;
    const auto* first = value.data();
    const auto* last = value.data() + value.size();
    auto [ptr, ec] = std::from_chars(first, last, parsed);
    if (ec != std::errc{} || ptr != last || parsed < 0) {
        return false;
    }
    out = parsed;
    return true;
}

[[nodiscard]] bool ParseInt(std::string_view value, int& out) noexcept {
    int64_t parsed = 0;
    if (!ParseInt(value, parsed) ||
        parsed > static_cast<int64_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    out = static_cast<int>(parsed);
    return true;
}

[[nodiscard]] VlessEncryptionParseError ParseMode(
    std::string_view value,
    VlessEncryptionMode& out) noexcept {
    if (transport::internet::EqualsAsciiCI(value, "native")) {
        out = VlessEncryptionMode::Native;
        return VlessEncryptionParseError::None;
    }
    if (transport::internet::EqualsAsciiCI(value, "xorpub")) {
        out = VlessEncryptionMode::XorPub;
        return VlessEncryptionParseError::None;
    }
    if (transport::internet::EqualsAsciiCI(value, "random")) {
        out = VlessEncryptionMode::Random;
        return VlessEncryptionParseError::None;
    }
    return VlessEncryptionParseError::InvalidMode;
}

[[nodiscard]] std::vector<std::string_view> Split(std::string_view value,
                                                  char separator) {
    std::vector<std::string_view> parts;
    size_t start = 0;
    while (start <= value.size()) {
        const size_t pos = value.find(separator, start);
        if (pos == std::string_view::npos) {
            parts.push_back(value.substr(start));
            break;
        }
        parts.push_back(value.substr(start, pos - start));
        start = pos + 1;
    }
    return parts;
}

[[nodiscard]] VlessEncryptionParseError ParsePadding(
    const std::vector<std::string_view>& parts,
    VlessEncryptionConfig& out) {
    int64_t max_len = 0;
    for (size_t i = 0; i < parts.size(); ++i) {
        const auto fields = Split(parts[i], '-');
        if (fields.size() != 3 || fields[0].empty() ||
            fields[1].empty() || fields[2].empty()) {
            return VlessEncryptionParseError::InvalidPadding;
        }

        VlessEncryptionPadding padding;
        if (!ParseInt(fields[0], padding.probability) ||
            !ParseInt(fields[1], padding.from) ||
            !ParseInt(fields[2], padding.to) ||
            padding.probability > 100) {
            return VlessEncryptionParseError::InvalidPadding;
        }

        if (i == 0 &&
            (padding.probability < kFirstPaddingMinProbability ||
             padding.from < kFirstPaddingMinLength ||
             padding.to < kFirstPaddingMinLength)) {
            return VlessEncryptionParseError::InvalidPadding;
        }

        // Odd parts are inter-fragment gaps; the handshake writes padding as
        // one block, so they are validated but not retained.
        if (i % 2 == 0) {
            out.padding_lens.push_back(padding);
            max_len += std::max(padding.from, padding.to);
            if (max_len > kMaxPaddingLength) {
                return VlessEncryptionParseError::PaddingTooLarge;
            }
        }
    }
    return VlessEncryptionParseError::None;
}

VlessEncryptionParseResult ParseErrorResult(VlessEncryptionParseError error) {
    return {
        .config = std::nullopt,
        .error = error,
    };
}

[[nodiscard]] VlessEncryptionParseResult ParseVlessEncryption(
    std::string_view value,
    VlessEncryptionRole role) {
    auto parts = Split(value, '.');
    if (parts.size() < 4) {
        return ParseErrorResult(VlessEncryptionParseError::TooFewParts);
    }
    if (!transport::internet::EqualsAsciiCI(parts[0], kEncryptionName)) {
        return ParseErrorResult(VlessEncryptionParseError::UnsupportedName);
    }

    VlessEncryptionConfig config;
    config.role = role;
    if (auto error = ParseMode(parts[1], config.mode);
        error != VlessEncryptionParseError::None) {
        return ParseErrorResult(error);
    }

    if (role == VlessEncryptionRole::Client) {
        if (transport::internet::EqualsAsciiCI(parts[2], "1rtt")) {
            config.zero_rtt = false;
        } else if (transport::internet::EqualsAsciiCI(parts[2], "0rtt")) {
            config.zero_rtt = true;
        } else {
            return ParseErrorResult(VlessEncryptionParseError::InvalidRtt);
        }
    } else {
        std::string_view seconds = parts[2];
        if (seconds.ends_with('s') || seconds.ends_with('S')) {
            seconds.remove_suffix(1);
        }
        const size_t hyphen = seconds.find('-');
        if (hyphen == std::string_view::npos) {
            if (!ParseInt(seconds, config.seconds_from)) {
                return ParseErrorResult(VlessEncryptionParseError::InvalidSeconds);
            }
        } else {
            if (!ParseInt(seconds.substr(0, hyphen), config.seconds_from) ||
                !ParseInt(seconds.substr(hyphen + 1), config.seconds_to)) {
                return ParseErrorResult(VlessEncryptionParseError::InvalidSeconds);
            }
        }
        if (config.seconds_from > 65535 || config.seconds_to > 65535) {
            return ParseErrorResult(VlessEncryptionParseError::InvalidSeconds);
        }
    }

    std::vector<std::string_view> padding_parts;
    for (size_t i = 3; i < parts.size(); ++i) {
        std::string_view part = parts[i];
        if (part.size() < 20) {
            padding_parts.push_back(part);
            continue;
        }

        std::vector<uint8_t> key(Base64UrlDecodedSize(part.size()));
        struct KeyCleanseGuard {
            std::vector<uint8_t>& buf;
            ~KeyCleanseGuard() noexcept {
                if (!buf.empty()) OPENSSL_cleanse(buf.data(), buf.size());
            }
        } cleanse_key{key};
        if (!DecodeBase64Url(part, key)) {
            return ParseErrorResult(VlessEncryptionParseError::InvalidBase64);
        }
        const size_t len = key.size();
        if (role == VlessEncryptionRole::Client) {
            if (len == kVlessX25519KeySize) {
                config.client_keys.push_back(VlessClientPfsKey{
                    .public_key = std::move(key),
                    .mlkem_key = nullptr,
                });
            } else if (len == kVlessMlKem768PublicKeySize) {
                auto mlkem_key = CreateVlessMlKem768PublicKey(key);
                if (!mlkem_key) {
                    return ParseErrorResult(
                        VlessEncryptionParseError::InvalidKeyMaterial);
                }
                config.client_keys.push_back(VlessClientPfsKey{
                    .public_key = std::move(key),
                    .mlkem_key = std::move(mlkem_key),
                });
            } else {
                return ParseErrorResult(
                    VlessEncryptionParseError::InvalidKeyLength);
            }
        } else {
            if (len == kVlessX25519KeySize) {
                std::array<uint8_t, kVlessX25519KeySize> public_key{};
                if (!DeriveVlessX25519PublicKey(key, public_key)) {
                    return ParseErrorResult(
                        VlessEncryptionParseError::InvalidKeyMaterial);
                }
                config.server_keys.emplace_back(
                    std::move(key),
                    std::vector<uint8_t>(public_key.begin(), public_key.end()),
                    nullptr);
            } else if (len == kVlessMlKem768SeedSize) {
                auto mlkem_key = CreateVlessMlKem768PrivateKeyFromSeed(key);
                auto public_key = DeriveVlessMlKem768PublicKey(mlkem_key.get());
                if (!mlkem_key || !public_key) {
                    return ParseErrorResult(
                        VlessEncryptionParseError::InvalidKeyMaterial);
                }
                config.server_keys.emplace_back(
                    std::move(key),
                    std::vector<uint8_t>(public_key->begin(), public_key->end()),
                    std::move(mlkem_key));
            } else {
                return ParseErrorResult(
                    VlessEncryptionParseError::InvalidKeyLength);
            }
        }
    }

    const bool has_keys = role == VlessEncryptionRole::Client
        ? !config.client_keys.empty()
        : !config.server_keys.empty();
    if (!has_keys) {
        return ParseErrorResult(VlessEncryptionParseError::EmptyKeys);
    }

    if (auto error = ParsePadding(padding_parts, config);
        error != VlessEncryptionParseError::None) {
        return ParseErrorResult(error);
    }

    return {
        .config = std::move(config),
        .error = VlessEncryptionParseError::None,
    };
}

}  // namespace

bool IsNoVlessEncryption(std::string_view value) noexcept {
    return value.empty() || transport::internet::EqualsAsciiCI(value, "none");
}

VlessEncryptionParseResult ParseVlessClientEncryption(
    std::string_view encryption) {
    if (IsNoVlessEncryption(encryption)) {
        return {};
    }
    return ParseVlessEncryption(encryption, VlessEncryptionRole::Client);
}

VlessEncryptionParseResult ParseVlessServerDecryption(
    std::string_view decryption) {
    if (IsNoVlessEncryption(decryption)) {
        return {};
    }
    return ParseVlessEncryption(decryption, VlessEncryptionRole::Server);
}

std::string_view VlessEncryptionParseErrorMessage(
    VlessEncryptionParseError error) noexcept {
    switch (error) {
    case VlessEncryptionParseError::None:
        return "ok";
    case VlessEncryptionParseError::UnsupportedName:
        return "unsupported encryption name";
    case VlessEncryptionParseError::TooFewParts:
        return "too few dot-separated parts";
    case VlessEncryptionParseError::InvalidMode:
        return "invalid mode";
    case VlessEncryptionParseError::InvalidRtt:
        return "invalid rtt mode";
    case VlessEncryptionParseError::InvalidSeconds:
        return "invalid seconds";
    case VlessEncryptionParseError::InvalidBase64:
        return "invalid raw URL base64 key";
    case VlessEncryptionParseError::InvalidKeyLength:
        return "invalid key length";
    case VlessEncryptionParseError::InvalidKeyMaterial:
        return "invalid key material";
    case VlessEncryptionParseError::EmptyKeys:
        return "missing key material";
    case VlessEncryptionParseError::InvalidPadding:
        return "invalid padding";
    case VlessEncryptionParseError::PaddingTooLarge:
        return "padding too large";
    }
    return "unknown error";
}

// ============================================================================
// Key Exchange (X25519 & ML-KEM-768)
// ============================================================================

namespace {

[[nodiscard]] std::shared_ptr<EVP_PKEY> ShareKey(
    bssl::UniquePtr<EVP_PKEY> key) noexcept {
    if (!key) {
        return nullptr;
    }
    try {
        return std::shared_ptr<EVP_PKEY>(key.release(), EVP_PKEY_free);
    } catch (const std::bad_alloc&) {
        return nullptr;
    }
}

}  // namespace

VlessX25519KeyPair GenerateVlessX25519KeyPair() noexcept {
    VlessX25519KeyPair pair;
    X25519_keypair(pair.public_key.data(), pair.private_key.bytes.data());
    return pair;
}

bool DeriveVlessX25519PublicKey(
    std::span<const uint8_t> private_key,
    std::span<uint8_t, kVlessX25519KeySize> out_public_key) noexcept {
    if (private_key.size() != kVlessX25519KeySize) {
        return false;
    }
    X25519_public_from_private(out_public_key.data(), private_key.data());
    return true;
}

bool ComputeVlessX25519SharedKey(
    std::span<const uint8_t> private_key,
    std::span<const uint8_t> peer_public_key,
    std::span<uint8_t, kVlessX25519KeySize> out_shared) noexcept {
    return private_key.size() == kVlessX25519KeySize &&
           peer_public_key.size() == kVlessX25519KeySize &&
           X25519(out_shared.data(), private_key.data(),
                  peer_public_key.data()) == 1;
}

std::shared_ptr<EVP_PKEY>
CreateVlessMlKem768PrivateKeyFromSeed(
    std::span<const uint8_t> seed) noexcept {
    if (seed.size() != kVlessMlKem768SeedSize) {
        return nullptr;
    }
    // ML-KEM's seed is d || z (64 bytes), not the expanded private key.
    bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_from_private_seed(
        EVP_pkey_ml_kem_768(), seed.data(), seed.size()));
    if (!key) {
        ERR_clear_error();
        return nullptr;
    }
    return ShareKey(std::move(key));
}

std::shared_ptr<EVP_PKEY>
CreateVlessMlKem768PublicKey(
    std::span<const uint8_t> public_key) noexcept {
    if (public_key.size() != kVlessMlKem768PublicKeySize) {
        return nullptr;
    }
    bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_from_raw_public_key(
        EVP_pkey_ml_kem_768(),
        public_key.data(),
        public_key.size()));
    if (!key) {
        ERR_clear_error();
        return nullptr;
    }
    return ShareKey(std::move(key));
}

bssl::UniquePtr<EVP_PKEY> GenerateVlessMlKem768PrivateKey() noexcept {
    bssl::UniquePtr<EVP_PKEY> key(
        EVP_PKEY_generate_from_alg(EVP_pkey_ml_kem_768()));
    if (!key) {
        ERR_clear_error();
    }
    return key;
}

std::optional<std::array<uint8_t, kVlessMlKem768PublicKeySize>>
DeriveVlessMlKem768PublicKey(const EVP_PKEY* key) noexcept {
    if (!key || EVP_PKEY_id(key) != EVP_PKEY_ML_KEM_768) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessMlKem768PublicKeySize> public_key{};
    size_t public_len = public_key.size();
    if (EVP_PKEY_get_raw_public_key(
            key,
            public_key.data(),
            &public_len) != 1 ||
        public_len != public_key.size()) {
        ERR_clear_error();
        return std::nullopt;
    }
    return public_key;
}

std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(const EVP_PKEY* public_key) noexcept {
    if (!public_key) {
        return std::nullopt;
    }

    VlessMlKem768Encapsulation result;
    if (EVP_KEM_encap(
            EVP_kem_ml_kem_768(),
            result.ciphertext.data(),
            result.ciphertext.size(),
            result.shared_secret.bytes.data(),
            result.shared_secret.bytes.size(),
            public_key) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }
    return result;
}

std::optional<VlessMlKem768Encapsulation>
EncapsulateVlessMlKem768(std::span<const uint8_t> public_key) noexcept {
    if (public_key.size() != kVlessMlKem768PublicKeySize) {
        return std::nullopt;
    }

    MLKEM768_public_key key;
    CBS input;
    CBS_init(&input, public_key.data(), public_key.size());
    if (MLKEM768_parse_public_key(&key, &input) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }
    VlessMlKem768Encapsulation result;
    MLKEM768_encap(result.ciphertext.data(), result.shared_secret.bytes.data(),
                   &key);
    return result;
}

bool DecapsulateVlessMlKem768(
    const EVP_PKEY* private_key,
    std::span<const uint8_t> ciphertext,
    std::span<uint8_t, kVlessMlKem768SharedSecretSize> out_shared) noexcept {
    if (!private_key || ciphertext.size() != kVlessMlKem768CiphertextSize) {
        return false;
    }

    if (EVP_KEM_decap(
            EVP_kem_ml_kem_768(),
            out_shared.data(),
            out_shared.size(),
            ciphertext.data(),
            ciphertext.size(),
            private_key) != 1) {
        ERR_clear_error();
        return false;
    }
    return true;
}

// ============================================================================
// AEAD Record Framing
// ============================================================================

namespace {

[[nodiscard]] const EVP_AEAD* ResolveAead(
    VlessEncryptionAeadCipher cipher) noexcept {
    switch (cipher) {
    case VlessEncryptionAeadCipher::Aes256Gcm:
        return EVP_aead_aes_256_gcm();
    case VlessEncryptionAeadCipher::Chacha20Poly1305:
        return EVP_aead_chacha20_poly1305();
    }
    return nullptr;
}

[[nodiscard]] std::array<uint8_t, kVlessEncryptionAeadKeySize>
DeriveAeadKey(std::span<const uint8_t> context,
              std::span<const uint8_t> key) noexcept {
    std::array<uint8_t, kVlessEncryptionAeadKeySize> out{};
    blake3_hasher hasher;
    blake3_hasher_init_derive_key_raw(
        &hasher,
        context.empty() ? nullptr : context.data(),
        context.size());
    if (!key.empty()) {
        blake3_hasher_update(&hasher, key.data(), key.size());
    }
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    OPENSSL_cleanse(&hasher, sizeof(hasher));
    return out;
}

}  // namespace

std::array<uint8_t, kVlessEncryptionLengthSize>
EncodeVlessEncryptionLength(size_t length) noexcept {
    return {
        static_cast<uint8_t>((length >> 8) & 0xffu),
        static_cast<uint8_t>(length & 0xffu),
    };
}

uint16_t DecodeVlessEncryptionLength(
    std::span<const uint8_t, kVlessEncryptionLengthSize> encoded) noexcept {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(encoded[0]) << 8) |
        static_cast<uint16_t>(encoded[1]));
}

bool EncodeVlessEncryptionRecordHeader(
    std::span<uint8_t, kVlessEncryptionRecordHeaderSize> header,
    size_t ciphertext_length) noexcept {
    if (ciphertext_length < kVlessEncryptionMinRecordCiphertextSize ||
        ciphertext_length > kVlessEncryptionMaxRecordCiphertextSize) {
        return false;
    }
    header[0] = 23;
    header[1] = 3;
    header[2] = 3;
    header[3] = static_cast<uint8_t>((ciphertext_length >> 8) & 0xffu);
    header[4] = static_cast<uint8_t>(ciphertext_length & 0xffu);
    return true;
}

std::optional<uint16_t> DecodeVlessEncryptionRecordHeader(
    std::span<const uint8_t, kVlessEncryptionRecordHeaderSize> header) noexcept {
    const auto length = static_cast<uint16_t>(
        (static_cast<uint16_t>(header[3]) << 8) |
        static_cast<uint16_t>(header[4]));
    if (header[0] != 23 || header[1] != 3 || header[2] != 3 ||
        length < kVlessEncryptionMinRecordCiphertextSize ||
        length > kVlessEncryptionMaxRecordCiphertextSize) {
        return std::nullopt;
    }
    return length;
}

void IncreaseVlessEncryptionNonce(
    std::span<uint8_t, kVlessEncryptionNonceSize> nonce) noexcept {
    for (size_t i = 0; i < nonce.size(); ++i) {
        uint8_t& value = nonce[nonce.size() - 1 - i];
        ++value;
        if (value != 0) {
            break;
        }
    }
}

bool IsVlessEncryptionMaxNonce(
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce) noexcept {
    return std::ranges::all_of(nonce, [](uint8_t value) {
        return value == 0xffu;
    });
}

std::optional<VlessEncryptionAead> VlessEncryptionAead::Create(
    std::span<const uint8_t> context,
    std::span<const uint8_t> key,
    VlessEncryptionAeadCipher cipher) noexcept {
    const EVP_AEAD* algorithm = ResolveAead(cipher);
    if (!algorithm) {
        return std::nullopt;
    }

    VlessEncryptionAead aead;
    auto derived = DeriveAeadKey(context, key);
    aead.cipher_ = cipher;
    aead.aead_ctx_.reset(EVP_AEAD_CTX_new(
        algorithm, derived.data(), derived.size(), kVlessEncryptionTagSize));
    OPENSSL_cleanse(derived.data(), derived.size());
    if (!aead.aead_ctx_) {
        ERR_clear_error();
        return std::nullopt;
    }
    return aead;
}

std::optional<size_t> VlessEncryptionAead::Seal(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    if (!aead_ctx_ || output.size() < kVlessEncryptionTagSize ||
        output.size() - kVlessEncryptionTagSize < plaintext.size()) {
        return std::nullopt;
    }
    IncreaseVlessEncryptionNonce(nonce_);
    return SealWithNonce(nonce_, plaintext, additional_data, output);
}

std::optional<size_t> VlessEncryptionAead::SealWithNonce(
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    if (!aead_ctx_ || output.size() < kVlessEncryptionTagSize ||
        output.size() - kVlessEncryptionTagSize < plaintext.size()) {
        return std::nullopt;
    }
    size_t out_len = 0;
    if (EVP_AEAD_CTX_seal(
            aead_ctx_.get(),
            output.data(),
            &out_len,
            output.size(),
            nonce.data(),
            nonce.size(),
            plaintext.data(),
            plaintext.size(),
            additional_data.data(),
            additional_data.size()) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }
    return out_len;
}

std::optional<size_t> VlessEncryptionAead::Open(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    if (!aead_ctx_ || ciphertext.size() < kVlessEncryptionTagSize ||
        output.size() < ciphertext.size() - kVlessEncryptionTagSize) {
        return std::nullopt;
    }
    IncreaseVlessEncryptionNonce(nonce_);
    return OpenWithNonce(nonce_, ciphertext, additional_data, output);
}

std::optional<size_t> VlessEncryptionAead::OpenWithNonce(
    std::span<const uint8_t, kVlessEncryptionNonceSize> nonce,
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> additional_data,
    std::span<uint8_t> output) noexcept {
    if (!aead_ctx_ || ciphertext.size() < kVlessEncryptionTagSize ||
        output.size() < ciphertext.size() - kVlessEncryptionTagSize) {
        return std::nullopt;
    }
    size_t out_len = 0;
    if (EVP_AEAD_CTX_open(
            aead_ctx_.get(),
            output.data(),
            &out_len,
            output.size(),
            nonce.data(),
            nonce.size(),
            ciphertext.data(),
            ciphertext.size(),
            additional_data.data(),
            additional_data.size()) != 1) {
        ERR_clear_error();
        return std::nullopt;
    }
    return out_len;
}

std::optional<size_t> SealVlessEncryptionRecord(
    VlessEncryptionAead& aead,
    std::span<const uint8_t> plaintext,
    std::span<uint8_t> output) noexcept {
    if (plaintext.empty() ||
        plaintext.size() > kVlessEncryptionMaxPlaintextSize ||
        output.size() <
            kVlessEncryptionRecordHeaderSize + plaintext.size() +
                kVlessEncryptionTagSize) {
        return std::nullopt;
    }

    auto header = std::span<uint8_t, kVlessEncryptionRecordHeaderSize>(
        output.data(),
        kVlessEncryptionRecordHeaderSize);
    const size_t ciphertext_length = plaintext.size() + kVlessEncryptionTagSize;
    if (!EncodeVlessEncryptionRecordHeader(header, ciphertext_length)) {
        return std::nullopt;
    }

    auto ciphertext = output.subspan(kVlessEncryptionRecordHeaderSize);
    auto sealed = aead.Seal(plaintext, header, ciphertext);
    if (!sealed || *sealed != ciphertext_length) {
        return std::nullopt;
    }
    return kVlessEncryptionRecordHeaderSize + ciphertext_length;
}

std::optional<size_t> OpenVlessEncryptionRecord(
    VlessEncryptionAead& aead,
    std::span<const uint8_t, kVlessEncryptionRecordHeaderSize> header,
    std::span<const uint8_t> ciphertext,
    std::span<uint8_t> output) noexcept {
    const auto length = DecodeVlessEncryptionRecordHeader(header);
    if (!length || ciphertext.size() != *length) {
        return std::nullopt;
    }
    return aead.Open(ciphertext, header, output);
}

// ============================================================================
// AES-256-CTR Header / Relay XOR
// ============================================================================

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

// ============================================================================
// Handshake Protocol
// ============================================================================

namespace {

constexpr size_t kHashSize = 32;
constexpr size_t kX25519RelaySize = kVlessX25519KeySize;
constexpr size_t kMlKem768RelaySize = kVlessMlKem768CiphertextSize;
constexpr VlessEncryptionPadding kDefaultPaddingLens[] = {
    {100, 111, 1111},
    {50, 0, 3333},
};

[[nodiscard]] bool RandomBytes(std::span<uint8_t> out) noexcept {
    return out.empty() ||
           RAND_bytes(out.data(), static_cast<int>(out.size())) == 1;
}

[[nodiscard]] uint64_t RandomU64() noexcept {
    uint64_t out = 0;
    if (RAND_bytes(reinterpret_cast<uint8_t*>(&out), sizeof(out)) != 1) {
        return 0;
    }
    return out;
}

[[nodiscard]] int64_t RandomBetween(int64_t from, int64_t to) noexcept {
    if (from == to) {
        return from;
    }
    if (from > to) {
        std::swap(from, to);
    }
    const uint64_t diff =
        static_cast<uint64_t>(to) - static_cast<uint64_t>(from);
    if (diff == std::numeric_limits<uint64_t>::max()) {
        return static_cast<int64_t>(RandomU64());
    }
    return from + static_cast<int64_t>(RandomU64() % (diff + 1));
}

[[nodiscard]] std::optional<uint32_t> PickPaddingValue(
    const VlessEncryptionPadding& padding) noexcept {
    if (padding.probability < 0 || padding.from < 0 || padding.to < 0) {
        return std::nullopt;
    }
    if (padding.probability == 0 || padding.probability <= RandomBetween(0, 99)) {
        return 0;
    }
    const int64_t value = RandomBetween(padding.from, padding.to);
    if (value < 0 ||
        value > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
        return std::nullopt;
    }
    return static_cast<uint32_t>(value);
}

[[nodiscard]] bool IsClientKey(const VlessClientPfsKey& key) noexcept {
    if (key.public_key.size() == kVlessX25519KeySize) {
        return !key.mlkem_key;
    }
    if (key.public_key.size() == kVlessMlKem768PublicKeySize) {
        return key.mlkem_key != nullptr;
    }
    return false;
}

[[nodiscard]] bool IsServerKey(const VlessServerPfsKey& key) noexcept {
    if (key.private_key.size() == kVlessX25519KeySize) {
        return key.public_key.size() == kVlessX25519KeySize &&
               !key.mlkem_key;
    }
    if (key.private_key.size() == kVlessMlKem768SeedSize) {
        return key.public_key.size() == kVlessMlKem768PublicKeySize &&
               key.mlkem_key != nullptr;
    }
    return false;
}

template <typename Key>
[[nodiscard]] size_t RelaySize(const Key& key) noexcept {
    return key.mlkem_key ? kMlKem768RelaySize : kX25519RelaySize;
}

[[nodiscard]] std::array<uint8_t, kHashSize> Hash32(
    std::span<const uint8_t> data) noexcept {
    std::array<uint8_t, kHashSize> out{};
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    if (!data.empty()) {
        blake3_hasher_update(&hasher, data.data(), data.size());
    }
    blake3_hasher_finalize(&hasher, out.data(), out.size());
    return out;
}

[[nodiscard]] std::span<const uint8_t, kVlessEncryptionIvSize>
IvSpan(const std::array<uint8_t, kVlessEncryptionIvSize>& iv) noexcept {
    return std::span<const uint8_t, kVlessEncryptionIvSize>(iv);
}

[[nodiscard]] const VlessEncryptionNonce& MaxNonce() noexcept {
    static constexpr VlessEncryptionNonce kMaxNonce = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    return kMaxNonce;
}

[[nodiscard]] uint16_t TicketSeconds(
    const VlessEncryptionConfig& config) noexcept {
    if (config.seconds_from <= 0 && config.seconds_to <= 0) {
        return 0;
    }
    int64_t seconds = 0;
    if (config.seconds_to == 0) {
        seconds = config.seconds_from * RandomBetween(50, 100) / 100;
    } else {
        seconds = RandomBetween(config.seconds_from, config.seconds_to);
    }
    return static_cast<uint16_t>(std::clamp<int64_t>(seconds, 1, 65535));
}

// PFS key layout: ML-KEM-768 shared secret followed by X25519 shared secret.
[[nodiscard]] std::span<uint8_t, kVlessMlKem768SharedSecretSize>
PfsMlKemPart(VlessEncryptionPfsKey& key) noexcept {
    return std::span<uint8_t, kVlessEncryptionPfsKeySize>(key.bytes)
        .first<kVlessMlKem768SharedSecretSize>();
}

[[nodiscard]] std::span<uint8_t, kVlessX25519KeySize>
PfsX25519Part(VlessEncryptionPfsKey& key) noexcept {
    return std::span<uint8_t, kVlessEncryptionPfsKeySize>(key.bytes)
        .subspan<kVlessMlKem768SharedSecretSize>();
}

[[nodiscard]] VlessEncryptionUnitedKey BuildUnitedKey(
    const VlessEncryptionPfsKey& pfs_key,
    const VlessEncryptionNfsKey& nfs_key) noexcept {
    VlessEncryptionUnitedKey out;
    auto next = std::copy(pfs_key.bytes.begin(), pfs_key.bytes.end(),
                          out.bytes.begin());
    std::copy(nfs_key.bytes.begin(), nfs_key.bytes.end(), next);
    return out;
}

[[nodiscard]] std::optional<size_t> PickPaddingLength(
    const VlessEncryptionConfig& config) noexcept {
    const auto lens = config.padding_lens.empty()
        ? std::span<const VlessEncryptionPadding>(kDefaultPaddingLens)
        : std::span<const VlessEncryptionPadding>(config.padding_lens);
    size_t total = 0;
    for (const auto& item : lens) {
        auto length = PickPaddingValue(item);
        if (!length) {
            return std::nullopt;
        }
        total += *length;
        if (total > kVlessEncryptionMaxPaddingLength) {
            return std::nullopt;
        }
    }
    if (total < kVlessEncryptionMinPaddingLength) {
        return std::nullopt;
    }
    return total;
}

}  // namespace

std::optional<size_t> VlessEncryptionRelaysLength(
    const VlessEncryptionConfig& config) noexcept {
    if (config.role == VlessEncryptionRole::Client) {
        if (config.client_keys.empty()) {
            return std::nullopt;
        }
        size_t length = 0;
        for (size_t i = 0; i < config.client_keys.size(); ++i) {
            const auto& key = config.client_keys[i];
            if (!IsClientKey(key)) {
                return std::nullopt;
            }
            length += RelaySize(key);
            if (i + 1 < config.client_keys.size()) {
                length += kHashSize;
            }
        }
        return length;
    }

    if (config.server_keys.empty()) {
        return std::nullopt;
    }
    size_t length = 0;
    for (size_t i = 0; i < config.server_keys.size(); ++i) {
        const auto& key = config.server_keys[i];
        if (!IsServerKey(key)) {
            return std::nullopt;
        }
        length += RelaySize(key);
        if (i + 1 < config.server_keys.size()) {
            length += kHashSize;
        }
    }
    return length;
}

std::optional<VlessEncryptionClientNfsHello>
BuildVlessEncryptionClientNfsHello(
    const VlessEncryptionConfig& config) noexcept {
    if (config.role != VlessEncryptionRole::Client) {
        return std::nullopt;
    }

    const auto relays_length = VlessEncryptionRelaysLength(config);
    if (!relays_length) {
        return std::nullopt;
    }

    VlessEncryptionClientNfsHello hello;
    if (!RandomBytes(hello.iv)) {
        return std::nullopt;
    }
    hello.bytes.resize(hello.iv.size() + *relays_length);
    std::copy(hello.iv.begin(), hello.iv.end(), hello.bytes.begin());

    std::optional<VlessEncryptionCtr> last_ctr;
    auto relays = std::span<uint8_t>(hello.bytes).subspan(hello.iv.size());
    for (size_t i = 0; i < config.client_keys.size(); ++i) {
        const auto& client_key = config.client_keys[i];
        const auto& public_key = client_key.public_key;
        const size_t relay_size = RelaySize(client_key);
        if (relays.size() < relay_size) {
            return std::nullopt;
        }

        std::span<uint8_t> current = relays.first(relay_size);
        if (!client_key.mlkem_key &&
            public_key.size() == kVlessX25519KeySize) {
            const auto pair = GenerateVlessX25519KeyPair();
            std::copy(pair.public_key.begin(), pair.public_key.end(),
                      current.begin());
            if (!ComputeVlessX25519SharedKey(
                    pair.private_key.bytes,
                    public_key,
                    hello.nfs_key.bytes)) {
                return std::nullopt;
            }
        } else if (client_key.mlkem_key &&
                   public_key.size() == kVlessMlKem768PublicKeySize) {
            auto enc = EncapsulateVlessMlKem768(client_key.mlkem_key.get());
            if (!enc) {
                return std::nullopt;
            }
            std::copy(enc->ciphertext.begin(), enc->ciphertext.end(),
                      current.begin());
            hello.nfs_key.bytes = enc->shared_secret.bytes;
        } else {
            return std::nullopt;
        }

        if (config.mode != VlessEncryptionMode::Native &&
            !XorVlessEncryptionInPlace(public_key, IvSpan(hello.iv), current)) {
            return std::nullopt;
        }
        if (last_ctr &&
            !last_ctr->XorInPlace(current.first(kHashSize))) {
            return std::nullopt;
        }
        if (i + 1 == config.client_keys.size()) {
            break;
        }

        relays = relays.subspan(relay_size);
        if (relays.size() < kHashSize) {
            return std::nullopt;
        }

        auto hash = Hash32(config.client_keys[i + 1].public_key);
        std::copy(hash.begin(), hash.end(), relays.begin());
        last_ctr = VlessEncryptionCtr::Create(hello.nfs_key.bytes,
                                              IvSpan(hello.iv));
        if (!last_ctr ||
            !last_ctr->XorInPlace(relays.first(kHashSize))) {
            return std::nullopt;
        }
        relays = relays.subspan(kHashSize);
    }
    return hello;
}

std::optional<VlessEncryptionServerNfsOpenResult>
OpenVlessEncryptionClientNfsHello(
    const VlessEncryptionConfig& config,
    std::span<uint8_t> iv_and_relays) noexcept {
    if (config.role != VlessEncryptionRole::Server ||
        iv_and_relays.size() < kVlessEncryptionIvSize) {
        return std::nullopt;
    }

    const auto relays_length = VlessEncryptionRelaysLength(config);
    if (!relays_length ||
        iv_and_relays.size() != kVlessEncryptionIvSize + *relays_length) {
        return std::nullopt;
    }

    VlessEncryptionServerNfsOpenResult result;
    std::copy_n(iv_and_relays.begin(), result.iv.size(), result.iv.begin());

    std::optional<VlessEncryptionCtr> last_ctr;
    auto relays = iv_and_relays.subspan(result.iv.size());
    for (size_t i = 0; i < config.server_keys.size(); ++i) {
        const auto& server_key = config.server_keys[i];
        const auto& secret_key = server_key.private_key;
        const auto& public_key = server_key.public_key;
        const size_t relay_size = RelaySize(server_key);
        if (relays.size() < relay_size) {
            return std::nullopt;
        }

        std::span<uint8_t> current = relays.first(relay_size);
        if (last_ctr &&
            !last_ctr->XorInPlace(current.first(kHashSize))) {
            return std::nullopt;
        }
        if (config.mode != VlessEncryptionMode::Native &&
            !XorVlessEncryptionInPlace(public_key, IvSpan(result.iv), current)) {
            return std::nullopt;
        }

        if (!server_key.mlkem_key &&
            secret_key.size() == kVlessX25519KeySize) {
            if (current[kVlessX25519KeySize - 1] > 127 ||
                !ComputeVlessX25519SharedKey(secret_key, current,
                                             result.nfs_key.bytes)) {
                return std::nullopt;
            }
        } else if (server_key.mlkem_key &&
                   secret_key.size() == kVlessMlKem768SeedSize) {
            if (!DecapsulateVlessMlKem768(server_key.mlkem_key.get(), current,
                                          result.nfs_key.bytes)) {
                return std::nullopt;
            }
        } else {
            return std::nullopt;
        }

        if (i + 1 == config.server_keys.size()) {
            break;
        }

        relays = relays.subspan(relay_size);
        if (relays.size() < kHashSize) {
            return std::nullopt;
        }
        last_ctr = VlessEncryptionCtr::Create(result.nfs_key.bytes,
                                              IvSpan(result.iv));
        if (!last_ctr ||
            !last_ctr->XorInPlace(relays.first(kHashSize))) {
            return std::nullopt;
        }
        const auto expected_hash = Hash32(config.server_keys[i + 1].public_key);
        if (!std::ranges::equal(expected_hash, relays.first(kHashSize))) {
            return std::nullopt;
        }
        relays = relays.subspan(kHashSize);
    }
    return result;
}

std::optional<VlessEncryptionClientPfsHello>
BuildVlessEncryptionClientPfsHello(
    VlessEncryptionAead& nfs_aead) noexcept {
    VlessEncryptionClientPfsHello hello;
    hello.mlkem_private_key = GenerateVlessMlKem768PrivateKey();
    auto mlkem_public = DeriveVlessMlKem768PublicKey(
        hello.mlkem_private_key.get());
    if (!mlkem_public) {
        return std::nullopt;
    }

    const auto x25519 = GenerateVlessX25519KeyPair();
    hello.x25519_private_key = x25519.private_key;
    std::copy(mlkem_public->begin(), mlkem_public->end(),
              hello.public_key.begin());
    std::copy(x25519.public_key.begin(), x25519.public_key.end(),
              hello.public_key.begin() +
                  static_cast<std::ptrdiff_t>(kVlessMlKem768PublicKeySize));

    const auto encrypted_len = EncodeVlessEncryptionLength(
        kVlessEncryptionEncryptedClientPfsPublicSize);
    auto encrypted = std::span<uint8_t, kVlessEncryptionClientPfsHelloSize>(
        hello.encrypted.data(), kVlessEncryptionClientPfsHelloSize);
    auto sealed_len = nfs_aead.Seal(
        encrypted_len,
        {},
        encrypted.first(kVlessEncryptionEncryptedLengthSize));
    if (!sealed_len || *sealed_len != kVlessEncryptionEncryptedLengthSize) {
        return std::nullopt;
    }

    auto sealed_key = nfs_aead.Seal(
        hello.public_key,
        {},
        encrypted.subspan(kVlessEncryptionEncryptedLengthSize));
    if (!sealed_key ||
        *sealed_key != kVlessEncryptionEncryptedClientPfsPublicSize) {
        return std::nullopt;
    }
    return hello;
}

std::optional<VlessEncryptionServerPfsResponse>
BuildVlessEncryptionServerPfsResponse(
    const VlessEncryptionConfig& config,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    const VlessEncryptionNfsKey& nfs_key,
    std::span<const uint8_t, kVlessEncryptionClientPfsPublicSize>
        client_public_key,
    VlessEncryptionAeadCipher cipher) noexcept {
    if (config.role != VlessEncryptionRole::Server) {
        return std::nullopt;
    }

    // Parsing the client's ML-KEM key here is also its validation.
    auto mlkem_enc = EncapsulateVlessMlKem768(
        client_public_key.first(kVlessMlKem768PublicKeySize));
    if (!mlkem_enc) {
        return std::nullopt;
    }

    VlessEncryptionServerPfsResponse response;
    const auto x25519 = GenerateVlessX25519KeyPair();
    if (!ComputeVlessX25519SharedKey(
            x25519.private_key.bytes,
            client_public_key.subspan(kVlessMlKem768PublicKeySize),
            PfsX25519Part(response.pfs_key))) {
        return std::nullopt;
    }
    std::copy(mlkem_enc->shared_secret.bytes.begin(),
              mlkem_enc->shared_secret.bytes.end(),
              PfsMlKemPart(response.pfs_key).begin());

    std::array<uint8_t, kVlessEncryptionServerPfsPublicSize> public_key{};
    std::copy(mlkem_enc->ciphertext.begin(), mlkem_enc->ciphertext.end(),
              public_key.begin());
    std::copy(x25519.public_key.begin(), x25519.public_key.end(),
              public_key.begin() +
                  static_cast<std::ptrdiff_t>(
                      kVlessMlKem768CiphertextSize));
    response.united_key = BuildUnitedKey(response.pfs_key, nfs_key);

    auto nfs_aead = VlessEncryptionAead::Create(iv, nfs_key.bytes, cipher);
    if (!nfs_aead) {
        return std::nullopt;
    }
    auto sealed_public = nfs_aead->SealWithNonce(
        MaxNonce(),
        public_key,
        {},
        response.encrypted_public_key);
    if (!sealed_public ||
        *sealed_public != kVlessEncryptionEncryptedServerPfsPublicSize) {
        return std::nullopt;
    }

    if (!RandomBytes(response.ticket)) {
        return std::nullopt;
    }
    response.ticket_seconds = TicketSeconds(config);
    const auto encoded_seconds =
        EncodeVlessEncryptionLength(response.ticket_seconds);
    std::copy(encoded_seconds.begin(), encoded_seconds.end(),
              response.ticket.begin());

    auto ticket_aead = VlessEncryptionAead::Create(
        public_key,
        response.united_key.bytes,
        cipher);
    if (!ticket_aead) {
        return std::nullopt;
    }
    auto sealed_ticket = ticket_aead->Seal(
        response.ticket,
        {},
        response.encrypted_ticket);
    if (!sealed_ticket ||
        *sealed_ticket != kVlessEncryptionEncryptedTicketSize) {
        return std::nullopt;
    }
    response.write_aead = std::move(*ticket_aead);
    return response;
}

std::optional<VlessEncryptionClientPfsOpenResult>
OpenVlessEncryptionServerPfsResponse(
    const VlessEncryptionClientPfsHello& client_hello,
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    const VlessEncryptionNfsKey& nfs_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedServerPfsPublicSize>
        encrypted_public_key,
    std::span<const uint8_t, kVlessEncryptionEncryptedTicketSize>
        encrypted_ticket,
    VlessEncryptionAeadCipher cipher) noexcept {
    auto nfs_aead = VlessEncryptionAead::Create(iv, nfs_key.bytes, cipher);
    if (!nfs_aead) {
        return std::nullopt;
    }

    std::array<uint8_t, kVlessEncryptionServerPfsPublicSize> server_public_key{};
    auto opened_public = nfs_aead->OpenWithNonce(
        MaxNonce(),
        encrypted_public_key,
        {},
        server_public_key);
    if (!opened_public ||
        *opened_public != kVlessEncryptionServerPfsPublicSize) {
        return std::nullopt;
    }

    VlessEncryptionClientPfsOpenResult result;
    const auto server_public = std::span<const uint8_t>(server_public_key);
    if (!DecapsulateVlessMlKem768(
            client_hello.mlkem_private_key.get(),
            server_public.first(kVlessMlKem768CiphertextSize),
            PfsMlKemPart(result.pfs_key)) ||
        !ComputeVlessX25519SharedKey(
            client_hello.x25519_private_key.bytes,
            server_public.subspan(kVlessMlKem768CiphertextSize),
            PfsX25519Part(result.pfs_key))) {
        return std::nullopt;
    }
    result.united_key = BuildUnitedKey(result.pfs_key, nfs_key);

    auto ticket_aead = VlessEncryptionAead::Create(
        server_public_key,
        result.united_key.bytes,
        cipher);
    if (!ticket_aead) {
        return std::nullopt;
    }
    auto opened_ticket = ticket_aead->Open(
        encrypted_ticket,
        {},
        result.ticket);
    if (!opened_ticket || *opened_ticket != result.ticket.size()) {
        return std::nullopt;
    }
    result.ticket_seconds = DecodeVlessEncryptionLength(
        std::span<const uint8_t, kVlessEncryptionTicketSize>(result.ticket)
            .first<kVlessEncryptionLengthSize>());
    result.read_aead = std::move(*ticket_aead);
    return result;
}

std::optional<memory::ByteVector> BuildVlessEncryptionPadding(
    const VlessEncryptionConfig& config,
    VlessEncryptionAead& aead) noexcept {
    const auto padding_length = PickPaddingLength(config);
    if (!padding_length) {
        return std::nullopt;
    }

    const size_t encrypted_body_length =
        *padding_length - kVlessEncryptionEncryptedLengthSize;
    const size_t plaintext_body_length =
        encrypted_body_length - kVlessEncryptionTagSize;
    auto encoded_length = EncodeVlessEncryptionLength(encrypted_body_length);

    memory::ByteVector out(*padding_length);
    auto sealed_length = aead.Seal(
        encoded_length,
        {},
        std::span<uint8_t>(out).first(kVlessEncryptionEncryptedLengthSize));
    if (!sealed_length ||
        *sealed_length != kVlessEncryptionEncryptedLengthSize) {
        return std::nullopt;
    }

    // The body is sealed in place over the zero-filled plaintext.
    auto body = std::span<uint8_t>(out).subspan(
        kVlessEncryptionEncryptedLengthSize);
    auto sealed_body = aead.Seal(body.first(plaintext_body_length), {}, body);
    if (!sealed_body || *sealed_body != encrypted_body_length) {
        return std::nullopt;
    }
    return out;
}

std::optional<VlessEncryptionClientZeroRttRequest>
BuildVlessEncryptionClientZeroRttRequest(
    std::span<const uint8_t, kVlessEncryptionIvSize> iv,
    const VlessEncryptionNfsKey& nfs_key,
    const VlessEncryptionPfsKey& pfs_key,
    std::span<const uint8_t, kVlessEncryptionTicketSize> ticket,
    VlessEncryptionAeadCipher cipher) noexcept {
    auto nfs_aead = VlessEncryptionAead::Create(iv, nfs_key.bytes, cipher);
    if (!nfs_aead) {
        return std::nullopt;
    }

    VlessEncryptionClientZeroRttRequest request;
    request.united_key = BuildUnitedKey(pfs_key, nfs_key);
    auto bytes = std::span<uint8_t, kVlessEncryptionZeroRttRequestSize>(
        request.bytes);
    const auto encoded_ticket_len =
        EncodeVlessEncryptionLength(kVlessEncryptionEncryptedTicketSize);
    auto sealed_len = nfs_aead->Seal(
        encoded_ticket_len,
        {},
        bytes.first<kVlessEncryptionEncryptedLengthSize>());
    if (!sealed_len || *sealed_len != kVlessEncryptionEncryptedLengthSize) {
        return std::nullopt;
    }

    auto sealed_ticket = nfs_aead->Seal(
        ticket,
        {},
        bytes.subspan<kVlessEncryptionEncryptedLengthSize>());
    if (!sealed_ticket ||
        *sealed_ticket != kVlessEncryptionEncryptedTicketSize) {
        return std::nullopt;
    }
    return request;
}

std::optional<VlessEncryptionServerZeroRttAccept>
AcceptVlessEncryptionClientZeroRtt(
    const VlessEncryptionNfsKey& nfs_key,
    const VlessEncryptionPfsKey& pfs_key) noexcept {
    VlessEncryptionServerZeroRttAccept accept;
    if (!RandomBytes(accept.server_random)) {
        return std::nullopt;
    }
    accept.united_key = BuildUnitedKey(pfs_key, nfs_key);
    return accept;
}

}  // namespace vless
