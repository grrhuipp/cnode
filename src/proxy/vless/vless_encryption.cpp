#include "vless_encryption.hpp"

#include "vless_encryption_crypto.hpp"
#include "common/binary_text_codec.hpp"
#include "transport/internet/http_headers.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <limits>
#include <string>

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

}  // namespace vless
