#include "vless_encryption.hpp"

#include "vless_encryption_crypto.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <limits>
#include <string>

namespace acpp::vless {
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

[[nodiscard]] int Base64RawUrlValue(char c) noexcept {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 'a' + 26;
    }
    if (c >= '0' && c <= '9') {
        return c - '0' + 52;
    }
    if (c == '-') {
        return 62;
    }
    if (c == '_') {
        return 63;
    }
    return -1;
}

[[nodiscard]] std::optional<std::vector<uint8_t>> DecodeRawUrlBase64(
    std::string_view value) {
    if (value.empty() || value.find('=') != std::string_view::npos ||
        value.size() % 4 == 1) {
        return std::nullopt;
    }

    std::vector<uint8_t> out;
    out.reserve(value.size() * 3 / 4);
    uint32_t bits = 0;
    int bit_count = 0;
    for (char c : value) {
        const int v = Base64RawUrlValue(c);
        if (v < 0) {
            return std::nullopt;
        }
        bits = (bits << 6) | static_cast<uint32_t>(v);
        bit_count += 6;
        if (bit_count >= 8) {
            bit_count -= 8;
            out.push_back(static_cast<uint8_t>((bits >> bit_count) & 0xff));
        }
    }
    return out;
}

[[nodiscard]] VlessEncryptionParseError ParseMode(
    std::string_view value,
    VlessEncryptionMode& out) noexcept {
    if (value == "native") {
        out = VlessEncryptionMode::Native;
        return VlessEncryptionParseError::None;
    }
    if (value == "xorpub") {
        out = VlessEncryptionMode::XorPub;
        return VlessEncryptionParseError::None;
    }
    if (value == "random") {
        out = VlessEncryptionMode::Random;
        return VlessEncryptionParseError::None;
    }
    return VlessEncryptionParseError::InvalidMode;
}

[[nodiscard]] std::vector<std::string_view> SplitDot(std::string_view value) {
    std::vector<std::string_view> parts;
    size_t start = 0;
    while (start <= value.size()) {
        const size_t dot = value.find('.', start);
        if (dot == std::string_view::npos) {
            parts.push_back(value.substr(start));
            break;
        }
        parts.push_back(value.substr(start, dot - start));
        start = dot + 1;
    }
    return parts;
}

[[nodiscard]] std::vector<std::string_view> SplitHyphen(std::string_view value) {
    std::vector<std::string_view> parts;
    size_t start = 0;
    while (start <= value.size()) {
        const size_t hyphen = value.find('-', start);
        if (hyphen == std::string_view::npos) {
            parts.push_back(value.substr(start));
            break;
        }
        parts.push_back(value.substr(start, hyphen - start));
        start = hyphen + 1;
    }
    return parts;
}

[[nodiscard]] VlessEncryptionParseError ParsePadding(
    const std::vector<std::string_view>& parts,
    VlessEncryptionConfig& out) {
    int max_len = 0;
    for (size_t i = 0; i < parts.size(); ++i) {
        const auto fields = SplitHyphen(parts[i]);
        if (fields.size() < 3 || fields[0].empty() ||
            fields[1].empty() || fields[2].empty()) {
            return VlessEncryptionParseError::InvalidPadding;
        }

        VlessEncryptionPadding padding;
        if (!ParseInt(fields[0], padding.probability) ||
            !ParseInt(fields[1], padding.from) ||
            !ParseInt(fields[2], padding.to)) {
            return VlessEncryptionParseError::InvalidPadding;
        }

        if (i == 0 &&
            (padding.probability < kFirstPaddingMinProbability ||
             padding.from < kFirstPaddingMinLength ||
             padding.to < kFirstPaddingMinLength)) {
            return VlessEncryptionParseError::InvalidPadding;
        }

        if (i % 2 == 0) {
            out.padding_lens.push_back(padding);
            max_len += std::max(padding.from, padding.to);
            if (max_len > kMaxPaddingLength) {
                return VlessEncryptionParseError::PaddingTooLarge;
            }
        } else {
            out.padding_gaps.push_back(padding);
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
    auto parts = SplitDot(value);
    if (parts.size() < 4) {
        return ParseErrorResult(VlessEncryptionParseError::TooFewParts);
    }
    if (parts[0] != kEncryptionName) {
        return ParseErrorResult(VlessEncryptionParseError::UnsupportedName);
    }

    VlessEncryptionConfig config;
    config.role = role;
    if (auto error = ParseMode(parts[1], config.mode);
        error != VlessEncryptionParseError::None) {
        return ParseErrorResult(error);
    }

    if (role == VlessEncryptionRole::Client) {
        if (parts[2] == "1rtt") {
            config.zero_rtt = false;
        } else if (parts[2] == "0rtt") {
            config.zero_rtt = true;
        } else {
            return ParseErrorResult(VlessEncryptionParseError::InvalidRtt);
        }
    } else {
        std::string_view seconds = parts[2];
        if (seconds.ends_with('s')) {
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
    }

    std::vector<std::string_view> padding_parts;
    for (size_t i = 3; i < parts.size(); ++i) {
        std::string_view part = parts[i];
        if (part.size() < 20) {
            padding_parts.push_back(part);
            continue;
        }

        auto key = DecodeRawUrlBase64(part);
        if (!key) {
            return ParseErrorResult(VlessEncryptionParseError::InvalidBase64);
        }
        const size_t len = key->size();
        const bool key_ok = role == VlessEncryptionRole::Client
            ? (len == kVlessX25519KeySize ||
               len == kVlessMlKem768PublicKeySize)
            : (len == kVlessX25519KeySize ||
               len == kVlessMlKem768SeedSize);
        if (!key_ok) {
            return ParseErrorResult(VlessEncryptionParseError::InvalidKeyLength);
        }
        if (role == VlessEncryptionRole::Client &&
            len == kVlessMlKem768PublicKeySize &&
            !ValidateVlessMlKem768PublicKey(*key)) {
            return ParseErrorResult(VlessEncryptionParseError::InvalidKeyMaterial);
        }
        if (role == VlessEncryptionRole::Server &&
            len == kVlessMlKem768SeedSize &&
            !DeriveVlessMlKem768PublicKeyFromSeed(*key)) {
            return ParseErrorResult(VlessEncryptionParseError::InvalidKeyMaterial);
        }
        config.keys.push_back(std::move(*key));
    }

    if (config.keys.empty()) {
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
    return value.empty() || value == "none";
}

uint32_t VlessEncryptionXorModeValue(VlessEncryptionMode mode) noexcept {
    switch (mode) {
    case VlessEncryptionMode::Native:
        return 0;
    case VlessEncryptionMode::XorPub:
        return 1;
    case VlessEncryptionMode::Random:
        return 2;
    }
    return 0;
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

}  // namespace acpp::vless
