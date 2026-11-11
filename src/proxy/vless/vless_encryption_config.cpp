#include "proxy/vless/vless_encryption_config.hpp"
#include "proxy/vless/vless_encryption.hpp"

#include "common/ascii.hpp"
#include "common/binary_text_codec.hpp"
#include "common/scoped_cleanse.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string_view>
#include <utility>
#include <vector>

namespace proxy::vless {
namespace {

constexpr std::string_view kEncryptionName = "mlkem768x25519plus";
constexpr int kFirstPaddingMinProbability = 100;
constexpr int kFirstPaddingMinLength = 18 + 17;
constexpr int kMaxPaddingLength = 18 + 65535;
constexpr int64_t kMaxTicketSeconds = 65535;
// 短于该长度的点分段是填充描述，否则是 base64url 密钥。
constexpr size_t kMinKeyPartLength = 20;

using ParseStep = tl::expected<void, VlessEncryptionParseError>;

[[nodiscard]] bool IsNoVlessEncryption(std::string_view value) noexcept {
    return value.empty() || common::EqualsAsciiCI(value, "none");
}

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

[[nodiscard]] std::optional<VlessEncryptionMode> ParseMode(
    std::string_view value) noexcept {
    if (common::EqualsAsciiCI(value, "native")) {
        return VlessEncryptionMode::Native;
    }
    if (common::EqualsAsciiCI(value, "xorpub")) {
        return VlessEncryptionMode::XorPub;
    }
    if (common::EqualsAsciiCI(value, "random")) {
        return VlessEncryptionMode::Random;
    }
    return std::nullopt;
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

[[nodiscard]] ParseStep ParseRtt(std::string_view value,
                                 VlessEncryptionConfig& config) noexcept {
    if (common::EqualsAsciiCI(value, "1rtt")) {
        config.zero_rtt = false;
        return {};
    }
    if (common::EqualsAsciiCI(value, "0rtt")) {
        config.zero_rtt = true;
        return {};
    }
    return tl::unexpected(VlessEncryptionParseError::InvalidRtt);
}

[[nodiscard]] ParseStep ParseTicketSeconds(std::string_view seconds,
                                           VlessEncryptionConfig& config) noexcept {
    if (seconds.ends_with('s') || seconds.ends_with('S')) {
        seconds.remove_suffix(1);
    }
    const size_t hyphen = seconds.find('-');
    const bool parsed = hyphen == std::string_view::npos
        ? ParseInt(seconds, config.seconds_from)
        : ParseInt(seconds.substr(0, hyphen), config.seconds_from) &&
              ParseInt(seconds.substr(hyphen + 1), config.seconds_to);
    if (!parsed || config.seconds_from > kMaxTicketSeconds ||
        config.seconds_to > kMaxTicketSeconds) {
        return tl::unexpected(VlessEncryptionParseError::InvalidSeconds);
    }
    return {};
}

[[nodiscard]] ParseStep AppendClientKey(std::vector<uint8_t> key,
                                        VlessEncryptionConfig& config) {
    if (key.size() == kVlessX25519KeySize) {
        config.client_keys.push_back(VlessClientPfsKey{
            .public_key = std::move(key),
            .mlkem_key = nullptr,
        });
        return {};
    }
    if (key.size() == kVlessMlKem768PublicKeySize) {
        auto mlkem_key = CreateVlessMlKem768PublicKey(key);
        if (!mlkem_key) {
            return tl::unexpected(VlessEncryptionParseError::InvalidKeyMaterial);
        }
        config.client_keys.push_back(VlessClientPfsKey{
            .public_key = std::move(key),
            .mlkem_key = std::move(mlkem_key),
        });
        return {};
    }
    return tl::unexpected(VlessEncryptionParseError::InvalidKeyLength);
}

[[nodiscard]] ParseStep AppendServerKey(std::vector<uint8_t> key,
                                        VlessEncryptionConfig& config) {
    if (key.size() == kVlessX25519KeySize) {
        std::array<uint8_t, kVlessX25519KeySize> public_key{};
        if (!DeriveVlessX25519PublicKey(key, public_key)) {
            return tl::unexpected(VlessEncryptionParseError::InvalidKeyMaterial);
        }
        config.server_keys.emplace_back(
            std::move(key),
            std::vector<uint8_t>(public_key.begin(), public_key.end()),
            nullptr);
        return {};
    }
    if (key.size() == kVlessMlKem768SeedSize) {
        auto mlkem_key = CreateVlessMlKem768PrivateKeyFromSeed(key);
        auto public_key = DeriveVlessMlKem768PublicKey(mlkem_key.get());
        if (!mlkem_key || !public_key) {
            return tl::unexpected(VlessEncryptionParseError::InvalidKeyMaterial);
        }
        config.server_keys.emplace_back(
            std::move(key),
            std::vector<uint8_t>(public_key->begin(), public_key->end()),
            std::move(mlkem_key));
        return {};
    }
    return tl::unexpected(VlessEncryptionParseError::InvalidKeyLength);
}

[[nodiscard]] ParseStep ParseKey(std::string_view part,
                                 VlessEncryptionConfig& config) {
    std::vector<uint8_t> key(common::Base64UrlDecodedSize(part.size()));
    common::ScopedCleanse cleanse_key{key};
    if (!common::DecodeBase64Url(part, key)) {
        return tl::unexpected(VlessEncryptionParseError::InvalidBase64);
    }
    return config.role == VlessEncryptionRole::Client
        ? AppendClientKey(std::move(key), config)
        : AppendServerKey(std::move(key), config);
}

[[nodiscard]] ParseStep ParsePadding(
    const std::vector<std::string_view>& parts,
    VlessEncryptionConfig& out) {
    int64_t max_len = 0;
    for (size_t i = 0; i < parts.size(); ++i) {
        const auto fields = Split(parts[i], '-');
        if (fields.size() != 3 || fields[0].empty() ||
            fields[1].empty() || fields[2].empty()) {
            return tl::unexpected(VlessEncryptionParseError::InvalidPadding);
        }

        VlessEncryptionPadding padding;
        if (!ParseInt(fields[0], padding.probability) ||
            !ParseInt(fields[1], padding.from) ||
            !ParseInt(fields[2], padding.to) ||
            padding.probability > 100) {
            return tl::unexpected(VlessEncryptionParseError::InvalidPadding);
        }

        if (i == 0 &&
            (padding.probability < kFirstPaddingMinProbability ||
             padding.from < kFirstPaddingMinLength ||
             padding.to < kFirstPaddingMinLength)) {
            return tl::unexpected(VlessEncryptionParseError::InvalidPadding);
        }

        // Odd parts are inter-fragment gaps; the handshake writes padding as
        // one block, so they are validated but not retained.
        if (i % 2 == 0) {
            out.padding_lens.push_back(padding);
            max_len += std::max(padding.from, padding.to);
            if (max_len > kMaxPaddingLength) {
                return tl::unexpected(VlessEncryptionParseError::PaddingTooLarge);
            }
        }
    }
    return {};
}

[[nodiscard]] VlessEncryptionParseResult ParseVlessEncryption(
    std::string_view value,
    VlessEncryptionRole role) {
    if (IsNoVlessEncryption(value)) {
        return std::optional<VlessEncryptionConfig>{};
    }
    const auto parts = Split(value, '.');
    if (parts.size() < 4) {
        return tl::unexpected(VlessEncryptionParseError::TooFewParts);
    }
    if (!common::EqualsAsciiCI(parts[0], kEncryptionName)) {
        return tl::unexpected(VlessEncryptionParseError::UnsupportedName);
    }

    VlessEncryptionConfig config;
    config.role = role;
    const auto mode = ParseMode(parts[1]);
    if (!mode) {
        return tl::unexpected(VlessEncryptionParseError::InvalidMode);
    }
    config.mode = *mode;

    if (auto step = role == VlessEncryptionRole::Client
            ? ParseRtt(parts[2], config)
            : ParseTicketSeconds(parts[2], config);
        !step) {
        return tl::unexpected(step.error());
    }

    std::vector<std::string_view> padding_parts;
    for (size_t i = 3; i < parts.size(); ++i) {
        if (parts[i].size() < kMinKeyPartLength) {
            padding_parts.push_back(parts[i]);
            continue;
        }
        if (auto step = ParseKey(parts[i], config); !step) {
            return tl::unexpected(step.error());
        }
    }

    const bool has_keys = role == VlessEncryptionRole::Client
        ? !config.client_keys.empty()
        : !config.server_keys.empty();
    if (!has_keys) {
        return tl::unexpected(VlessEncryptionParseError::EmptyKeys);
    }
    if (auto step = ParsePadding(padding_parts, config); !step) {
        return tl::unexpected(step.error());
    }
    return std::optional<VlessEncryptionConfig>(std::move(config));
}

}  // namespace

VlessEncryptionParseResult ParseVlessClientEncryption(
    std::string_view encryption) {
    return ParseVlessEncryption(encryption, VlessEncryptionRole::Client);
}

VlessEncryptionParseResult ParseVlessServerDecryption(
    std::string_view decryption) {
    return ParseVlessEncryption(decryption, VlessEncryptionRole::Server);
}

std::string_view VlessEncryptionParseErrorMessage(
    VlessEncryptionParseError error) noexcept {
    switch (error) {
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

}  // namespace proxy::vless
