#pragma once

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace acpp::vless {

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
    EmptyKeys,
    InvalidPadding,
    PaddingTooLarge,
};

struct VlessEncryptionPadding {
    int probability = 0;
    int from = 0;
    int to = 0;
};

struct VlessEncryptionConfig {
    VlessEncryptionRole role = VlessEncryptionRole::Client;
    VlessEncryptionMode mode = VlessEncryptionMode::Native;
    bool zero_rtt = false;
    int64_t seconds_from = 0;
    int64_t seconds_to = 0;
    std::vector<std::vector<uint8_t>> keys;
    std::vector<VlessEncryptionPadding> padding_lens;
    std::vector<VlessEncryptionPadding> padding_gaps;
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

}  // namespace acpp::vless
