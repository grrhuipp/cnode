#pragma once

#include "common/binary_text_codec.hpp"
#include "common/byte_reader.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <tl/expected.hpp>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace transport::internet {

inline constexpr std::size_t kRealityKeySize = 32;
inline constexpr std::size_t kRealityMldsa65PublicKeySize = 1952;
inline constexpr std::size_t kRealityMldsa65SignatureSize = 3309;

using RealityKey = std::array<uint8_t, kRealityKeySize>;
using RealityMldsa65PublicKey = std::array<uint8_t, kRealityMldsa65PublicKeySize>;

enum class RealityKeyError {
    InvalidFormat,
};

[[nodiscard]] tl::expected<RealityKey, RealityKeyError>
ParseRealityKey(std::string_view value) noexcept;

[[nodiscard]] tl::expected<RealityKey, RealityKeyError>
ParseRealityMldsa65Seed(std::string_view value) noexcept;

[[nodiscard]] tl::expected<RealityMldsa65PublicKey, RealityKeyError>
ParseRealityMldsa65PublicKey(std::string_view value) noexcept;

[[nodiscard]] std::optional<std::string>
NormalizeRealityFingerprint(std::string_view value);

inline constexpr std::size_t kRealityShortIdSize = 8;
using RealityShortId = std::array<uint8_t, kRealityShortIdSize>;

enum class RealityShortIdError {
    InvalidFormat,
};

[[nodiscard]] inline tl::expected<RealityShortId, RealityShortIdError>
ParseRealityShortId(std::string_view value) noexcept {
    if (value.size() % 2 != 0 || value.size() > kRealityShortIdSize * 2) {
        return tl::unexpected(RealityShortIdError::InvalidFormat);
    }

    RealityShortId parsed{};
    for (std::size_t i = 0; i < value.size(); i += 2) {
        const int high = HexDigitValue(value[i]);
        const int low = HexDigitValue(value[i + 1]);
        if (high < 0 || low < 0) {
            return tl::unexpected(RealityShortIdError::InvalidFormat);
        }
        parsed[i / 2] = static_cast<uint8_t>((high << 4) | low);
    }
    return parsed;
}

using RealityClientVersion = std::array<uint8_t, 4>;

enum class RealityClientVersionError {
    InvalidFormat,
};

[[nodiscard]] inline tl::expected<
    std::optional<RealityClientVersion>, RealityClientVersionError>
ParseRealityClientVersion(std::string_view value) noexcept {
    if (value.empty()) {
        return std::optional<RealityClientVersion>{};
    }

    RealityClientVersion version{};
    size_t part = 0;
    size_t start = 0;
    while (true) {
        if (part >= 3) {
            return tl::unexpected(RealityClientVersionError::InvalidFormat);
        }
        const size_t dot = value.find('.', start);
        const size_t end = dot == std::string_view::npos ? value.size() : dot;
        if (end == start) {
            return tl::unexpected(RealityClientVersionError::InvalidFormat);
        }
        uint32_t parsed = 0;
        for (char ch : value.substr(start, end - start)) {
            if (ch < '0' || ch > '9') {
                return tl::unexpected(RealityClientVersionError::InvalidFormat);
            }
            parsed = parsed * 10u + static_cast<uint32_t>(ch - '0');
            if (parsed > 255u) {
                return tl::unexpected(RealityClientVersionError::InvalidFormat);
            }
        }
        version[part++] = static_cast<uint8_t>(parsed);
        if (dot == std::string_view::npos) {
            break;
        }
        start = dot + 1;
    }
    return std::optional<RealityClientVersion>{version};
}

[[nodiscard]] inline uint32_t RealityClientVersionValue(
    std::span<const uint8_t, 4> version) noexcept {
    return LoadU32BE(version.data());
}

}  // namespace transport::internet
