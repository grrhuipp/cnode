#pragma once

#include "common/byte_reader.hpp"

#include <array>
#include <cstdint>
#include <tl/expected.hpp>
#include <optional>
#include <span>
#include <string_view>

namespace transport::internet {

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
