#pragma once

#include "acppnode/infra/json.hpp"

#include <cstdint>
#include <initializer_list>
#include <limits>
#include <string_view>

namespace acpp {

enum class JsonPortError {
    None,
    Missing,
    InvalidType,
    OutOfRange,
};

struct JsonPortResult {
    JsonPortError error = JsonPortError::Missing;
    uint16_t value = 0;

    [[nodiscard]] bool Valid() const noexcept {
        return error == JsonPortError::None;
    }

    [[nodiscard]] bool Invalid() const noexcept {
        return error == JsonPortError::InvalidType ||
               error == JsonPortError::OutOfRange;
    }
};

[[nodiscard]] inline JsonPortResult ReadJsonPort(
    const json::object& source,
    std::initializer_list<std::string_view> keys) noexcept {
    for (const std::string_view key : keys) {
        const auto* raw = source.if_contains(key);
        if (!raw) {
            continue;
        }

        uint64_t value = 0;
        if (raw->is_int64()) {
            const int64_t signed_value = raw->as_int64();
            if (signed_value <= 0) {
                return {.error = JsonPortError::OutOfRange};
            }
            value = static_cast<uint64_t>(signed_value);
        } else if (raw->is_uint64()) {
            value = raw->as_uint64();
        } else {
            return {.error = JsonPortError::InvalidType};
        }

        if (value == 0 || value > std::numeric_limits<uint16_t>::max()) {
            return {.error = JsonPortError::OutOfRange};
        }
        return {
            .error = JsonPortError::None,
            .value = static_cast<uint16_t>(value),
        };
    }
    return {};
}

}  // namespace acpp
