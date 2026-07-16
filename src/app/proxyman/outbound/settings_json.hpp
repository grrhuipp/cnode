#pragma once

#include "acppnode/infra/json.hpp"

#include <cstdint>
#include <initializer_list>
#include <limits>
#include <string_view>

namespace acpp::proxyman::outbound {

struct ParsedPort {
    bool present = false;
    bool valid = true;
    uint16_t value = 0;
};

[[nodiscard]] inline ParsedPort ParsePort(
    const json::object& settings,
    std::initializer_list<std::string_view> keys) noexcept {
    for (const std::string_view key : keys) {
        const auto* raw = settings.if_contains(key);
        if (!raw) {
            continue;
        }

        uint64_t value = 0;
        if (raw->is_int64()) {
            const int64_t signed_value = raw->as_int64();
            if (signed_value <= 0) {
                return {.present = true, .valid = false};
            }
            value = static_cast<uint64_t>(signed_value);
        } else if (raw->is_uint64()) {
            value = raw->as_uint64();
        } else {
            return {.present = true, .valid = false};
        }

        if (value == 0 || value > std::numeric_limits<uint16_t>::max()) {
            return {.present = true, .valid = false};
        }
        return {
            .present = true,
            .valid = true,
            .value = static_cast<uint16_t>(value),
        };
    }
    return {};
}

}  // namespace acpp::proxyman::outbound
