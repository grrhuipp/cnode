#pragma once

#include "api/api.hpp"
#include "common/ascii.hpp"
#include "infra/json.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tl/expected.hpp>
#include <vector>

namespace api::v2board {

// PHP encodes an empty associative-array configuration as [] instead of {}.
[[nodiscard]] inline bool IsPanelEmptyObject(const json::value& value) noexcept {
    return value.is_array() && value.as_array().empty();
}

[[nodiscard]] inline bool ContainsControlCharacter(std::string_view value) noexcept {
    for (const unsigned char ch : value) {
        if (ch < 0x20 || ch == 0x7f) {
            return true;
        }
    }
    return false;
}

[[nodiscard]] inline std::optional<uint64_t> PanelUnsignedInteger(
    const json::value& value) noexcept {
    if (const auto parsed = JsonUnsignedInteger(value)) {
        return parsed;
    }
    if (!value.is_string()) {
        return std::nullopt;
    }

    const std::string_view text = value.as_string();
    uint64_t parsed = 0;
    const auto [end, error] = std::from_chars(
        text.data(), text.data() + text.size(), parsed);
    if (text.empty() || error != std::errc{} ||
        end != text.data() + text.size()) {
        return std::nullopt;
    }
    return parsed;
}

[[nodiscard]] inline std::optional<bool> PanelBoolean(
    const json::value& value) noexcept {
    if (value.is_bool()) {
        return value.as_bool();
    }
    if (const auto number = PanelUnsignedInteger(value); number && *number <= 1) {
        return *number == 1;
    }
    if (value.is_string()) {
        const std::string_view text = value.as_string();
        if (EqualsAsciiCI(text, "true")) {
            return true;
        }
        if (EqualsAsciiCI(text, "false")) {
            return false;
        }
    }
    return std::nullopt;
}

struct OnlineReportPayload {
    json::object alive_body;
    size_t user_count = 0;
    size_t device_count = 0;
};

[[nodiscard]] tl::expected<::api::NodeInfo, std::string> ParseNodeInfo(
    const json::object& source,
    std::string_view node_type);

[[nodiscard]] std::vector<rule::DetectRule> ExtractBlockDetectRules(
    const json::object& config);

[[nodiscard]] tl::expected<std::vector<::api::UserInfo>, std::string>
ParseUserList(const json::object& source);

[[nodiscard]] OnlineReportPayload BuildOnlineReportPayload(
    std::span<const ::api::OnlineUser> online_devices,
    int node_id);

}  // namespace api::v2board
