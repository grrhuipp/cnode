#include "user_list_json.hpp"

#include "infra/json_field.hpp"
#include "core/naming.hpp"
#include "panel_json_compat.hpp"

#include <format>
#include <limits>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace api::v2board {

namespace {

constexpr uint64_t kBytesPerSecondPerMbps = 1024ULL * 1024ULL / 8ULL;
constexpr uint64_t kMaxSpeedLimitMbps =
    std::numeric_limits<uint64_t>::max() / kBytesPerSecondPerMbps;

tl::expected<uint64_t, std::string> ParseOptionalLimit(
    const json::object& source,
    std::string_view field,
    size_t user_index) {
    const auto* value = source.if_contains(field);
    if (!value || value->is_null()) return 0;

    const auto limit = PanelUnsignedInteger(*value);
    if (!limit) {
        return tl::unexpected(std::format(
            "users[{}].{} must be a non-negative integer or null", user_index, field));
    }
    return *limit;
}

bool ContainsControlCharacter(std::string_view value) noexcept {
    for (const unsigned char ch : value) {
        if (ch < 0x20 || ch == 0x7f) {
            return true;
        }
    }
    return false;
}

tl::expected<std::string, std::string> ParseOptionalString(
    const json::object& source,
    std::string_view field,
    size_t user_index) {
    const auto* value = source.if_contains(field);
    if (!value || value->is_null()) return std::string{};
    if (!value->is_string()) {
        return tl::unexpected(std::format(
            "users[{}].{} must be a string or null", user_index, field));
    }
    if (ContainsControlCharacter(value->as_string())) {
        return tl::unexpected(std::format(
            "users[{}].{} contains control characters", user_index, field));
    }
    return std::string(value->as_string());
}

}  // namespace

tl::expected<std::vector<::api::UserInfo>, std::string>
ParseUserList(const json::object& source) {
    const auto* users_value = source.if_contains("users");
    if (!users_value) {
        return tl::unexpected("users is required");
    }
    if (!users_value->is_array()) {
        return tl::unexpected("users must be an array");
    }

    const auto& users_array = users_value->as_array();
    std::vector<::api::UserInfo> users;
    users.reserve(users_array.size());
    // A repeated id would merge accounting for two users. Credentials are
    // compared after protocol derivation, when the UserStore snapshot is built.
    std::unordered_set<int64_t> seen_ids;
    seen_ids.reserve(users_array.size());
    for (size_t i = 0; i < users_array.size(); ++i) {
        const auto& user_value = users_array[i];
        if (!user_value.is_object()) {
            return tl::unexpected(std::format("users[{}] must be an object", i));
        }
        const auto& source_user = user_value.as_object();
        ::api::UserInfo user;

        const auto* id = source_user.if_contains("id");
        const auto parsed_id = id ? PanelUnsignedInteger(*id) : std::nullopt;
        if (!parsed_id || *parsed_id == 0 ||
            *parsed_id > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) {
            return tl::unexpected(std::format(
                "users[{}].id must be a positive int64", i));
        }
        user.UID = static_cast<int64_t>(*parsed_id);
        if (!seen_ids.insert(user.UID).second) {
            return tl::unexpected(std::format("users[{}].id duplicates another user", i));
        }

        const auto* uuid = source_user.if_contains("uuid");
        if (!uuid || !uuid->is_string() || uuid->as_string().empty()) {
            return tl::unexpected(std::format(
                "users[{}].uuid must be a non-empty string", i));
        }
        if (ContainsControlCharacter(uuid->as_string())) {
            return tl::unexpected(std::format(
                "users[{}].uuid contains control characters", i));
        }
        user.UUID = std::string(uuid->as_string());

        auto flow = ParseOptionalString(source_user, "flow", i);
        if (!flow) return tl::unexpected(std::move(flow.error()));
        user.Flow = naming::LowerAscii(std::move(*flow));

        auto speed_limit = ParseOptionalLimit(source_user, "speed_limit", i);
        if (!speed_limit) {
            return tl::unexpected(std::move(speed_limit.error()));
        }
        if (*speed_limit > kMaxSpeedLimitMbps) {
            return tl::unexpected(std::format(
                "users[{}].speed_limit exceeds {} Mbps",
                i, kMaxSpeedLimitMbps));
        }
        user.SpeedLimit = *speed_limit * kBytesPerSecondPerMbps;

        auto device_limit = ParseOptionalLimit(source_user, "device_limit", i);
        if (!device_limit) {
            return tl::unexpected(std::move(device_limit.error()));
        }
        if (*device_limit > std::numeric_limits<uint32_t>::max()) {
            return tl::unexpected(std::format(
                "users[{}].device_limit exceeds {}",
                i, std::numeric_limits<uint32_t>::max()));
        }
        user.DeviceLimit = static_cast<uint32_t>(*device_limit);

        auto email = ParseOptionalString(source_user, "email", i);
        if (!email) return tl::unexpected(std::move(email.error()));
        user.Email = std::move(*email);
        users.push_back(std::move(user));
    }
    return users;
}

}  // namespace api::v2board
