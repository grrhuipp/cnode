#include "user_list_json.hpp"

#include <format>
#include <limits>
#include <string>
#include <utility>

namespace acpp::api::v2board {

namespace {

constexpr uint64_t kBytesPerSecondPerMbps = 1024ULL * 1024ULL / 8ULL;
constexpr uint64_t kMaxSpeedLimitMbps =
    std::numeric_limits<uint64_t>::max() / kBytesPerSecondPerMbps;

std::expected<uint64_t, std::string> ParseOptionalLimit(
    const json::object& source,
    std::string_view field,
    size_t user_index) {
    const auto* value = source.if_contains(field);
    if (!value || value->is_null()) return 0;

    if (value->is_int64()) {
        const int64_t signed_value = value->as_int64();
        if (signed_value < 0) {
            return std::unexpected(std::format(
                "users[{}].{} must not be negative", user_index, field));
        }
        return static_cast<uint64_t>(signed_value);
    }
    if (value->is_uint64()) return value->as_uint64();
    return std::unexpected(std::format(
        "users[{}].{} must be an integer or null", user_index, field));
}

std::expected<std::string, std::string> ParseOptionalString(
    const json::object& source,
    std::string_view field,
    size_t user_index) {
    const auto* value = source.if_contains(field);
    if (!value || value->is_null()) return std::string{};
    if (!value->is_string()) {
        return std::unexpected(std::format(
            "users[{}].{} must be a string or null", user_index, field));
    }
    return std::string(value->as_string());
}

}  // namespace

std::expected<std::vector<::acpp::api::UserInfo>, std::string>
ParseUserList(const json::object& source) {
    const auto* users_value = source.if_contains("users");
    if (!users_value) {
        return std::unexpected("users is required");
    }
    if (!users_value->is_array()) {
        return std::unexpected("users must be an array");
    }

    const auto& users_array = users_value->as_array();
    std::vector<::acpp::api::UserInfo> users;
    users.reserve(users_array.size());
    for (size_t i = 0; i < users_array.size(); ++i) {
        const auto& user_value = users_array[i];
        if (!user_value.is_object()) {
            return std::unexpected(std::format("users[{}] must be an object", i));
        }
        const auto& source_user = user_value.as_object();
        ::acpp::api::UserInfo user;

        const auto* id = source_user.if_contains("id");
        if (!id || !id->is_int64() || id->as_int64() <= 0) {
            return std::unexpected(std::format(
                "users[{}].id must be a positive int64", i));
        }
        user.UID = id->as_int64();

        const auto* uuid = source_user.if_contains("uuid");
        if (!uuid || !uuid->is_string() || uuid->as_string().empty()) {
            return std::unexpected(std::format(
                "users[{}].uuid must be a non-empty string", i));
        }
        user.UUID = std::string(uuid->as_string());
        user.Passwd = user.UUID;

        auto flow = ParseOptionalString(source_user, "flow", i);
        if (!flow) return std::unexpected(std::move(flow.error()));
        user.Flow = std::move(*flow);

        auto speed_limit = ParseOptionalLimit(source_user, "speed_limit", i);
        if (!speed_limit) {
            return std::unexpected(std::move(speed_limit.error()));
        }
        if (*speed_limit > kMaxSpeedLimitMbps) {
            return std::unexpected(std::format(
                "users[{}].speed_limit exceeds {} Mbps",
                i, kMaxSpeedLimitMbps));
        }
        user.SpeedLimit = *speed_limit * kBytesPerSecondPerMbps;

        auto device_limit = ParseOptionalLimit(source_user, "device_limit", i);
        if (!device_limit) {
            return std::unexpected(std::move(device_limit.error()));
        }
        if (*device_limit > std::numeric_limits<uint32_t>::max()) {
            return std::unexpected(std::format(
                "users[{}].device_limit exceeds {}",
                i, std::numeric_limits<uint32_t>::max()));
        }
        user.DeviceLimit = static_cast<uint32_t>(*device_limit);

        auto email = ParseOptionalString(source_user, "email", i);
        if (!email) return std::unexpected(std::move(email.error()));
        user.Email = std::move(*email);
        if (user.Email.empty()) user.Email = std::to_string(user.UID);
        user.Enabled = true;
        users.push_back(std::move(user));
    }
    return users;
}

}  // namespace acpp::api::v2board
