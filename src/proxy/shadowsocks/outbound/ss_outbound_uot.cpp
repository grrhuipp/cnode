#include "ss_outbound_uot.hpp"

#include <format>
#include <string_view>
#include <utility>

namespace acpp::proxy::shadowsocks::outbound {

namespace {

std::expected<SsUotVersion, std::string> ParseVersionValue(
    const json::value& value,
    std::string_view field) {
    uint64_t raw = 0;
    if (value.is_int64()) {
        const int64_t signed_value = value.as_int64();
        if (signed_value < 0) {
            return std::unexpected(std::format("{} must be 1 or 2", field));
        }
        raw = static_cast<uint64_t>(signed_value);
    } else if (value.is_uint64()) {
        raw = value.as_uint64();
    } else {
        return std::unexpected(std::format("{} must be an integer", field));
    }

    if (raw == 1) return SsUotVersion::V1;
    if (raw == 2) return SsUotVersion::V2;
    return std::unexpected(std::format("{} must be 1 or 2", field));
}

std::expected<std::optional<SsUotVersion>, std::string> ReadTopLevelVersion(
    const json::object& source) {
    std::optional<SsUotVersion> result;
    std::string_view first_key;
    for (const std::string_view key : {"uotVersion"}) {
        const auto* value = source.if_contains(key);
        if (!value) continue;
        auto parsed = ParseVersionValue(*value, key);
        if (!parsed) return std::unexpected(std::move(parsed.error()));
        if (result && *result != *parsed) {
            return std::unexpected(std::format(
                "{} and {} must match", first_key, key));
        }
        if (!result) {
            result = *parsed;
            first_key = key;
        }
    }
    return result;
}

std::expected<std::optional<SsUotVersion>, std::string> ParseActivation(
    const json::value& value,
    std::string_view field,
    std::optional<SsUotVersion> top_level_version) {
    if (value.is_bool()) {
        if (!value.as_bool()) {
            if (top_level_version) {
                return std::unexpected(std::format(
                    "{} is disabled but a UoT version is configured", field));
            }
            return std::optional<SsUotVersion>{};
        }
        return std::optional<SsUotVersion>{
            top_level_version.value_or(SsUotVersion::V2)};
    }

    if (!value.is_object()) {
        return std::unexpected(std::format(
            "{} must be a boolean or object", field));
    }
    if (top_level_version) {
        return std::unexpected(std::format(
            "top-level UoT version cannot be combined with {} object", field));
    }

    const auto& object = value.as_object();
    bool enabled = true;
    if (const auto* enabled_value = object.if_contains("enabled")) {
        if (!enabled_value->is_bool()) {
            return std::unexpected(std::format(
                "{}.enabled must be a boolean", field));
        }
        enabled = enabled_value->as_bool();
    }

    const auto* version_value = object.if_contains("version");
    if (!enabled) {
        if (version_value) {
            return std::unexpected(std::format(
                "{} is disabled but version is configured", field));
        }
        return std::optional<SsUotVersion>{};
    }
    if (!version_value) {
        return std::optional<SsUotVersion>{SsUotVersion::V2};
    }
    auto version = ParseVersionValue(*version_value, std::format("{}.version", field));
    if (!version) return std::unexpected(std::move(version.error()));
    return std::optional<SsUotVersion>{*version};
}

}  // namespace

std::expected<std::optional<SsUotVersion>, std::string>
ParseUotVersion(const json::object& source) {
    auto top_level_version = ReadTopLevelVersion(source);
    if (!top_level_version) {
        return std::unexpected(std::move(top_level_version.error()));
    }

    const auto* uot = source.if_contains("uot");
    if (!uot) {
        if (*top_level_version) {
            return std::unexpected("UoT version requires uot");
        }
        return std::optional<SsUotVersion>{};
    }
    return ParseActivation(*uot, "uot", *top_level_version);
}

}  // namespace acpp::proxy::shadowsocks::outbound
