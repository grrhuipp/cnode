#include "ss_outbound_uot.hpp"

#include "infra/json_field.hpp"

#include <format>
#include <string_view>
#include <utility>

namespace proxy::shadowsocks::outbound {

namespace {

tl::expected<SsUotVersion, std::string> ParseVersionValue(
    const json::value& value,
    std::string_view field) {
    const auto raw = JsonUnsignedInteger(value);
    if (!raw) {
        return tl::unexpected(std::format("{} must be 1 or 2", field));
    }

    if (*raw == 1) return SsUotVersion::V1;
    if (*raw == 2) return SsUotVersion::V2;

    return tl::unexpected(std::format("{} must be 1 or 2", field));
}

tl::expected<std::optional<SsUotVersion>, std::string> ReadTopLevelVersion(
    const json::object& source) {
    const auto* value = source.if_contains("uotVersion");
    if (!value) {
        return std::optional<SsUotVersion>{};
    }
    auto parsed = ParseVersionValue(*value, "uotVersion");
    if (!parsed) {
        return tl::unexpected(std::move(parsed.error()));
    }
    return std::optional<SsUotVersion>{*parsed};
}

tl::expected<std::optional<SsUotVersion>, std::string> ParseActivation(
    const json::value& value,
    std::string_view field,
    std::optional<SsUotVersion> top_level_version) {
    if (value.is_bool()) {
        if (!value.as_bool()) {
            if (top_level_version) {
                return tl::unexpected(std::format(
                    "{} is disabled but a UoT version is configured", field));
            }
            return std::optional<SsUotVersion>{};
        }
        return std::optional<SsUotVersion>{
            top_level_version.value_or(SsUotVersion::V2)};
    }

    if (!value.is_object()) {
        return tl::unexpected(std::format(
            "{} must be a boolean or object", field));
    }
    if (top_level_version) {
        return tl::unexpected(std::format(
            "top-level UoT version cannot be combined with {} object", field));
    }

    const auto& object = value.as_object();
    bool enabled = true;
    if (const auto* enabled_value = object.if_contains("enabled")) {
        if (!enabled_value->is_bool()) {
            return tl::unexpected(std::format(
                "{}.enabled must be a boolean", field));
        }
        enabled = enabled_value->as_bool();
    }

    const auto* version_value = object.if_contains("version");
    if (!enabled) {
        if (version_value) {
            return tl::unexpected(std::format(
                "{} is disabled but version is configured", field));
        }
        return std::optional<SsUotVersion>{};
    }
    if (!version_value) {
        return std::optional<SsUotVersion>{SsUotVersion::V2};
    }
    auto version = ParseVersionValue(*version_value, std::format("{}.version", field));
    if (!version) return tl::unexpected(std::move(version.error()));
    return std::optional<SsUotVersion>{*version};
}

}  // namespace

tl::expected<std::optional<SsUotVersion>, std::string>
ParseUotVersion(const json::object& source) {
    auto top_level_version = ReadTopLevelVersion(source);
    if (!top_level_version) {
        return tl::unexpected(std::move(top_level_version.error()));
    }

    const auto* uot = source.if_contains("uot");
    if (!uot) {
        if (*top_level_version) {
            return tl::unexpected("UoT version requires uot");
        }
        return std::optional<SsUotVersion>{};
    }
    return ParseActivation(*uot, "uot", *top_level_version);
}

}  // namespace proxy::shadowsocks::outbound
