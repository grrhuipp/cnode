#pragma once

#include "infra/config_types.hpp"
#include "infra/panel_config.hpp"
#include "infra/runtime_config_types.hpp"
#include <cstddef>
#include <filesystem>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <string>
#include <string_view>
#include <vector>

struct Config {
    LogConfig log;
    DnsConfig dns;
    LimitsConfig limits;
    TimeoutsConfig timeouts;
    RoutingConfig routing;
    std::vector<PanelConfig> panels;
    std::vector<StaticInboundConfig> static_inbounds;
    std::vector<infra::OutboundSourceConfig> outbounds;
    uint32_t workers = 0;  // 加载时将 0 归一化为可用 CPU 核心数。
    std::filesystem::path config_dir;
};

// 文件与目录共用解析入口；侧车固定从主配置所在目录读取。
[[nodiscard]] std::optional<Config> LoadConfig(const std::filesystem::path& path);
[[nodiscard]] std::optional<Config> ParseConfig(const json::object& source);
[[nodiscard]] bool ValidateConfig(const Config& config);
[[nodiscard]] std::vector<std::string> GetUsedGeoIPTags(const RoutingConfig& routing);
[[nodiscard]] std::vector<std::string> GetUsedGeoSiteTags(const RoutingConfig& routing);

enum class ConfigSemanticError {
    None,
    NoOutbounds,
    EmptyOutboundTag,
    ReservedOutboundTag,
    DuplicateOutboundTag,
    EmptyRouteOutboundTag,
    UnknownRouteOutboundTag,
    EmptyStaticInboundOutboundTag,
    UnknownStaticInboundOutboundTag,
};

struct ConfigSemanticValidation {
    ConfigSemanticError error = ConfigSemanticError::None;
    size_t index = 0;
    std::string_view tag;

    [[nodiscard]] bool Ok() const noexcept {
        return error == ConfigSemanticError::None;
    }
};

enum class StaticInboundSemanticError {
    None,
    InvalidPort,
    EmptyTag,
    ReservedTag,
    DuplicateTag,
    DuplicateEndpoint,
};

struct StaticInboundSemanticValidation {
    StaticInboundSemanticError error = StaticInboundSemanticError::None;
    size_t index = 0;
    size_t conflicting_index = 0;
    std::string detail;

    [[nodiscard]] bool Ok() const noexcept {
        return error == StaticInboundSemanticError::None;
    }

    [[nodiscard]] std::string Message() const;
};

[[nodiscard]] ConfigSemanticValidation ValidateOutboundSelectionSemantics(
    std::span<const infra::OutboundSourceConfig> outbounds,
    std::span<const RouteRuleConfig> rules,
    std::span<const StaticInboundConfig> inbounds);

[[nodiscard]] StaticInboundSemanticValidation ValidateStaticInboundSemantics(
    std::span<const StaticInboundConfig> inbounds);


namespace infra {

// Cold-path configuration normalization. A string preserves the existing
// binding semantics; an ordered array chooses only assigned local addresses.
[[nodiscard]] inline OutboundBind ParseOutboundBindConfig(
    const json::value& value, const json::value* strategy = nullptr) {
    if (value.is_string()) {
        if (strategy) {
            throw std::invalid_argument(
                "sendThroughStrategy requires an array sendThrough");
        }
        auto result = OutboundBind::Parse(value.as_string());
        if (!result) {
            throw std::invalid_argument(
                "sendThrough must be auto, wildcard, an IP address, or an array of IPs/CIDRs");
        }
        return std::move(*result);
    }
    if (!value.is_array()) {
        throw std::invalid_argument("sendThrough must be a string or an array of IPs/CIDRs");
    }

    auto policy = OutboundBind::ChoicePolicy::Random;
    if (strategy) {
        if (!strategy->is_string()) {
            throw std::invalid_argument(
                "sendThroughStrategy must be random, ip_hash, or user_hash");
        }
        if (transport::internet::EqualsAsciiCI(strategy->as_string(), "random")) {
            policy = OutboundBind::ChoicePolicy::Random;
        } else if (transport::internet::EqualsAsciiCI(strategy->as_string(), "ip_hash")) {
            policy = OutboundBind::ChoicePolicy::IpHash;
        } else if (transport::internet::EqualsAsciiCI(strategy->as_string(), "user_hash")) {
            policy = OutboundBind::ChoicePolicy::UserHash;
        } else {
            throw std::invalid_argument(
                "sendThroughStrategy must be random, ip_hash, or user_hash");
        }
    }
    std::vector<std::string_view> entries;
    entries.reserve(value.as_array().size());
    for (const auto& entry : value.as_array()) {
        if (!entry.is_string()) {
            throw std::invalid_argument("sendThrough array must contain only IP/CIDR strings");
        }
        entries.push_back(entry.as_string());
    }
    auto result = OutboundBind::ParseCandidates(entries, policy);
    if (!result) {
        throw std::invalid_argument("sendThrough array contains an invalid IP/CIDR or is empty");
    }
    return std::move(*result);
}

[[nodiscard]] inline std::optional<OutboundBind> ParseOptionalOutboundBind(
    const json::object& source, std::string_view context) {
    if (source.contains("send_through") ||
        source.contains("send_through_strategy")) {
        throw std::invalid_argument(
            std::string(context) +
            " binding must use sendThrough/sendThroughStrategy without underscores");
    }
    const auto* send_through = source.if_contains("sendThrough");
    const auto* strategy = source.if_contains("sendThroughStrategy");
    if (strategy && !send_through) {
        throw std::invalid_argument(
            std::string(context) + " sendThroughStrategy requires sendThrough");
    }
    if (!send_through) {
        return std::nullopt;
    }
    return ParseOutboundBindConfig(*send_through, strategy);
}

}  // namespace infra
