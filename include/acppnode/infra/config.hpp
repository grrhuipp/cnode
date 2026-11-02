#pragma once

#include "acppnode/infra/config_types.hpp"
#include "acppnode/infra/outbound_source_config.hpp"
#include "acppnode/infra/panel_config.hpp"
#include <filesystem>
#include <optional>

namespace acpp {

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

}  // namespace acpp
