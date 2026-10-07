#pragma once

#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/service/controller/config.hpp"
#include <filesystem>
#include <optional>

namespace acpp {

// ============================================================================
// 主配置
// ============================================================================
class Config {
public:
    // 从配置路径加载。为兼容命令行入口，path 可以是 config.json 文件或配置目录。
    static std::optional<Config> LoadFromFile(const std::filesystem::path& path);

    // 从目录加载：固定读取 config.json，以及同目录 inbounds/outbounds/routing sidecar。
    static std::optional<Config> LoadFromDirectory(const std::filesystem::path& dir);

    // 从 JSON 加载配置
    static std::optional<Config> LoadFromJson(const json::object& j);

    // Getter
    const LogConfig& GetLog() const { return log_; }
    const DnsConfig& GetDns() const { return dns_; }
    const LimitsConfig& GetLimits() const { return limits_; }
    const TimeoutsConfig& GetTimeouts() const { return timeouts_; }
    const RoutingConfig& GetRouting() const { return routing_; }
    const std::vector<PanelConfig>& GetPanels() const { return panels_; }
    const std::vector<StaticInboundConfig>& GetStaticInbounds() const { return static_inbounds_; }
    const std::vector<proxyman::outbound::PreparedOutboundConfig>& GetPreparedOutbounds() const {
        return prepared_outbounds_;
    }

    uint32_t GetWorkers() const { return workers_; }

    // 配置目录路径（用于加载 geo 文件）
    const std::filesystem::path& GetConfigDir() const { return config_dir_; }

    // 验证配置
    bool Validate() const;

    // 提取路由中使用的 GeoIP/GeoSite tag
    std::vector<std::string> GetUsedGeoIPTags() const;
    std::vector<std::string> GetUsedGeoSiteTags() const;

private:
    LogConfig log_;
    DnsConfig dns_;
    LimitsConfig limits_;
    TimeoutsConfig timeouts_;
    RoutingConfig routing_;
    std::vector<PanelConfig> panels_;
    std::vector<StaticInboundConfig> static_inbounds_;
    std::vector<proxyman::outbound::PreparedOutboundConfig> prepared_outbounds_;
    uint32_t workers_ = 0;  // 0 = CPU 核心数
    std::filesystem::path config_dir_;
};

}  // namespace acpp
