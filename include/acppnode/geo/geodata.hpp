#pragma once

#include "acppnode/common/asio_types.hpp"

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp::geo {

// ============================================================================
// 全局 Geo 管理器
// ============================================================================
class GeoManager {
public:
    GeoManager();
    ~GeoManager();

    GeoManager(const GeoManager&) = delete;
    GeoManager& operator=(const GeoManager&) = delete;
    GeoManager(GeoManager&&) noexcept;
    GeoManager& operator=(GeoManager&&) noexcept;

    // 初始化
    bool Init(const std::filesystem::path& geoip_path,
              const std::filesystem::path& geosite_path);

    // 预加载指定的 tag（从路由规则中提取）
    // 预加载完成后会自动启用无锁查询
    void PreloadTags(const std::vector<std::string>& geoip_tags,
                     const std::vector<std::string>& geosite_tags);

    bool MatchGeoIP(std::string_view tag, const net::ip::address& ip) const;
    bool MatchGeoSite(std::string_view tag, std::string_view domain) const;

    struct Stats {
        size_t geoip_tags_loaded;
        size_t geosite_tags_loaded;
        size_t geoip_total_cidrs;
        size_t geosite_total_entries;
    };
    Stats GetStats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp::geo
