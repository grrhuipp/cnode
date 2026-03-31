#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"

#include <boost/json/src.hpp>  // 仅在此 TU 提供 Boost.JSON 实现

#include <fstream>
#include <iterator>
#include <utility>

namespace acpp {

namespace {

// 从磁盘读取并解析单个 JSON 文件
std::optional<boost::json::value> LoadJsonFile(const std::filesystem::path& path) {
    if (!std::filesystem::exists(path)) {
        return std::nullopt;
    }

    std::ifstream file(path);
    if (!file.is_open()) {
        return std::nullopt;
    }

    try {
        std::string content((std::istreambuf_iterator<char>(file)),
                            std::istreambuf_iterator<char>());
        return boost::json::parse(content);
    } catch (const std::exception& e) {
        LOG_CONSOLE("  ERROR: Failed to parse {}: {}", path.filename().string(), e.what());
        return std::nullopt;
    }
}

}  // namespace

std::optional<Config> Config::LoadFromFile(const std::filesystem::path& path) {
    std::filesystem::path config_dir;
    boost::json::value main_config;

    LOG_CONSOLE("Loading configuration from: {}", path.string());

    if (std::filesystem::is_directory(path)) {
        config_dir = path;
        LOG_CONSOLE("  Mode: directory");
        LOG_CONSOLE("  Config directory: {}", config_dir.string());

        auto config_path = path / constants::paths::kDefaultConfigFile;
        if (auto j = LoadJsonFile(config_path)) {
            main_config = std::move(*j);
            LOG_CONSOLE("  Loaded: {}", constants::paths::kDefaultConfigFile);
        } else {
            main_config = boost::json::object{};
            LOG_CONSOLE("  {} not found, using defaults", constants::paths::kDefaultConfigFile);
        }
    } else {
        config_dir = path.parent_path();
        if (config_dir.empty()) {
            config_dir = ".";
        }
        LOG_CONSOLE("  Mode: file");
        LOG_CONSOLE("  Config directory: {}", config_dir.string());

        std::ifstream file(path);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open config file: {}", path.string());
            return std::nullopt;
        }

        try {
            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            main_config = boost::json::parse(content);
            LOG_CONSOLE("  Loaded: {}", path.filename().string());
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to parse config file: {}", e.what());
            return std::nullopt;
        }
    }

    auto cfg_opt = LoadFromJson(main_config.as_object());
    if (!cfg_opt) {
        return std::nullopt;
    }

    Config& cfg = *cfg_opt;
    cfg.config_dir_ = config_dir;

    LOG_CONSOLE("  Scanning for additional config files...");

    if (auto j = LoadJsonFile(config_dir / constants::paths::kInboundFile)) {
        try {
            size_t count_before = cfg.inbounds_.size();
            if (j->is_array()) {
                for (const auto& item : j->as_array()) {
                    cfg.inbounds_.push_back(InboundConfig::FromJson(item.as_object()));
                }
            } else if (j->is_object()) {
                cfg.inbounds_.push_back(InboundConfig::FromJson(j->as_object()));
            }
            LOG_CONSOLE("  Loaded: {} ({} inbounds)",
                        constants::paths::kInboundFile,
                        cfg.inbounds_.size() - count_before);
        } catch (const std::exception& e) {
            LOG_WARN("  Failed to parse {}: {}", constants::paths::kInboundFile, e.what());
        }
    }

    if (auto j = LoadJsonFile(config_dir / constants::paths::kOutboundFile)) {
        try {
            size_t count_before = cfg.outbounds_.size();
            if (j->is_array()) {
                for (const auto& item : j->as_array()) {
                    cfg.outbounds_.push_back(OutboundConfig::FromJson(item.as_object()));
                }
            } else if (j->is_object()) {
                cfg.outbounds_.push_back(OutboundConfig::FromJson(j->as_object()));
            }
            LOG_CONSOLE("  Loaded: {} ({} outbounds)",
                        constants::paths::kOutboundFile,
                        cfg.outbounds_.size() - count_before);
        } catch (const std::exception& e) {
            LOG_WARN("  Failed to parse {}: {}", constants::paths::kOutboundFile, e.what());
        }
    }

    if (auto j = LoadJsonFile(config_dir / constants::paths::kRouteFile)) {
        try {
            cfg.routing_ = RoutingConfig::FromJson(j->as_object());
            LOG_CONSOLE("  Loaded: {} ({} rules)",
                        constants::paths::kRouteFile,
                        cfg.routing_.rules.size());
        } catch (const std::exception& e) {
            LOG_WARN("  Failed to parse {}: {}", constants::paths::kRouteFile, e.what());
        }
    }

    bool has_direct = false;
    bool has_blackhole = false;
    for (const auto& ob : cfg.outbounds_) {
        if (ob.tag == constants::protocol::kDirect) has_direct = true;
        if (ob.tag == constants::protocol::kBlackhole) has_blackhole = true;
    }

    if (!has_direct) {
        OutboundConfig direct;
        direct.tag = std::string(constants::protocol::kDirect);
        direct.protocol = std::string(constants::protocol::kFreedom);
        direct.settings = boost::json::object{
            {"sendThrough", constants::binding::kAuto},
            {"domainStrategy", constants::protocol::kAsIs}
        };
        cfg.outbounds_.insert(cfg.outbounds_.begin(), direct);
        LOG_CONSOLE("  Added built-in outbound: {} (SendThrough: {})",
                    constants::protocol::kDirect, constants::binding::kAuto);
    }

    if (!has_blackhole) {
        OutboundConfig blackhole;
        blackhole.tag = std::string(constants::protocol::kBlackhole);
        blackhole.protocol = std::string(constants::protocol::kBlackhole);
        cfg.outbounds_.push_back(blackhole);
        LOG_CONSOLE("  Added built-in outbound: {}", constants::protocol::kBlackhole);
    }

    auto geoip_path = config_dir / constants::paths::kGeoIpFile;
    auto geosite_path = config_dir / constants::paths::kGeoSiteFile;
    if (std::filesystem::exists(geoip_path)) {
        LOG_CONSOLE("  Found: {}", constants::paths::kGeoIpFile);
    }
    if (std::filesystem::exists(geosite_path)) {
        LOG_CONSOLE("  Found: {}", constants::paths::kGeoSiteFile);
    }

    LOG_CONSOLE("Configuration summary:");
    LOG_CONSOLE("  Workers: {}", cfg.workers_);
    LOG_CONSOLE("  Inbounds: {}", cfg.inbounds_.size());
    LOG_CONSOLE("  Outbounds: {}", cfg.outbounds_.size());
    LOG_CONSOLE("  Route rules: {}", cfg.routing_.rules.size());
    LOG_CONSOLE("  Default outbound: {}",
                cfg.outbounds_.empty() ? std::string(constants::protocol::kDirect)
                                       : cfg.outbounds_.front().tag);
    if (!cfg.panels_.empty()) {
        LOG_CONSOLE("  Panels: {}", cfg.panels_.size());
    }

    return cfg;
}

std::optional<Config> Config::LoadFromDirectory(const std::filesystem::path& dir) {
    return LoadFromFile(dir);
}

}  // namespace acpp
