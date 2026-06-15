#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"

#include "acppnode/infra/json.hpp"
#include "../app/proxyman/outbound/source_config.hpp"

#include <fstream>
#include <iterator>
#include <system_error>
#include <utility>
#include <vector>

namespace acpp {

namespace {

std::optional<json::value> ParseConfigContent(
    const std::filesystem::path&,
    std::string_view content) {
    return json::parse(content);
}

// 从磁盘读取并解析单个 JSON 文件
std::optional<json::value> LoadJsonFile(const std::filesystem::path& path) {
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
        return ParseConfigContent(path, content);
    } catch (const std::exception& e) {
        LOG_CONSOLE("  ERROR: Failed to parse {}: {}", path.filename().string(), e.what());
        return std::nullopt;
    }
}

template <typename AddFn>
void LoadConfigItems(const json::value& value, AddFn&& add) {
    if (value.is_array()) {
        for (const auto& item : value.as_array()) {
            add(item.as_object());
        }
    } else if (value.is_object()) {
        add(value.as_object());
    }
}

const json::value& SelectConfigList(const json::value& value, std::string_view key) {
    if (value.is_object()) {
        if (const auto* nested = value.as_object().if_contains(key); nested) {
            return *nested;
        }
    }
    return value;
}

RoutingConfig ParseRoutingConfigValue(const json::value& value) {
    const auto& obj = value.as_object();
    if (auto* routing = obj.if_contains("routing"); routing && routing->is_object()) {
        return RoutingConfig::FromJson(routing->as_object());
    }
    return RoutingConfig::FromJson(obj);
}

std::optional<proxyman::outbound::PreparedOutboundConfig> PrepareOutboundForLoad(
    proxyman::outbound::OutboundSourceConfig raw_config) {
    auto prepared = proxyman::outbound::PrepareOutboundConfig(raw_config);
    if (!prepared) {
        LOG_WARN("  Skipped outbound '{}' with unsupported protocol '{}'",
                 raw_config.tag, raw_config.protocol);
        return std::nullopt;
    }
    return prepared;
}

void LoadInboundItems(
    std::vector<StaticInboundConfig>& inbounds,
    const json::value& value,
    std::string_view source_name) {
    size_t count_before = inbounds.size();
    LoadConfigItems(value, [&](const json::object& item) {
        inbounds.push_back(StaticInboundConfig::FromJson(item));
    });
    LOG_CONSOLE("  Loaded: {} ({} inbounds)",
                source_name,
                inbounds.size() - count_before);
}

void LoadOutboundItems(
    std::vector<proxyman::outbound::PreparedOutboundConfig>& outbounds,
    const json::value& value,
    std::string_view source_name) {
    size_t count_before = outbounds.size();
    LoadConfigItems(value, [&](const json::object& item) {
        auto prepared = PrepareOutboundForLoad(
            proxyman::outbound::OutboundSourceConfig::FromJson(item));
        if (prepared) {
            outbounds.push_back(std::move(*prepared));
        }
    });
    LOG_CONSOLE("  Loaded: {} ({} outbounds)",
                source_name,
                outbounds.size() - count_before);
}

}  // namespace

std::optional<Config> Config::LoadFromFile(const std::filesystem::path& path) {
    std::filesystem::path config_dir;
    json::value main_config;

    LOG_CONSOLE("Loading configuration from: {}", path.string());

    if (std::filesystem::is_directory(path)) {
        config_dir = path;
        LOG_CONSOLE("  Mode: directory");
        LOG_CONSOLE("  Config directory: {}", config_dir.string());

        auto config_path = path / constants::paths::kDefaultConfigFile;
        if (auto j = LoadJsonFile(config_path)) {
            main_config = std::move(*j);
            LOG_CONSOLE("  Loaded: {}", config_path.filename().string());
        } else {
            main_config = json::object{};
            LOG_CONSOLE("  {} not found, using defaults", constants::paths::kDefaultConfigFile);
        }
    } else {
        auto file_path = path;

        config_dir = file_path.parent_path();
        if (config_dir.empty()) {
            config_dir = ".";
        }
        LOG_CONSOLE("  Mode: file");
        LOG_CONSOLE("  Config directory: {}", config_dir.string());

        std::ifstream file(file_path);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open config file: {}", path.string());
            return std::nullopt;
        }

        try {
            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            main_config = *ParseConfigContent(file_path, content);
            LOG_CONSOLE("  Loaded: {}", file_path.filename().string());
        } catch (const std::exception& e) {
            LOG_ERROR("Failed to parse config file: {}", e.what());
            return std::nullopt;
        }
    }

    const auto& main_object = main_config.as_object();
    auto cfg_opt = LoadFromJson(main_object);
    if (!cfg_opt) {
        return std::nullopt;
    }

    Config& cfg = *cfg_opt;
    cfg.config_dir_ = config_dir;

    LOG_CONSOLE("  Scanning for additional config files...");

    const auto default_inbound_path = config_dir / constants::paths::kInboundFile;
    if (auto j = LoadJsonFile(default_inbound_path)) {
        try {
            LoadInboundItems(
                cfg.static_inbounds_,
                SelectConfigList(*j, "inbounds"),
                constants::paths::kInboundFile);
        } catch (const std::exception& e) {
            LOG_WARN("  Failed to parse {}: {}", constants::paths::kInboundFile, e.what());
        }
    }

    const auto default_outbound_path = config_dir / constants::paths::kOutboundFile;
    if (auto j = LoadJsonFile(default_outbound_path)) {
        try {
            LoadOutboundItems(
                cfg.prepared_outbounds_,
                SelectConfigList(*j, "outbounds"),
                constants::paths::kOutboundFile);
        } catch (const std::exception& e) {
            LOG_WARN("  Failed to parse {}: {}", constants::paths::kOutboundFile, e.what());
        }
    }

    const auto default_route_path = config_dir / constants::paths::kRouteFile;
    if (auto j = LoadJsonFile(default_route_path)) {
        try {
            cfg.routing_ = ParseRoutingConfigValue(*j);
            LOG_CONSOLE("  Loaded: {} ({} rules)",
                        constants::paths::kRouteFile,
                        cfg.routing_.rules.size());
        } catch (const std::exception& e) {
            LOG_WARN("  Failed to parse {}: {}", constants::paths::kRouteFile, e.what());
        }
    }

    bool has_direct = false;
    bool has_blackhole = false;
    for (const auto& ob : cfg.prepared_outbounds_) {
        if (ob.tag == constants::protocol::kDirect) has_direct = true;
        if (ob.tag == constants::protocol::kBlackhole) has_blackhole = true;
    }

    if (!has_direct) {
        proxyman::outbound::OutboundSourceConfig direct;
        direct.tag = std::string(constants::protocol::kDirect);
        direct.protocol = std::string(constants::protocol::kFreedom);
        auto prepared = proxyman::outbound::PrepareOutboundConfig(direct);
        if (prepared) {
            cfg.prepared_outbounds_.insert(cfg.prepared_outbounds_.begin(), std::move(*prepared));
        }
        LOG_CONSOLE("  Added built-in outbound: {} (sendThrough: {})",
                    constants::protocol::kDirect, constants::binding::kAuto);
    }

    if (!has_blackhole) {
        proxyman::outbound::OutboundSourceConfig blackhole;
        blackhole.tag = std::string(constants::protocol::kBlackhole);
        blackhole.protocol = std::string(constants::protocol::kBlackhole);
        auto prepared = PrepareOutboundForLoad(std::move(blackhole));
        if (prepared) {
            cfg.prepared_outbounds_.push_back(std::move(*prepared));
        }
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
    LOG_CONSOLE("  Inbounds: {}", cfg.static_inbounds_.size());
    LOG_CONSOLE("  Outbounds: {}", cfg.prepared_outbounds_.size());
    LOG_CONSOLE("  Route rules: {}", cfg.routing_.rules.size());
    LOG_CONSOLE("  Default outbound: {}",
                cfg.prepared_outbounds_.empty() ? std::string(constants::protocol::kDirect)
                                                : cfg.prepared_outbounds_.front().tag);
    if (!cfg.panels_.empty()) {
        LOG_CONSOLE("  Panels: {}", cfg.panels_.size());
    }

    return cfg;
}

std::optional<Config> Config::LoadFromDirectory(const std::filesystem::path& dir) {
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) {
        LOG_ERROR("Config path is not a directory: {}", dir.string());
        return std::nullopt;
    }

    return LoadFromFile(dir);
}

}  // namespace acpp
