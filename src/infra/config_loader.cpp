#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"

#include "acppnode/infra/json.hpp"
#include "acppnode/infra/outbound_source_config.hpp"
#include "config_semantics.hpp"

#include <fstream>
#include <iterator>
#include <stdexcept>
#include <utility>
#include <vector>

namespace acpp {

namespace {

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
        return json::parse(content, json::KeyComparison::AsciiCaseInsensitive);
    } catch (const std::exception& e) {
        LOG_ERROR("config.parse_failed file={} error={}",
                  path.filename().string(), e.what());
        return std::nullopt;
    }
}

template <typename AddFn>
void LoadConfigItems(const json::value& value, AddFn&& add) {
    if (!value.is_array()) {
        throw std::invalid_argument("config list must be an array of objects");
    }
    for (const auto& item : value.as_array()) {
        if (!item.is_object()) {
            throw std::invalid_argument("config list entries must be objects");
        }
        add(item.as_object());
    }
}

void LoadInboundItems(
    std::vector<StaticInboundConfig>& inbounds,
    const json::value& value,
    std::string_view source_name) {
    size_t count_before = inbounds.size();
    LoadConfigItems(value, [&](const json::object& item) {
        inbounds.push_back(StaticInboundConfig::FromJson(item));
    });
    LOG_CONSOLE("config.sidecar loaded file={} inbounds={}",
                source_name,
                inbounds.size() - count_before);
}

void LoadOutboundItems(
    std::vector<infra::OutboundSourceConfig>& outbounds,
    const json::value& value,
    std::string_view source_name) {
    size_t count_before = outbounds.size();
    LoadConfigItems(value, [&](const json::object& item) {
        outbounds.push_back(infra::OutboundSourceConfig::FromJson(item));
    });
    LOG_CONSOLE("config.sidecar loaded file={} outbounds={}",
                source_name,
                outbounds.size() - count_before);
}

}  // namespace

std::optional<Config> LoadConfig(const std::filesystem::path& path) {
    std::filesystem::path config_dir;
    json::value main_config;

    LOG_CONSOLE("config loading source={}", path.string());

    if (std::filesystem::is_directory(path)) {
        config_dir = path;
        LOG_CONSOLE("config mode=directory dir={}", config_dir.string());

        auto config_path = path / constants::paths::kDefaultConfigFile;
        if (std::filesystem::exists(config_path)) {
            auto j = LoadJsonFile(config_path);
            if (!j) {
                LOG_ERROR("config.main_load_failed file={}",
                          config_path.filename().string());
                return std::nullopt;
            }
            main_config = std::move(*j);
            LOG_CONSOLE("config.main loaded file={}", config_path.filename().string());
        } else {
            main_config = json::object{};
            LOG_CONSOLE("config.main missing file={} using_defaults=true",
                        constants::paths::kDefaultConfigFile);
        }
    } else {
        auto file_path = path;

        config_dir = file_path.parent_path();
        if (config_dir.empty()) {
            config_dir = ".";
        }
        LOG_CONSOLE("config mode=file dir={}", config_dir.string());

        auto parsed = LoadJsonFile(file_path);
        if (!parsed) {
            LOG_ERROR("config.main_load_failed file={}", file_path.filename().string());
            return std::nullopt;
        }
        main_config = std::move(*parsed);
        LOG_CONSOLE("config.main loaded file={}", file_path.filename().string());
    }

    if (!main_config.is_object()) {
        LOG_ERROR("config.main_invalid reason=expected_object");
        return std::nullopt;
    }
    auto cfg_opt = ParseConfig(main_config.as_object());
    if (!cfg_opt) {
        return std::nullopt;
    }

    Config& cfg = *cfg_opt;
    cfg.config_dir = config_dir;

    const auto default_inbound_path = config_dir / constants::paths::kInboundFile;
    if (std::filesystem::exists(default_inbound_path)) {
        auto j = LoadJsonFile(default_inbound_path);
        if (!j) {
            LOG_ERROR("config.sidecar_load_failed file={}",
                      constants::paths::kInboundFile);
            return std::nullopt;
        }
        try {
            LoadInboundItems(
                cfg.static_inbounds,
                *j,
                constants::paths::kInboundFile);
        } catch (const std::exception& e) {
            LOG_ERROR("config.sidecar_parse_failed file={} error={}",
                      constants::paths::kInboundFile, e.what());
            return std::nullopt;
        }
    }

    const auto default_outbound_path = config_dir / constants::paths::kOutboundFile;
    if (std::filesystem::exists(default_outbound_path)) {
        auto j = LoadJsonFile(default_outbound_path);
        if (!j) {
            LOG_ERROR("config.sidecar_load_failed file={}",
                      constants::paths::kOutboundFile);
            return std::nullopt;
        }
        try {
            LoadOutboundItems(
                cfg.outbounds,
                *j,
                constants::paths::kOutboundFile);
        } catch (const std::exception& e) {
            LOG_ERROR("config.sidecar_parse_failed file={} error={}",
                      constants::paths::kOutboundFile, e.what());
            return std::nullopt;
        }
    }

    const auto default_route_path = config_dir / constants::paths::kRouteFile;
    if (std::filesystem::exists(default_route_path)) {
        auto j = LoadJsonFile(default_route_path);
        if (!j) {
            LOG_ERROR("config.sidecar_load_failed file={}",
                      constants::paths::kRouteFile);
            return std::nullopt;
        }
        try {
            if (!j->is_object() || j->as_object().contains("routing")) {
                throw std::invalid_argument("routing sidecar must be a direct routing object");
            }
            cfg.routing = RoutingConfig::FromJson(j->as_object());
            LOG_CONSOLE("config.sidecar loaded file={} rules={}",
                        constants::paths::kRouteFile,
                        cfg.routing.rules.size());
        } catch (const std::exception& e) {
            LOG_ERROR("config.sidecar_parse_failed file={} error={}",
                      constants::paths::kRouteFile, e.what());
            return std::nullopt;
        }
    }

    bool has_direct = false;
    bool has_blackhole = false;
    for (const auto& ob : cfg.outbounds) {
        if (ob.tag == constants::protocol::kDirect) has_direct = true;
        if (ob.tag == constants::protocol::kBlackhole) has_blackhole = true;
    }

    if (!has_direct) {
        infra::OutboundSourceConfig direct;
        direct.tag = std::string(constants::protocol::kDirect);
        direct.protocol = std::string(constants::protocol::kFreedom);
        cfg.outbounds.insert(cfg.outbounds.begin(), std::move(direct));
        LOG_CONSOLE("config.outbound builtin tag={} sendThrough={}",
                    constants::protocol::kDirect, constants::binding::kAuto);
    }

    if (!has_blackhole) {
        infra::OutboundSourceConfig blackhole;
        blackhole.tag = std::string(constants::protocol::kBlackhole);
        blackhole.protocol = std::string(constants::protocol::kBlackhole);
        cfg.outbounds.push_back(std::move(blackhole));
        LOG_CONSOLE("config.outbound builtin tag={}", constants::protocol::kBlackhole);
    }

    auto geoip_path = config_dir / constants::paths::kGeoIpFile;
    auto geosite_path = config_dir / constants::paths::kGeoSiteFile;
    if (std::filesystem::exists(geoip_path)) {
        LOG_CONSOLE("config.geo found file={}", constants::paths::kGeoIpFile);
    }
    if (std::filesystem::exists(geosite_path)) {
        LOG_CONSOLE("config.geo found file={}", constants::paths::kGeoSiteFile);
    }

    LOG_CONSOLE("config summary workers={} inbounds={} outbounds={} rules={} panels={}",
                cfg.workers,
                cfg.static_inbounds.size(),
                cfg.outbounds.size(),
                cfg.routing.rules.size(),
                cfg.panels.size());

    return cfg;
}

}  // namespace acpp
