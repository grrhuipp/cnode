#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"

#include "acppnode/infra/json.hpp"
#include "../app/proxyman/outbound/source_config.hpp"
#include "config_semantics.hpp"

#include <fstream>
#include <iterator>
#include <stdexcept>
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
        LOG_ERROR("config.parse_failed file={} error={}",
                  path.filename().string(), e.what());
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
    } else {
        throw std::invalid_argument("config list must be an object or array");
    }
}

const json::value& SelectConfigList(const json::value& value, std::string_view key) {
    if (value.is_object()) {
        if (const auto* nested = value.as_object().if_contains(key); nested) {
            if (!nested->is_array()) {
                throw std::invalid_argument(
                    std::string(key) + " wrapper field must be an array");
            }
            return *nested;
        }
    }
    return value;
}

RoutingConfig ParseRoutingConfigValue(const json::value& value) {
    const auto& obj = value.as_object();
    if (auto* routing = obj.if_contains("routing")) {
        if (!routing->is_object()) {
            throw std::invalid_argument("routing wrapper field must be an object");
        }
        return RoutingConfig::FromJson(routing->as_object());
    }
    return RoutingConfig::FromJson(obj);
}

proxyman::outbound::PreparedOutboundConfig PrepareOutboundForLoad(
    proxyman::outbound::OutboundSourceConfig raw_config) {
    auto prepared = proxyman::outbound::PrepareOutboundConfig(raw_config);
    if (!prepared) {
        throw std::invalid_argument(
            "outbound '" + raw_config.tag + "' protocol '" +
            raw_config.protocol + "' is unsupported or invalid");
    }
    return std::move(*prepared);
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
    std::vector<proxyman::outbound::PreparedOutboundConfig>& outbounds,
    const json::value& value,
    std::string_view source_name) {
    size_t count_before = outbounds.size();
    LoadConfigItems(value, [&](const json::object& item) {
        outbounds.push_back(PrepareOutboundForLoad(
            proxyman::outbound::OutboundSourceConfig::FromJson(item)));
    });
    LOG_CONSOLE("config.sidecar loaded file={} outbounds={}",
                source_name,
                outbounds.size() - count_before);
}

}  // namespace

std::optional<Config> Config::LoadFromFile(const std::filesystem::path& path) {
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

        std::ifstream file(file_path);
        if (!file.is_open()) {
            LOG_ERROR("config.open_failed file={}", path.string());
            return std::nullopt;
        }

        try {
            std::string content((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
            main_config = *ParseConfigContent(file_path, content);
            LOG_CONSOLE("config.main loaded file={}", file_path.filename().string());
        } catch (const std::exception& e) {
            LOG_ERROR("config.parse_failed file={} error={}",
                      file_path.filename().string(), e.what());
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
                cfg.static_inbounds_,
                SelectConfigList(*j, "inbounds"),
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
                cfg.prepared_outbounds_,
                SelectConfigList(*j, "outbounds"),
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
            cfg.routing_ = ParseRoutingConfigValue(*j);
            LOG_CONSOLE("config.sidecar loaded file={} rules={}",
                        constants::paths::kRouteFile,
                        cfg.routing_.rules.size());
        } catch (const std::exception& e) {
            LOG_ERROR("config.sidecar_parse_failed file={} error={}",
                      constants::paths::kRouteFile, e.what());
            return std::nullopt;
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
        if (!prepared) {
            LOG_ERROR("config.outbound builtin_prepare_failed tag={} protocol={}",
                      direct.tag, direct.protocol);
            return std::nullopt;
        }
        cfg.prepared_outbounds_.insert(cfg.prepared_outbounds_.begin(), std::move(*prepared));
        LOG_CONSOLE("config.outbound builtin tag={} sendThrough={}",
                    constants::protocol::kDirect, constants::binding::kAuto);
    }

    if (!has_blackhole) {
        proxyman::outbound::OutboundSourceConfig blackhole;
        blackhole.tag = std::string(constants::protocol::kBlackhole);
        blackhole.protocol = std::string(constants::protocol::kBlackhole);
        auto prepared = proxyman::outbound::PrepareOutboundConfig(blackhole);
        if (!prepared) {
            LOG_ERROR("config.outbound builtin_prepare_failed tag={} protocol={}",
                      blackhole.tag, blackhole.protocol);
            return std::nullopt;
        }
        cfg.prepared_outbounds_.push_back(std::move(*prepared));
        LOG_CONSOLE("config.outbound builtin tag={}", constants::protocol::kBlackhole);
    }

    for (const auto& ignored : IgnoreUnknownRoutingRules(
             cfg.prepared_outbounds_, cfg.routing_.rules)) {
        LOG_WARN("config.routing ignored rule={} unknown_outbound={}",
                 ignored.index, ignored.tag);
    }

    auto geoip_path = config_dir / constants::paths::kGeoIpFile;
    auto geosite_path = config_dir / constants::paths::kGeoSiteFile;
    if (std::filesystem::exists(geoip_path)) {
        LOG_CONSOLE("config.geo found file={}", constants::paths::kGeoIpFile);
    }
    if (std::filesystem::exists(geosite_path)) {
        LOG_CONSOLE("config.geo found file={}", constants::paths::kGeoSiteFile);
    }

    LOG_CONSOLE("config summary workers={} inbounds={} outbounds={} rules={} default_outbound={} panels={}",
                cfg.workers_,
                cfg.static_inbounds_.size(),
                cfg.prepared_outbounds_.size(),
                cfg.routing_.rules.size(),
                cfg.prepared_outbounds_.empty() ? std::string(constants::protocol::kDirect)
                                                : cfg.prepared_outbounds_.front().tag,
                cfg.panels_.size());

    return cfg;
}

std::optional<Config> Config::LoadFromDirectory(const std::filesystem::path& dir) {
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec)) {
        LOG_ERROR("config.invalid_path dir={} reason=not_directory", dir.string());
        return std::nullopt;
    }

    return LoadFromFile(dir);
}

}  // namespace acpp
