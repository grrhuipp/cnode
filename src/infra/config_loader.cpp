#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"

#include "acppnode/infra/json.hpp"
#include "acppnode/infra/outbound_source_config.hpp"
#include "config_semantics.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

namespace acpp {

namespace {

// 文件不存在表示“未配置”，是否允许缺省由调用方决定；打开、读取失败与 JSON
// 损坏都属于配置损坏，在此分别记录原因后阻断加载。以 fopen 的 errno 判定缺失，
// 不做 exists() 预检，避免检查与打开之间的竞态；ferror 区分读取故障与文件结束。
struct ConfigFileAbsent {};
struct ConfigFileInvalid {};
using ConfigFileLoad = std::variant<json::value, ConfigFileAbsent, ConfigFileInvalid>;

struct FileCloser {
    void operator()(std::FILE* file) const noexcept { std::fclose(file); }
};

ConfigFileLoad LoadJsonFile(const std::filesystem::path& path) {
    const auto file_name = path.filename().string();
    const std::unique_ptr<std::FILE, FileCloser> file(std::fopen(path.c_str(), "rb"));
    if (!file) {
        const int error = errno;
        if (error == ENOENT) {
            return ConfigFileAbsent{};
        }
        LOG_ERROR("config.read_failed file={} error={}",
                  file_name, std::generic_category().message(error));
        return ConfigFileInvalid{};
    }

    std::string content;
    std::array<char, 16 * 1024> chunk;
    for (;;) {
        const size_t read = std::fread(chunk.data(), 1, chunk.size(), file.get());
        if (read < chunk.size() && std::ferror(file.get())) {
            const int error = errno;
            LOG_ERROR("config.read_failed file={} error={}",
                      file_name, std::generic_category().message(error));
            return ConfigFileInvalid{};
        }
        content.append(chunk.data(), read);
        if (read < chunk.size()) {
            break;
        }
    }

    try {
        return json::parse(content, json::KeyComparison::AsciiCaseInsensitive);
    } catch (const std::exception& e) {
        LOG_ERROR("config.parse_failed file={} error={}", file_name, e.what());
        return ConfigFileInvalid{};
    }
}

// 侧车文件缺失即未配置；存在但读取、解析或校验失败都阻断加载。
template <typename ApplyFn>
bool LoadSidecarFile(const std::filesystem::path& config_dir,
                     std::string_view file_name,
                     ApplyFn&& apply) {
    auto loaded = LoadJsonFile(config_dir / file_name);
    if (std::holds_alternative<ConfigFileAbsent>(loaded)) {
        return true;
    }
    auto* value = std::get_if<json::value>(&loaded);
    if (!value) {
        LOG_ERROR("config.sidecar_load_failed file={}", file_name);
        return false;
    }
    try {
        apply(*value);
    } catch (const std::exception& e) {
        LOG_ERROR("config.sidecar_parse_failed file={} error={}", file_name, e.what());
        return false;
    }
    return true;
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

        auto loaded = LoadJsonFile(path / constants::paths::kDefaultConfigFile);
        if (std::holds_alternative<ConfigFileInvalid>(loaded)) {
            LOG_ERROR("config.main_load_failed file={}",
                      constants::paths::kDefaultConfigFile);
            return std::nullopt;
        }
        if (auto* loaded_config = std::get_if<json::value>(&loaded)) {
            main_config = std::move(*loaded_config);
            LOG_CONSOLE("config.main loaded file={}", constants::paths::kDefaultConfigFile);
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

        auto loaded = LoadJsonFile(file_path);
        auto* loaded_config = std::get_if<json::value>(&loaded);
        if (!loaded_config) {
            // 显式指定的配置文件不存在同样是错误，不回落到默认配置。
            LOG_ERROR("config.main_load_failed file={} missing={}",
                      file_path.filename().string(),
                      std::holds_alternative<ConfigFileAbsent>(loaded));
            return std::nullopt;
        }
        main_config = std::move(*loaded_config);
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
    for (auto& panel : cfg.panels) {
        panel.TrafficJournalDir = std::filesystem::absolute(config_dir / "traffic-journal");
    }

    const bool sidecars_loaded =
        LoadSidecarFile(config_dir, constants::paths::kInboundFile,
            [&](const json::value& value) {
                LoadInboundItems(cfg.static_inbounds, value, constants::paths::kInboundFile);
            }) &&
        LoadSidecarFile(config_dir, constants::paths::kOutboundFile,
            [&](const json::value& value) {
                LoadOutboundItems(cfg.outbounds, value, constants::paths::kOutboundFile);
            }) &&
        LoadSidecarFile(config_dir, constants::paths::kRouteFile,
            [&](const json::value& value) {
                if (!value.is_object() || value.as_object().contains("routing")) {
                    throw std::invalid_argument(
                        "routing sidecar must be a direct routing object");
                }
                cfg.routing = RoutingConfig::FromJson(value.as_object());
                LOG_CONSOLE("config.sidecar loaded file={} rules={}",
                            constants::paths::kRouteFile,
                            cfg.routing.rules.size());
            });
    if (!sidecars_loaded) {
        return std::nullopt;
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
