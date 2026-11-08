#include "infra/config.hpp"
#include "infra/log.hpp"

#include "infra/json.hpp"
#include "infra/outbound_source_config.hpp"
#include "config_semantics.hpp"

#include <array>
#include <cerrno>
#include <cstdio>
#include <format>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

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
        Log::WriteConsole(LogLevel::ERROR, std::format(
            "Configuration read failed: file={} reason={}",
            file_name, std::generic_category().message(error)));
        return ConfigFileInvalid{};
    }

    std::string content;
    std::array<char, 16 * 1024> chunk;
    for (;;) {
        const size_t read = std::fread(chunk.data(), 1, chunk.size(), file.get());
        if (read < chunk.size() && std::ferror(file.get())) {
            const int error = errno;
            Log::WriteConsole(LogLevel::ERROR, std::format(
                "Configuration read failed: file={} reason={}",
                file_name, std::generic_category().message(error)));
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
        Log::WriteConsole(LogLevel::ERROR, std::format(
            "Configuration parsing failed: file={} reason={}", file_name, e.what()));
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
        Log::WriteConsole(LogLevel::ERROR, std::format(
            "Configuration sidecar load failed: file={}", file_name));
        return false;
    }
    try {
        apply(*value);
    } catch (const std::exception& e) {
        Log::WriteConsole(LogLevel::ERROR, std::format(
            "Configuration sidecar parsing failed: file={} reason={}", file_name, e.what()));
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
    const json::value& value) {
    LoadConfigItems(value, [&](const json::object& item) {
        inbounds.push_back(StaticInboundConfig::FromJson(item));
    });
}

void LoadOutboundItems(
    std::vector<infra::OutboundSourceConfig>& outbounds,
    const json::value& value) {
    LoadConfigItems(value, [&](const json::object& item) {
        outbounds.push_back(infra::OutboundSourceConfig::FromJson(item));
    });
}

}  // namespace

std::optional<Config> LoadConfig(const std::filesystem::path& path) {
    std::filesystem::path config_dir;
    json::value main_config;

    std::error_code ec;
    const bool is_dir = std::filesystem::is_directory(path, ec);
    if (ec && ec != std::errc::no_such_file_or_directory && ec != std::errc::not_a_directory) {
        Log::WriteConsole(LogLevel::ERROR, std::format(
            "Configuration path stat failed: path={} reason={}",
            path.string(), ec.message()));
        return std::nullopt;
    }

    if (is_dir) {
        config_dir = path;

        auto loaded = LoadJsonFile(path / constants::paths::kDefaultConfigFile);
        if (std::holds_alternative<ConfigFileInvalid>(loaded)) {
            Log::WriteConsole(LogLevel::ERROR, std::format(
                "Main configuration load failed: file={}",
                constants::paths::kDefaultConfigFile));
            return std::nullopt;
        }
        if (auto* loaded_config = std::get_if<json::value>(&loaded)) {
            main_config = std::move(*loaded_config);
        } else {
            main_config = json::object{};
        }
    } else {
        auto file_path = path;

        config_dir = file_path.parent_path();
        if (config_dir.empty()) {
            config_dir = ".";
        }

        auto loaded = LoadJsonFile(file_path);
        auto* loaded_config = std::get_if<json::value>(&loaded);
        if (!loaded_config) {
            // 显式指定的配置文件不存在同样是错误，不回落到默认配置。
            Log::WriteConsole(LogLevel::ERROR, std::format(
                "Main configuration load failed: file={} missing={}",
                file_path.filename().string(),
                std::holds_alternative<ConfigFileAbsent>(loaded)));
            return std::nullopt;
        }
        main_config = std::move(*loaded_config);
    }

    if (!main_config.is_object()) {
        Log::WriteConsole(LogLevel::ERROR, "Main configuration must be an object");
        return std::nullopt;
    }
    auto cfg_opt = ParseConfig(main_config.as_object());
    if (!cfg_opt) {
        return std::nullopt;
    }

    Config& cfg = *cfg_opt;
    cfg.config_dir = config_dir;
    if (!cfg.panels.empty()) {
        const auto journal_dir = std::filesystem::absolute(config_dir / "traffic-journal", ec);
        if (ec) {
            Log::WriteConsole(LogLevel::ERROR, std::format(
                "Traffic journal path resolution failed: reason={}", ec.message()));
            return std::nullopt;
        }
        for (auto& panel : cfg.panels) {
            panel.TrafficJournalDir = journal_dir;
        }
    }

    const bool sidecars_loaded =
        LoadSidecarFile(config_dir, constants::paths::kInboundFile,
            [&](const json::value& value) {
                LoadInboundItems(cfg.static_inbounds, value);
            }) &&
        LoadSidecarFile(config_dir, constants::paths::kOutboundFile,
            [&](const json::value& value) {
                LoadOutboundItems(cfg.outbounds, value);
            }) &&
        LoadSidecarFile(config_dir, constants::paths::kRouteFile,
            [&](const json::value& value) {
                if (!value.is_object() || value.as_object().contains("routing")) {
                    throw std::invalid_argument(
                        "routing sidecar must be a direct routing object");
                }
                cfg.routing = RoutingConfig::FromJson(value.as_object());
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
    }

    if (!has_blackhole) {
        infra::OutboundSourceConfig blackhole;
        blackhole.tag = std::string(constants::protocol::kBlackhole);
        blackhole.protocol = std::string(constants::protocol::kBlackhole);
        cfg.outbounds.push_back(std::move(blackhole));
    }

    return cfg;
}

