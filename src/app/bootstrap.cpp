#include "common/allocator.hpp"
#include "core/constants.hpp"
#include "infra/config.hpp"
#include "infra/log.hpp"
#include "app/bootstrap_setup.hpp"
#include "app/bootstrap_runtime.hpp"
#include "service/controller/controller.hpp"
#include "app/stats.hpp"
#include "app/worker.hpp"
#include "geo/geodata.hpp"
#include "app/bootstrap.hpp"

#include <iostream>
#include <exception>
#include <filesystem>
#include <format>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#ifndef BUILD_CHANNEL
#define BUILD_CHANNEL "release"
#endif

#ifndef BUILD_ID
#define BUILD_ID "dev"
#endif


namespace {

enum class CommandLineAction {
    None,
    Help,
    Version,
    Error,
};

enum class ConfigPathMode {
    Auto,
    File,
    Directory,
};

struct CommandLineOptions {
    std::string config_path = std::string(constants::paths::kDefaultConfigFile);
    ConfigPathMode config_mode = ConfigPathMode::Auto;
    bool test_mode = false;
    CommandLineAction action = CommandLineAction::None;
    std::string error;
};

bool SetError(CommandLineOptions& options, std::string error) {
    options.action = CommandLineAction::Error;
    options.error = std::move(error);
    return false;
}

bool ReadValue(
    CommandLineOptions& options,
    std::string_view option,
    int argc,
    char* argv[],
    int& index) {
    if (index + 1 >= argc) {
        return SetError(options, std::format("Option {} requires a value", option));
    }

    options.config_path = argv[++index];
    return true;
}

[[nodiscard]] CommandLineOptions ParseCommandLine(int argc, char* argv[]) {
    CommandLineOptions options;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            if (options.action == CommandLineAction::None) {
                options.action = CommandLineAction::Help;
            }
            continue;
        }
        if (arg == "-v" || arg == "--version") {
            if (options.action == CommandLineAction::None) {
                options.action = CommandLineAction::Version;
            }
            continue;
        }
        if (arg == "-t" || arg == "--test") {
            options.test_mode = true;
            continue;
        }
        if (arg == "-c" || arg == "--config") {
            if (!ReadValue(options, arg, argc, argv, i)) break;
            options.config_mode = ConfigPathMode::Auto;
            continue;
        }
        if (arg == "--config-file") {
            if (!ReadValue(options, arg, argc, argv, i)) break;
            options.config_mode = ConfigPathMode::File;
            continue;
        }
        if (arg == "-C" || arg == "--config-dir") {
            if (!ReadValue(options, arg, argc, argv, i)) break;
            options.config_mode = ConfigPathMode::Directory;
            continue;
        }
        if (!arg.empty() && arg.front() == '-') {
            SetError(options, std::format("Unknown option: {}", arg));
            break;
        }
        SetError(options, std::format("Unexpected argument: {}", arg));
        break;
    }

    return options;
}

void PrintUsage(std::ostream& out, std::string_view prog) {
    out << "Usage: " << prog << " [options]\n"
        << "  -c, --config <path>       Config file or directory (default: "
        << constants::paths::kDefaultConfigFile << ")\n"
        << "      --config-file <file>  Load one config file; sidecars use its directory\n"
        << "  -C, --config-dir <dir>    Load config.json and sidecars from directory\n"
        << "  -t, --test                Test mode with built-in user\n"
        << "  -h, --help                Show help\n"
        << "  -v, --version             Show version\n"
        << "\n"
        << "Directory mode reads: "
        << constants::paths::kDefaultConfigFile << ", "
        << constants::paths::kInboundFile << ", "
        << constants::paths::kOutboundFile << ", "
        << constants::paths::kRouteFile << "\n";
}

void PrintVersion(std::ostream& out) {
    out << BUILD_CHANNEL << ":" << BUILD_ID << "\n";
}

std::optional<Config> LoadConfigFromCli(
    const CommandLineOptions& cli,
    bool& error_reported) {
    const std::filesystem::path config_path(cli.config_path);

    if (cli.config_mode == ConfigPathMode::Directory) {
        std::error_code ec;
        if (!std::filesystem::is_directory(config_path, ec)) {
            Log::WriteConsole(LogLevel::ERROR, std::format(
                "--config-dir expects an existing directory: {}", cli.config_path));
            error_reported = true;
            return std::nullopt;
        }
    }

    if (cli.config_mode == ConfigPathMode::File) {
        std::error_code ec;
        if (std::filesystem::is_directory(config_path, ec)) {
            Log::WriteConsole(LogLevel::ERROR, std::format(
                "--config-file expects a file, got directory: {}", cli.config_path));
            error_reported = true;
            return std::nullopt;
        }
    }

    return LoadConfig(config_path);
}

constexpr std::string_view IoBackendName() noexcept {
#if defined(CNODE_IO_URING_ENABLED)
    return "io_uring";
#else
    return "epoll";
#endif
}

}  // namespace

// ============================================================================
// RunFromCommandLine
// ============================================================================
int RunFromCommandLine(int argc, char* argv[]) {
    memory::ConfigureProcessAllocator();

    const CommandLineOptions cli = ParseCommandLine(argc, argv);
    if (cli.action == CommandLineAction::Help) {
        PrintUsage(std::cout, argv[0]);
        return 0;
    }
    if (cli.action == CommandLineAction::Version) {
        PrintVersion(std::cout);
        return 0;
    }
    if (cli.action == CommandLineAction::Error) {
        std::cerr << cli.error << "\n";
        PrintUsage(std::cerr, argv[0]);
        return 2;
    }

    bool config_error_reported = false;
    auto config_opt = LoadConfigFromCli(cli, config_error_reported);
    if (!config_opt) {
        if (!config_error_reported) {
            Log::WriteConsole(LogLevel::ERROR, std::format("Failed to load config from: {}", cli.config_path));
        }
        return 1;
    }
    const Config& config = *config_opt;

    if (!Log::Init(config.log.level,
                   config.log.log_dir,
                   config.log.max_days,
                   config.log.access_path,
                   config.log.error_path,
                   config.log.rotate_daily,
                   config.log.gzip)) {
        Log::WriteConsole(LogLevel::ERROR, "Failed to initialize logging");
        return 1;
    }
    LOG_CONSOLE("Configuration loaded: workers={} inbounds={} outbounds={} rules={} panels={}",
                config.workers,
                config.static_inbounds.size(),
                config.outbounds.size(),
                config.routing.rules.size(),
                config.panels.size());
    LOG_CONSOLE("Starting cnode v1.0.0: channel={} build={}", BUILD_CHANNEL, BUILD_ID);
    LOG_CONSOLE("Runtime configured: workers={} io={} accept=SO_REUSEPORT allocator=thread-local",
                config.workers, IoBackendName());
    if (!ValidateConfig(config)) {
        Log::WriteConsole(LogLevel::ERROR, "Invalid configuration");
        Log::Shutdown();
        return 1;
    }

    int result = 1;
    try {
        auto env = CreateBootstrapEnvironment(config, cli.test_mode);
        result = RunApplicationRuntime(MakeRuntimeContext(env));
    } catch (const std::exception& e) {
        Log::WriteConsole(LogLevel::ERROR, std::format("Failed to initialize runtime: {}", e.what()));
        Log::Shutdown();
        return 1;
    }
    Log::Shutdown();
    return result;
}

