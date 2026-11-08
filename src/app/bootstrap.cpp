#include "common/allocator.hpp"
#include "app/bootstrap_cli.hpp"
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
#include <string_view>
#include <system_error>

#ifndef BUILD_CHANNEL
#define BUILD_CHANNEL "unknown"
#endif

#ifndef BUILD_ID
#define BUILD_ID "unknown"
#endif


namespace {

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

