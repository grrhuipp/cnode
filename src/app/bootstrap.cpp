#include "acppnode/common/allocator.hpp"
#include "acppnode/app/bootstrap_cli.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/bootstrap_setup.hpp"
#include "acppnode/app/bootstrap_runtime.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/geo/geodata.hpp"
#include "acppnode/app/bootstrap.hpp"

#include <iostream>
#include <exception>
#include <filesystem>
#include <optional>
#include <string_view>
#include <system_error>

#ifndef BUILD_CHANNEL
#define BUILD_CHANNEL "unknown"
#endif

#ifndef BUILD_ID
#define BUILD_ID "unknown"
#endif

namespace acpp {

namespace {

std::optional<Config> LoadConfigFromCli(
    const CommandLineOptions& cli,
    std::ostream& err,
    bool& error_reported) {
    const std::filesystem::path config_path(cli.config_path);

    if (cli.config_mode == ConfigPathMode::Directory) {
        std::error_code ec;
        if (!std::filesystem::is_directory(config_path, ec)) {
            err << "--config-dir expects an existing directory: "
                << cli.config_path << "\n";
            error_reported = true;
            return std::nullopt;
        }
        return Config::LoadFromDirectory(config_path);
    }

    if (cli.config_mode == ConfigPathMode::File) {
        std::error_code ec;
        if (std::filesystem::is_directory(config_path, ec)) {
            err << "--config-file expects a file, got directory: "
                << cli.config_path << "\n";
            error_reported = true;
            return std::nullopt;
        }
    }

    return Config::LoadFromFile(config_path);
}

constexpr std::string_view IoBackendName() noexcept {
#if defined(__APPLE__)
    return "kqueue";
#elif defined(_WIN32)
    return "IOCP";
#elif defined(CNODE_IO_URING_ENABLED)
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
    [[maybe_unused]] memory::ThreadScope main_thread_allocator_scope;

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
    auto config_opt = LoadConfigFromCli(cli, std::cerr, config_error_reported);
    if (!config_opt) {
        if (!config_error_reported) {
            std::cerr << "Failed to load config from: " << cli.config_path << "\n";
        }
        return 1;
    }
    const Config& config = *config_opt;

    if (!Log::Init(config.GetLog().level,
                   config.GetLog().log_dir,
                   config.GetLog().max_days,
                   config.GetLog().access_path,
                   config.GetLog().error_path)) {
        std::cerr << "Failed to initialize logging\n";
        return 1;
    }

    LOG_CONSOLE("cnode v1.0.0 starting channel={} build={}", BUILD_CHANNEL, BUILD_ID);
    LOG_CONSOLE("runtime workers={} io={} accept=SO_REUSEPORT allocator=system",
                config.GetWorkers(), IoBackendName());

    if (!config.Validate()) {
        std::cerr << "Invalid configuration\n";
        return 1;
    }

    try {
        auto env = CreateBootstrapEnvironment(config, cli.test_mode);
        RunApplicationRuntime(MakeRuntimeContext(env));
    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize runtime: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

}  // namespace acpp
