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

namespace acpp {

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

    auto config_opt = Config::LoadFromFile(cli.config_path);
    if (!config_opt) {
        std::cerr << "Failed to load config from: " << cli.config_path << "\n";
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

    LOG_CONSOLE("╔═══════════════════════════════════════════════════════════╗");
    LOG_CONSOLE("║              acppnode v1.0.0 - VMess Proxy                ║");
#ifdef USE_MIMALLOC
    LOG_CONSOLE("║     C++23 / standalone Asio / SO_REUSEPORT / mimalloc     ║");
#else
    LOG_CONSOLE("║  C++23 / standalone Asio / SO_REUSEPORT / system malloc   ║");
#endif
    LOG_CONSOLE("╚═══════════════════════════════════════════════════════════╝");
    LOG_CONSOLE("");
    LOG_CONSOLE("Configuration:");
    LOG_CONSOLE("  Workers:        {}", config.GetWorkers());
#if defined(__APPLE__)
    LOG_CONSOLE("  I/O backend:    kqueue (macOS)");
#elif defined(_WIN32)
    LOG_CONSOLE("  I/O backend:    IOCP (Windows)");
#else
    LOG_CONSOLE("  I/O backend:    epoll (Linux)");
#endif
    LOG_CONSOLE("  Accept model:   SO_REUSEPORT per-worker");
#ifdef USE_MIMALLOC
    LOG_CONSOLE("  Allocator:      mimalloc");
#else
    LOG_CONSOLE("  Allocator:      system");
#endif

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
