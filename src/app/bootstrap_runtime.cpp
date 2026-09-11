#include "acppnode/app/bootstrap_runtime.hpp"

#include "acppnode/app/bootstrap_inbounds.hpp"
#include "acppnode/app/bootstrap_monitor.hpp"
#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <exception>
#include <thread>

namespace acpp {

[[noreturn]] void RunApplicationRuntime(const RuntimeContext& ctx) noexcept {
    // Keep every runtime owner outside the try block. In particular, partially
    // created joinable threads must not unwind before the failure handler runs.
    std::vector<std::thread> worker_threads;
    std::unique_ptr<RuntimeMonitor> runtime_monitor;
    std::unique_ptr<net::signal_set> shutdown_signals;
    const char* phase = "worker-startup";
    try {
        worker_threads.reserve(ctx.workers.size());
        for (uint32_t i = 0; i < ctx.workers.size(); ++i) {
            worker_threads.emplace_back([&ctx, i]() {
                try {
                    (void)TimeoutScheduler::ForIoContext(*ctx.io_contexts[i]);
                    ctx.io_contexts[i]->run();
                } catch (const std::exception& error) {
                    FailRuntime("worker-loop", error.what());
                } catch (...) {
                    FailRuntime("worker-loop", "unknown exception");
                }
                FailRuntime("worker-loop", "event loop stopped unexpectedly");
            });
        }

        phase = "inbound-startup";
        for (auto& result : ctx.inbound_startup.worker_results) {
            result.get();
        }
        ctx.inbound_startup.worker_results.clear();

        phase = "runtime-startup";
        for (const auto& inbound : ctx.inbound_startup.entries) {
            LOG_CONSOLE("static_inbound ready tag={} port={} protocol={} network={}",
                        inbound.tag,
                        inbound.port,
                        inbound.protocol,
                        inbound.stream_settings.network);
        }

        LOG_CONSOLE("");
        LOG_CONSOLE("server started workers={} accept=SO_REUSEPORT", ctx.workers.size());
        LOG_CONSOLE("shutdown shortcut=Ctrl+C");

        if (ctx.enable_controller) {
            ctx.controller.Start();
        }

        runtime_monitor = std::make_unique<RuntimeMonitor>(ctx);
        shutdown_signals = InstallShutdownHandler(ctx.main_ctx);
        runtime_monitor->Start();

        phase = "main-loop";
        ctx.main_ctx.run();
        FailRuntime(phase, "event loop stopped unexpectedly");
    } catch (const std::exception& error) {
        FailRuntime(phase, error.what());
    } catch (...) {
        FailRuntime(phase, "unknown exception");
    }
}

}  // namespace acpp
