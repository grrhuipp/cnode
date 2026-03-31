#include "acppnode/app/bootstrap_runtime.hpp"

#include "acppnode/app/bootstrap_monitor.hpp"
#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/panel_sync.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker.hpp"

#include <atomic>
#include <thread>

namespace acpp {

void RunApplicationRuntime(const RuntimeContext& ctx) {
    std::vector<std::thread> worker_threads;
    worker_threads.reserve(ctx.workers.size());
    for (uint32_t i = 0; i < ctx.workers.size(); ++i) {
        worker_threads.emplace_back([&ctx, i]() {
            memory::ThreadScope worker_thread_allocator_scope;
            memory::MarkThreadPoolThread();
            ctx.io_contexts[i]->run();
        });
    }

    LOG_CONSOLE("");
    LOG_CONSOLE("Server started with {} workers (SO_REUSEPORT)", ctx.workers.size());
    LOG_CONSOLE("Press Ctrl+C to stop");

    if (ctx.enable_panel_sync) {
        ctx.sync_manager.Start();
    }

    std::atomic<bool> running{true};
    [[maybe_unused]] auto shutdown_signals = InstallShutdownHandler(ctx, running);

    StartRuntimeMonitoring(ctx, running);

    ctx.main_ctx.run();

    for (auto& t : worker_threads) {
        if (t.joinable()) t.join();
    }

    ctx.main_ctx.restart();
    ctx.main_ctx.run_for(std::chrono::milliseconds(100));

    LOG_CONSOLE("=== acppnode stopped ===");
    Log::Shutdown();
}

}  // namespace acpp
