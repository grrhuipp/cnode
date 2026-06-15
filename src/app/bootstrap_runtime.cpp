#include "acppnode/app/bootstrap_runtime.hpp"

#include "acppnode/app/bootstrap_monitor.hpp"
#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <thread>

namespace acpp {

void RunApplicationRuntime(const RuntimeContext& ctx) {
    std::vector<std::thread> worker_threads;
    worker_threads.reserve(ctx.workers.size());
    for (uint32_t i = 0; i < ctx.workers.size(); ++i) {
        worker_threads.emplace_back([&ctx, i]() {
            [[maybe_unused]] memory::ThreadScope worker_thread_allocator_scope;
            memory::MarkThreadPoolThread();
            (void)TimeoutScheduler::ForIoContext(*ctx.io_contexts[i]);
            ctx.io_contexts[i]->run();
            TimeoutScheduler::ReleaseForIoContext(*ctx.io_contexts[i]);
        });
    }

    LOG_CONSOLE("");
    LOG_CONSOLE("server started workers={} accept=SO_REUSEPORT", ctx.workers.size());
    LOG_CONSOLE("shutdown shortcut=Ctrl+C");

    if (ctx.enable_controller) {
        ctx.controller.Start();
    }

    RuntimeState runtime_state;
    [[maybe_unused]] auto shutdown_signals = InstallShutdownHandler(ctx, runtime_state);

    StartRuntimeMonitoring(ctx, runtime_state);

    ctx.main_ctx.run();

    for (auto& t : worker_threads) {
        if (t.joinable()) t.join();
    }
    ctx.main_ctx.restart();
    ctx.main_ctx.run_for(std::chrono::milliseconds(100));
    TimeoutScheduler::ReleaseForIoContext(ctx.main_ctx);

    LOG_CONSOLE("cnode stopped");
    Log::Shutdown();
}

}  // namespace acpp
