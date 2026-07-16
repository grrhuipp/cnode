#include "acppnode/app/bootstrap_runtime.hpp"

#include "acppnode/app/bootstrap_monitor.hpp"
#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/access_log_reporter.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/use_future.hpp>

#include <exception>
#include <stdexcept>
#include <thread>

namespace acpp {

namespace {

net::awaitable<void> ShutdownStartupWorker(Worker& worker) {
    co_await worker.ShutdownTask();
}

}  // namespace

void RunApplicationRuntime(const RuntimeContext& ctx) {
    std::vector<std::thread> worker_threads;
    worker_threads.reserve(ctx.workers.size());
    for (uint32_t i = 0; i < ctx.workers.size(); ++i) {
        worker_threads.emplace_back([&ctx, i]() {
            [[maybe_unused]] memory::ThreadScope worker_thread_allocator_scope;
            memory::MarkThreadPoolThread();
            (void)TimeoutScheduler::ForIoContext(*ctx.io_contexts[i]);
            ctx.workers[i]->StartWorkerLocalServices();
            ctx.io_contexts[i]->run();
            TimeoutScheduler::ReleaseForIoContext(*ctx.io_contexts[i]);
        });
    }

    bool inbound_startup_ok = true;
    std::exception_ptr inbound_startup_error;
    for (auto& result : ctx.inbound_startup.worker_results) {
        try {
            inbound_startup_ok = result.get() && inbound_startup_ok;
        } catch (...) {
            inbound_startup_ok = false;
            if (!inbound_startup_error) {
                inbound_startup_error = std::current_exception();
            }
        }
    }
    ctx.inbound_startup.worker_results.clear();
    if (!inbound_startup_ok) {
        std::vector<std::future<void>> cleanup_results;
        cleanup_results.reserve(ctx.workers.size());
        for (const auto& worker : ctx.workers) {
            cleanup_results.push_back(net::co_spawn(
                worker->GetExecutor(),
                ShutdownStartupWorker(*worker),
                net::use_future));
        }
        for (auto& cleanup : cleanup_results) {
            try {
                cleanup.get();
            } catch (...) {
                if (!inbound_startup_error) {
                    inbound_startup_error = std::current_exception();
                }
            }
        }
        for (const auto& io_context : ctx.io_contexts) {
            io_context->stop();
        }
        for (auto& thread : worker_threads) {
            if (thread.joinable()) thread.join();
        }
        ctx.workers.clear();
        if (inbound_startup_error) {
            std::rethrow_exception(inbound_startup_error);
        }
        throw std::runtime_error("configured inbound startup failed");
    }

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

    RuntimeMonitor runtime_monitor(ctx);
    [[maybe_unused]] auto shutdown_signals =
        InstallShutdownHandler(ctx, runtime_monitor);
    runtime_monitor.Start();

    ctx.main_ctx.run();
    shutdown_signals.reset();

    for (auto& t : worker_threads) {
        if (t.joinable()) t.join();
    }
    TimeoutScheduler::ReleaseForIoContext(ctx.main_ctx);

    accesslog::Reporter::Instance().Shutdown();
    LOG_CONSOLE("cnode stopped");
    Log::Shutdown();
}

}  // namespace acpp
