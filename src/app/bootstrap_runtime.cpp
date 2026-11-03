#include "acppnode/app/bootstrap_runtime.hpp"

#include "acppnode/app/bootstrap_inbounds.hpp"
#include "acppnode/app/bootstrap_monitor.hpp"
#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/app/dns/dns_worker.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/infra/runtime_failure.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "../common/awaitable_batch.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <thread>
#include <stdexcept>

namespace acpp {
namespace {

// All state transitions run on main_ctx. Data threads may only publish one
// failure notification, and remain in run() until their live owner has joined.
class RuntimeOwner {
public:
    explicit RuntimeOwner(const RuntimeContext& context)
        : ctx(context), main_work(net::make_work_guard(ctx.main_ctx)),
          stop_event(ctx.main_ctx, std::chrono::steady_clock::time_point::max()),
          monitor(ctx) {}

    void RequestStop(bool failure = false) noexcept {
        if (failure) exit_code = EXIT_FAILURE;
        if (stopping) return;
        stopping = true;
        ctx.controller.RequestStop();
        monitor.RequestStop();
        for (size_t i = 0; i < started_threads; ++i) ctx.workers[i]->RequestStop();
        ctx.dns_worker.RequestStop();
        stop_event.cancel();
        IoErrorCode ignored;
        if (signals) signals->cancel(ignored);
    }

    void RecordFailure(std::exception_ptr error) noexcept {
        RequestStop(true);
        try {
            if (error) std::rethrow_exception(error);
        } catch (const std::exception& failure) {
            try { LOG_ERROR("runtime failure: {}", failure.what()); } catch (...) {}
        } catch (...) {
            try { LOG_ERROR("runtime failure: unknown exception"); } catch (...) {}
        }
    }

    void PublishFailure(std::exception_ptr error) noexcept {
        if (failure_pending.exchange(true, std::memory_order_acq_rel)) return;
        try {
            net::post(ctx.main_ctx, [this, error] { RecordFailure(error); });
        } catch (...) {
            FailRuntime("runtime-failure", "cannot notify lifecycle owner");
        }
    }

    net::awaitable<void> Run() {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        if (!stopping) {
            try {
                std::vector<net::awaitable<void>> startups;
                startups.reserve(ctx.workers.size());
                for (const auto& worker : ctx.workers) {
                    startups.push_back(worker->PostTask(
                        StartWorkerInbounds(*worker, ctx.inbound_startup.entries)));
                }
                co_await RunAwaitableBatch(ctx.main_ctx.get_executor(), std::move(startups));
                if (!stopping) {
                    if (ctx.enable_controller) ctx.controller.Start();
                    monitor.Start();
                    for (const auto& inbound : ctx.inbound_startup.entries) {
                        LOG_CONSOLE("static_inbound ready tag={} port={} protocol={} network={}",
                            inbound.tag, inbound.port, inbound.protocol, inbound.stream_settings.network);
                    }
                    LOG_CONSOLE("server started workers={} accept=SO_REUSEPORT", ctx.workers.size());
                }
            } catch (const IoSystemError& error) {
                if (!stopping || error.code() != net::error::operation_aborted)
                    RecordFailure(std::current_exception());
            } catch (...) { RecordFailure(std::current_exception()); }
        }
        while (!stopping) {
            IoErrorCode ec;
            co_await stop_event.async_wait(net::redirect_error(net::use_awaitable, ec));
        }
        // Every owner must join even if an earlier component reports a real
        // failure. Worker admission is already closed: do not start rollback
        // mutations; retained prepared state dies only after Workers finish.
        try { co_await ctx.controller.AsyncJoin(); }
        catch (...) { RecordFailure(std::current_exception()); }
        try { co_await monitor.AsyncJoin(); }
        catch (...) { RecordFailure(std::current_exception()); }
        for (size_t i = 0; i < started_threads; ++i) {
            bool joined = false;
            while (!joined) {
                try {
                    co_await ctx.workers[i]->AsyncJoin();
                    joined = true;
                } catch (...) { RecordFailure(std::current_exception()); }
            }
            ctx.work_guards[i].reset();
        }
        bool dns_joined = false;
        while (!dns_joined) {
            try {
                co_await ctx.dns_worker.AsyncJoin();
                dns_joined = true;
            } catch (...) { RecordFailure(std::current_exception()); }
        }
    }

    const RuntimeContext& ctx;
    net::executor_work_guard<net::io_context::executor_type> main_work;
    net::steady_timer stop_event;
    RuntimeMonitor monitor;
    std::unique_ptr<net::signal_set> signals;
    size_t started_threads = 0;
    int exit_code = EXIT_SUCCESS;
    bool stopping = false;
    bool completed = false;
    std::atomic<bool> failure_pending{false};
};

void RunDataThread(RuntimeOwner& owner, size_t index) noexcept {
    auto& context = *owner.ctx.io_contexts[index];
    owner.ctx.workers[index]->RunEventLoop();
    // Live state and maintenance have already joined. Release cancels the
    // scheduler's final timer; drain that completion before destroying its PMR
    // container capacity on this same thread.
    TimeoutScheduler::ReleaseForIoContext(context);
    context.restart();
    for (;;) {
        try { context.run(); break; }
        catch (...) { owner.PublishFailure(std::current_exception()); }
    }
    owner.ctx.io_contexts[index].reset();
}

}  // namespace

int RunApplicationRuntime(const RuntimeContext& ctx) noexcept {
    std::vector<std::thread> threads;
    try {
        RuntimeOwner owner(ctx);
        threads.reserve(ctx.workers.size());
        // The total lifecycle coroutine is owned before any data thread starts.
        net::co_spawn(ctx.main_ctx, owner.Run(), [&owner](std::exception_ptr error) {
            if (error) FailRuntime("runtime-join", "lifecycle completion failed");
            owner.completed = true;
            owner.main_work.reset();
        });
        try {
            owner.signals = InstallShutdownHandler(ctx.main_ctx, [&owner] { owner.RequestStop(); });
            for (size_t i = 0; i < ctx.workers.size(); ++i) {
                ctx.workers[i]->SetFailureHandler([&owner](std::exception_ptr error) {
                    owner.PublishFailure(error);
                });
                threads.emplace_back([&owner, i] { RunDataThread(owner, i); });
                ++owner.started_threads;
            }
        } catch (...) { owner.RecordFailure(std::current_exception()); }

        for (;;) {
            try {
                ctx.main_ctx.run();
                if (owner.completed) break;
                ctx.main_ctx.restart();
                owner.RecordFailure(std::make_exception_ptr(
                    std::runtime_error("main event loop stopped before lifecycle completion")));
            } catch (...) { owner.RecordFailure(std::current_exception()); }
        }
        // No join blocks an event loop needed by a data-thread completion.
        for (auto& thread : threads) thread.join();
        for (size_t i = owner.started_threads; i < ctx.work_guards.size(); ++i)
            ctx.work_guards[i].reset();
        TimeoutScheduler::ReleaseForIoContext(ctx.main_ctx);
        ctx.main_ctx.restart();
        for (;;) {
            try { ctx.main_ctx.run(); break; }
            catch (...) { owner.RecordFailure(std::current_exception()); }
        }
        return owner.exit_code;
    } catch (...) {
        // Before the pre-owned lifecycle exists there are no data threads or
        // accepted startup jobs. An exception after that boundary is corruption
        // of the lifecycle itself and cannot unwind live thread owners.
        if (!threads.empty()) FailRuntime("runtime-owner", "lifecycle owner failed");
        return EXIT_FAILURE;
    }
}

}  // namespace acpp
