#include "acppnode/app/bootstrap_runtime.hpp"

#include "acppnode/app/bootstrap_inbounds.hpp"
#include "acppnode/app/bootstrap_monitor.hpp"
#include "acppnode/app/bootstrap_shutdown.hpp"
#include "acppnode/app/dns/dns_service.hpp"
#include "acppnode/runtime/runtime.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/service/controller/controller.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/transport/internet/transport_stack.hpp"
#include "../common/awaitable_task_group.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>

#include <algorithm>
#include <atomic>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <vector>

namespace acpp {
namespace {

net::awaitable<void> StopOnSignal(
    const RuntimeContext& context,
    RuntimeMonitor& monitor) {
    const int signal = co_await WaitForShutdownSignal(context.control_executor);
    LOG_CONSOLE("shutdown signal={} status=stopping", signal);

    if (!context.controller.RequestStop()) {
        throw std::runtime_error("controller stop request was rejected");
    }
    if (!monitor.RequestStop()) {
        throw std::runtime_error("runtime monitor stop request was rejected");
    }
    co_await context.runtime.Stop();
}

net::awaitable<void> CloseAfterStartupFailure(const RuntimeContext& context) {
    const bool previous = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    try {
        co_await context.runtime.Stop();
    } catch (...) {
        failure = std::current_exception();
    }
    try {
        co_await context.dns_service.Close();
    } catch (...) {
        if (!failure) failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(previous);
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> RunManagedLifecycle(const RuntimeContext& context) {
    std::exception_ptr startup_failure;
    try {
        co_await SetupRuntimeInbounds(
            context.runtime, context.inbound_startup);
    } catch (...) {
        startup_failure = std::current_exception();
    }
    if (startup_failure) {
        try {
            co_await CloseAfterStartupFailure(context);
        } catch (...) {
            // Preserve the startup error: it identifies the resource that did
            // not become ready. Runtime/DNS cleanup has still been attempted.
        }
        std::rethrow_exception(startup_failure);
    }

    for (const auto& inbound : context.inbound_startup.entries) {
        LOG_CONSOLE("static_inbound ready tag={} port={} protocol={} network={}",
                    inbound.tag,
                    inbound.port,
                    inbound.protocol,
                    inbound.stream_settings.network);
    }
    LOG_CONSOLE("");
    LOG_CONSOLE("server started io_threads={} accept=single-owner", context.io_threads);
    LOG_CONSOLE("shutdown shortcut=Ctrl+C");

    RuntimeMonitor monitor(context);
    std::exception_ptr failure;
    try {
        co_await RunAwaitableTaskGroup(
            context.control_executor,
            [&](AwaitableTaskGroup& tasks) {
                tasks.Spawn(context.runtime.Run());
                tasks.Spawn(context.controller.Run());
                tasks.Spawn(monitor.Run());
                tasks.Spawn(StopOnSignal(context, monitor));
            });
    } catch (...) {
        failure = std::current_exception();
    }

    const bool previous = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    if (failure) {
        (void)context.controller.RequestStop();
        (void)monitor.RequestStop();
        try {
            co_await context.runtime.Stop();
        } catch (...) {
            // Keep the first service failure while still closing DNS below.
        }
    }
    try {
        co_await context.dns_service.Close();
    } catch (...) {
        if (!failure) failure = std::current_exception();
    }
    co_await net::this_coro::throw_if_cancelled(previous);
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> RunLifecycle(const RuntimeContext& context) {
    co_await RunAwaitableTaskGroup(
        context.control_executor,
        [&](AwaitableTaskGroup& tasks) {
            tasks.Spawn(context.dns_service.Run());
            tasks.Spawn(RunManagedLifecycle(context));
        });
}

}  // namespace

void RunApplicationRuntime(const RuntimeContext& context) {
    if (!context.work_guard) {
        context.work_guard.emplace(net::make_work_guard(context.io_context));
    }

    std::exception_ptr lifecycle_failure;
    std::exception_ptr runner_failure;
    std::mutex runner_failure_mutex;
    std::atomic<bool> recovery_requested{false};
    net::cancellation_signal lifecycle_cancellation;

    const auto request_recovery = [&] {
        if (recovery_requested.exchange(true, std::memory_order_relaxed)) return;
        net::post(context.control_executor, [&lifecycle_cancellation] {
            lifecycle_cancellation.emit(net::cancellation_type::all);
        });
    };

    net::co_spawn(
        context.control_executor,
        RunLifecycle(context),
        net::bind_cancellation_slot(
            lifecycle_cancellation.slot(),
            [&](std::exception_ptr failure) {
                lifecycle_failure = std::move(failure);
                context.work_guard.reset();
                context.io_context.stop();
            }));

    const auto run_context = [&] {
        for (;;) {
            try {
                context.io_context.run();
                return;
            } catch (...) {
                {
                    std::lock_guard lock(runner_failure_mutex);
                    if (!runner_failure) runner_failure = std::current_exception();
                }
                // A throwing handler only unwinds this run() invocation. Keep
                // this runner available to drive cancellation and cleanup.
                request_recovery();
            }
        }
    };

    std::vector<std::thread> threads;
    try {
        threads.reserve(context.io_threads > 0 ? context.io_threads - 1 : 0);
        for (uint32_t index = 1;
             index < std::max<uint32_t>(context.io_threads, 1);
             ++index) {
            threads.emplace_back(run_context);
        }
    } catch (...) {
        {
            std::lock_guard lock(runner_failure_mutex);
            if (!runner_failure) runner_failure = std::current_exception();
        }
        // Some workers may already be running. The calling thread also runs
        // the same context until lifecycle completion joins all cleanup.
        request_recovery();
    }
    run_context();

    context.io_context.stop();
    for (auto& thread : threads) {
        if (thread.joinable()) thread.join();
    }
    ReleaseXHttpSessionService(context.io_context.get_executor());
    TimeoutScheduler::ReleaseForExecutor(context.io_context.get_executor());

    if (runner_failure) std::rethrow_exception(runner_failure);
    if (lifecycle_failure) std::rethrow_exception(lifecycle_failure);
}

}  // namespace acpp
