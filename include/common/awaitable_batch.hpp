#pragma once

#include "common/asio_types.hpp"
#include "common/error.hpp"

#include <asio/async_result.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <cstddef>
#include <exception>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

namespace common::detail {

template <typename Handler>
struct BatchState {
    BatchState(Handler handler, size_t task_count)
        : completion(std::move(handler)), remaining(task_count + 1) {}

    void RecordFailure(std::exception_ptr error) {
        if (!error) return;
        const bool cancelled = IsOperationCancelled(error);
        if (!failure || (failure_is_cancellation && !cancelled)) {
            failure = std::move(error);
            failure_is_cancellation = cancelled;
        }
    }

    void Finish(std::exception_ptr error = {}) {
        RecordFailure(std::move(error));
        if (--remaining == 0) std::move(completion)(failure);
    }

    Handler completion;
    size_t remaining;
    std::exception_ptr failure;
    bool failure_is_cancellation = false;
};

// This coroutine and every completion callback run on the supplied executor.
// Acquire the join continuation before launching any child, so completion never
// depends on allocating a separate wait operation after children have started.
inline net::awaitable<void> RunBatchOnExecutor(
    std::vector<net::awaitable<void>> tasks) {
    const auto executor = co_await net::this_coro::executor;
    auto token = net::use_awaitable;
    co_await net::async_initiate<decltype(token), void(std::exception_ptr)>(
        [executor, tasks = std::move(tasks)](auto handler) mutable {
            static_assert(std::is_nothrow_move_constructible_v<decltype(handler)>);
            std::shared_ptr<BatchState<decltype(handler)>> state;
            try {
                state = std::make_shared<BatchState<decltype(handler)>>(
                    std::move(handler), tasks.size());
            } catch (...) {
                tasks.clear();
                std::move(handler)(std::current_exception());
                return;
            }
            size_t launched = 0;
            try {
                for (auto& task : tasks) {
                    net::co_spawn(executor, std::move(task),
                        [state](std::exception_ptr error) { state->Finish(std::move(error)); });
                    ++launched;
                }
            } catch (...) {
                state->RecordFailure(std::current_exception());
                state->remaining -= tasks.size() - launched;
            }
            // Destroy unstarted frames before releasing the launch sentinel.
            // Even immediate child completion cannot resume the caller sooner.
            tasks.clear();
            state->Finish();
        }, token);
}

}  // namespace detail

// Starts every task on the supplied single-threaded executor and resumes only
// after all tasks finish. The first non-cancellation failure takes precedence
// over child cancellation. Caller cancellation is deferred until all started
// tasks finish; it cannot detach tasks that borrow the caller's state.
namespace common {

inline net::awaitable<void> RunAwaitableBatch(
    net::any_io_executor executor,
    std::vector<net::awaitable<void>> tasks) {
    if (tasks.empty()) co_return;

    // Cancellation must not detach children from a caller whose state they may
    // borrow. Join on an independent coroutine, then report deferred cancellation.
    co_await net::co_spawn(executor, detail::RunBatchOnExecutor(std::move(tasks)),
        net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
}

// Fans out one task per Worker index and joins them as RunAwaitableBatch does.
// Tasks are built at the call, so the caller must co_await the result at once.
template <typename WorkerRange, typename TaskFactory>
[[nodiscard]] net::awaitable<void> RunWorkerBatch(
    net::any_io_executor executor,
    WorkerRange& workers,
    TaskFactory task_factory) {
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers.size());
    for (size_t i = 0; i < workers.size(); ++i) {
        tasks.push_back(task_factory(*workers[i], i));
    }
    return RunAwaitableBatch(std::move(executor), std::move(tasks));
}

}  // namespace common
