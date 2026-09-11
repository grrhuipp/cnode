#include "awaitable_batch.hpp"

#include <asio/async_result.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <exception>
#include <memory>
#include <type_traits>
#include <utility>

namespace acpp {

namespace {

template <typename Handler>
struct BatchState {
    BatchState(Handler handler, size_t task_count)
        : completion(std::move(handler)), remaining(task_count + 1) {}

    void Finish(std::exception_ptr error = {}) {
        if (error && !failure) failure = std::move(error);
        if (--remaining == 0) std::move(completion)(failure);
    }

    Handler completion;
    size_t remaining;
    std::exception_ptr failure;
};

// This coroutine and every completion callback run on the supplied executor.
// Acquire the join continuation before launching any child, so completion never
// depends on allocating a separate wait operation after children have started.
net::awaitable<void> RunBatchOnExecutor(std::vector<net::awaitable<void>> tasks) {
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
                if (!state->failure) state->failure = std::current_exception();
                state->remaining -= tasks.size() - launched;
            }
            // Destroy unstarted frames before releasing the launch sentinel.
            // Even immediate child completion cannot resume the caller sooner.
            tasks.clear();
            state->Finish();
        }, token);
}

}  // namespace

net::awaitable<void> RunAwaitableBatch(
    net::any_io_executor executor,
    std::vector<net::awaitable<void>> tasks) {
    if (tasks.empty()) co_return;

    // Cancellation must not detach children from a caller whose state they may
    // borrow. Join on an independent coroutine, then report deferred cancellation.
    co_await net::co_spawn(executor, RunBatchOnExecutor(std::move(tasks)),
        net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
}

}  // namespace acpp
