#include "awaitable_batch.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <exception>
#include <memory>

namespace acpp {

namespace {

struct BatchState {
    BatchState(net::any_io_executor executor, size_t task_count)
        : completion(std::move(executor))
        , remaining(task_count) {
        completion.expires_at(net::steady_timer::time_point::max());
    }

    net::steady_timer completion;
    size_t remaining = 0;
    std::exception_ptr failure;
};

net::awaitable<void> RunBatchTask(
    std::shared_ptr<BatchState> state,
    net::awaitable<void> task) {
    try {
        co_await std::move(task);
    } catch (...) {
        if (!state->failure) {
            state->failure = std::current_exception();
        }
    }

    if (--state->remaining == 0) {
        IoErrorCode ignored;
        state->completion.cancel(ignored);
    }
}

}  // namespace

net::awaitable<void> RunAwaitableBatch(
    net::any_io_executor executor,
    std::vector<net::awaitable<void>> tasks) {
    if (tasks.empty()) {
        co_return;
    }

    auto state = std::make_shared<BatchState>(executor, tasks.size());
    size_t spawned = 0;
    try {
        for (auto& task : tasks) {
            net::co_spawn(
                executor,
                RunBatchTask(state, std::move(task)),
                net::detached);
            ++spawned;
        }
    } catch (...) {
        if (!state->failure) {
            state->failure = std::current_exception();
        }
        const size_t not_spawned = tasks.size() - spawned;
        state->remaining -= not_spawned;
        if (state->remaining == 0) {
            IoErrorCode ignored;
            state->completion.cancel(ignored);
        }
    }

    if (state->remaining != 0) {
        (void)co_await state->completion.async_wait(
            net::as_tuple(net::use_awaitable));
    }
    if (state->failure) {
        std::rethrow_exception(state->failure);
    }
}

}  // namespace acpp
