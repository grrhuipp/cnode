#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/error.hpp"

#include <asio/as_tuple.hpp>
#include <asio/async_result.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <cerrno>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <dirent.h>
#include <sys/resource.h>
namespace detail {

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
                state = memory::AllocateShared<BatchState<decltype(handler)>>(
                    nullptr, std::move(handler), tasks.size());
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

namespace monitor_detail {

// Each process or panel monitor has its own completion boundary. The factory owns its
// context, and co_spawn retains this state until this loop's exit is reported.
// Construction, Start, stop, join and completion belong to the main executor.
class MonitorLoop final : public std::enable_shared_from_this<MonitorLoop> {
public:
    using Factory = std::function<net::awaitable<void>()>;
    using ReportExit = std::function<void(std::string_view, std::exception_ptr)>;

    MonitorLoop(net::any_io_executor executor, std::string name,
                Factory factory, ReportExit report_exit)
        : executor_(std::move(executor)), name_(std::move(name)),
          factory_(std::move(factory)), report_exit_(std::move(report_exit)),
          completion_(executor_, net::steady_timer::time_point::max()) {}

    MonitorLoop(const MonitorLoop&) = delete;
    MonitorLoop& operator=(const MonitorLoop&) = delete;

    void Start() {
        if (active_ || stopping_) return;
        auto self = shared_from_this();
        active_ = true;
        try {
            net::co_spawn(executor_,
                [self]() -> net::awaitable<void> {
                    if (!self->stopping_) co_await self->factory_();
                },
                net::bind_cancellation_slot(cancellation_.slot(),
                    [self](std::exception_ptr failure) {
                        self->active_ = false;
                        self->completion_.cancel();
                        if (self->stopping_ && (!failure || IsOperationCancelled(failure))) return;
                        self->report_exit_(self->name_, std::move(failure));
                    }));
        } catch (...) {
            active_ = false;
            throw;
        }
    }

    void RequestStop() noexcept {
        if (stopping_) return;
        stopping_ = true;
        cancellation_.emit(net::cancellation_type::all);
    }

    net::awaitable<void> AsyncJoin() {
        // A cancelled owner still has to retain the loop through actual completion.
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        while (active_) {
            (void)co_await completion_.async_wait(net::as_tuple(net::use_awaitable));
        }
    }

private:
    net::any_io_executor executor_;
    std::string name_;
    Factory factory_;
    ReportExit report_exit_;
    bool active_ = false;
    net::cancellation_signal cancellation_;
    net::steady_timer completion_;
    bool stopping_ = false;
};

}  // namespace monitor_detail

struct ProcessDescriptors {
    std::optional<size_t> open;
    std::optional<size_t> soft_limit;
    bool soft_limit_unlimited = false;
};

// Control-thread diagnostics only. Unavailable counters remain unknown, not zero.
// Excludes the temporary directory descriptor used by this sample.
[[nodiscard]] inline ProcessDescriptors ReadProcessDescriptors() noexcept {
    ProcessDescriptors result;
    rlimit limits{};
    if (::getrlimit(RLIMIT_NOFILE, &limits) == 0) {
        result.soft_limit_unlimited = limits.rlim_cur == RLIM_INFINITY;
        if (!result.soft_limit_unlimited) {
            result.soft_limit = static_cast<size_t>(limits.rlim_cur);
        }
    }
    if (DIR* directory = ::opendir("/proc/self/fd")) {
        size_t count = 0;
        errno = 0;
        while (const auto* entry = ::readdir(directory)) {
            if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') ++count;
        }
        const bool complete = errno == 0;
        ::closedir(directory);
        if (complete && count > 0) result.open = count - 1;
    }
    return result;
}

