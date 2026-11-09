#pragma once

#include "common/asio_types.hpp"
#include "common/error.hpp"

#include <asio/async_result.hpp>
#include <asio/co_spawn.hpp>
#include <asio/dispatch.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <atomic>
#include <concepts>
#include <cstddef>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>


class WorkerMailboxFull : public std::runtime_error {
public:
    WorkerMailboxFull()
        : std::runtime_error(std::string(ErrorCodeToString(ErrorCode::RESOURCE_EXHAUSTED))) {}
};

// Admission and closure have a single atomic linearization point. Accepted
// slots are released on the owner executor, including failed spawn attempts.
class WorkerMailbox {
public:
    WorkerMailbox(net::io_context& io_context, size_t capacity)
        : io_context_(io_context), capacity_(capacity),
          joined_(std::make_unique<CompletionChannel>(io_context, 1)) {
        if (capacity_ == 0 || capacity_ >= kClosed)
            throw std::invalid_argument("mailbox capacity");
    }
    WorkerMailbox(const WorkerMailbox&) = delete;
    WorkerMailbox& operator=(const WorkerMailbox&) = delete;

    [[nodiscard]] size_t Outstanding() const noexcept {
        return state_.load(std::memory_order_acquire) & ~kClosed;
    }
    [[nodiscard]] bool IsClosed() const noexcept {
        return (state_.load(std::memory_order_acquire) & kClosed) != 0;
    }
    void CloseAdmission() noexcept {
        state_.fetch_or(kClosed, std::memory_order_acq_rel);
    }
    // Single owner-executor observer. Admission must be closed first.
    net::awaitable<void> AsyncJoinAccepted() {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        if (!IsClosed()) throw std::logic_error("joining open mailbox");
        while (Outstanding() != 0) {
            co_await joined_->async_receive(net::use_awaitable);
        }
        joined_.reset();
    }

    // Runs an owner-executor coroutine that may genuinely suspend.
    template <typename T>
    net::awaitable<T> Post(net::awaitable<T> task) {
        Slot slot = Acquire();
        if constexpr (std::is_void_v<T>) {
            co_await net::co_spawn(io_context_.get_executor(),
                RunHeld(std::move(slot), std::move(task)), net::use_awaitable);
        } else {
            co_return co_await net::co_spawn(io_context_.get_executor(),
                RunHeld(std::move(slot), std::move(task)), net::use_awaitable);
        }
    }
    // Runs a synchronous, self-contained callable on the owner executor. Only
    // the cross-thread hop and the completion back to the caller are
    // asynchronous; no owner-side coroutine frame is allocated.
    template <typename Fn>
        requires std::invocable<Fn&>
    net::awaitable<std::invoke_result_t<Fn&>> PostCall(Fn fn) {
        using R = std::invoke_result_t<Fn&>;
        Slot slot = Acquire();
        auto caller_exec = co_await net::this_coro::executor;
        if constexpr (std::is_void_v<R>) {
            co_await net::async_initiate<const net::use_awaitable_t<>&, void(std::exception_ptr)>(
                [this, caller_exec, slot = std::move(slot), fn = std::move(fn)](auto handler) mutable {
                    net::post(io_context_, [caller_exec, slot = std::move(slot), fn = std::move(fn),
                                            handler = std::move(handler)]() mutable {
                        std::exception_ptr err;
                        try {
                            std::invoke(fn);
                        } catch (...) {
                            err = std::current_exception();
                        }
                        slot.ReleaseOnOwner();
                        net::dispatch(caller_exec,
                            [handler = std::move(handler), err = std::move(err)]() mutable {
                                std::move(handler)(std::move(err));
                            });
                    });
                },
                net::use_awaitable);
        } else {
            co_return co_await net::async_initiate<const net::use_awaitable_t<>&, void(std::exception_ptr, R)>(
                [this, caller_exec, slot = std::move(slot), fn = std::move(fn)](auto handler) mutable {
                    net::post(io_context_, [caller_exec, slot = std::move(slot), fn = std::move(fn),
                                            handler = std::move(handler)]() mutable {
                        std::optional<R> result;
                        std::exception_ptr err;
                        try {
                            result.emplace(std::invoke(fn));
                        } catch (...) {
                            err = std::current_exception();
                        }
                        slot.ReleaseOnOwner();
                        net::dispatch(caller_exec,
                            [handler = std::move(handler), err = std::move(err),
                             result = std::move(result)]() mutable {
                                std::move(handler)(std::move(err),
                                    result ? std::move(*result) : R{});
                            });
                    });
                },
                net::use_awaitable);
        }
    }

private:
    using CompletionChannel = SignalChannel;
    static constexpr size_t kClosed = size_t{1} << (std::numeric_limits<size_t>::digits - 1);
    class Slot {
    public:
        explicit Slot(WorkerMailbox& mailbox) noexcept : mailbox_(&mailbox) {}
        Slot(Slot&& other) noexcept : mailbox_(std::exchange(other.mailbox_, nullptr)) {}
        ~Slot() { if (mailbox_) mailbox_->Release(); }
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;
        void ReleaseOnOwner() noexcept {
            if (auto* m = std::exchange(mailbox_, nullptr)) m->ReleaseOnOwner();
        }
    private:
        WorkerMailbox* mailbox_;
    };
    Slot Acquire() {
        auto state = state_.load(std::memory_order_acquire);
        for (;;) {
            if (state & kClosed) throw std::system_error(net::error::operation_aborted);
            if (state >= capacity_) throw WorkerMailboxFull();
            if (state_.compare_exchange_weak(state, state + 1,
                    std::memory_order_acq_rel, std::memory_order_acquire))
                return Slot(*this);
        }
    }
    void ReleaseOnOwner() noexcept {
        const auto previous = state_.fetch_sub(1, std::memory_order_acq_rel);
        if ((previous & ~kClosed) == 0)
            FailRuntime("mailbox-join", "accepted task completion underflow");
        try {
            if (previous == (kClosed | 1) && !joined_->try_send(IoErrorCode{}))
                FailRuntime("mailbox-join", "completion channel already occupied");
        } catch (...) {
            FailRuntime("mailbox-join", "cannot signal accepted task completion");
        }
    }
    void Release() noexcept {
        try {
            // Inline for ordinary task completion. A failed cross-thread
            // initiation retains its slot until this bounded notification runs.
            net::dispatch(io_context_, [this]() noexcept { ReleaseOnOwner(); });
        } catch (...) {
            FailRuntime("mailbox-join", "cannot deliver accepted task completion");
        }
    }
    template <typename T>
    static net::awaitable<T> RunHeld(Slot slot, net::awaitable<T> task) {
        struct OwnerGuard {
            Slot& slot;
            ~OwnerGuard() noexcept { slot.ReleaseOnOwner(); }
        } guard{slot};
        if constexpr (std::is_void_v<T>) co_await std::move(task);
        else co_return co_await std::move(task);
    }
    net::io_context& io_context_;
    size_t capacity_;
    std::atomic<size_t> state_{0};
    std::unique_ptr<CompletionChannel> joined_;
};

