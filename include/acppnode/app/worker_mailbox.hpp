#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <atomic>
#include <cstddef>
#include <exception>
#include <future>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace acpp {

class WorkerMailboxFull : public std::runtime_error {
public:
    WorkerMailboxFull()
        : std::runtime_error(std::string(ErrorCodeToString(ErrorCode::RESOURCE_EXHAUSTED))) {}

    static constexpr ErrorCode code = ErrorCode::RESOURCE_EXHAUSTED;
};

// Cold-path bounded admission onto a Worker io_context. Capacity counts
// in-flight posted tasks; a full mailbox rejects instead of queueing without
// bound. Request hot path must not use this.
class WorkerMailbox {
public:
    WorkerMailbox(net::io_context& io_context, size_t capacity)
        : io_context_(io_context)
        , capacity_(capacity == 0 ? 1 : capacity) {}

    WorkerMailbox(const WorkerMailbox&) = delete;
    WorkerMailbox& operator=(const WorkerMailbox&) = delete;

    [[nodiscard]] size_t Capacity() const noexcept { return capacity_; }
    [[nodiscard]] size_t Outstanding() const noexcept {
        return outstanding_.load(std::memory_order_acquire);
    }

    template <typename T>
    net::awaitable<T> Post(net::awaitable<T> task) {
        Slot slot = TryAcquire();
        if (!slot) {
            throw WorkerMailboxFull();
        }
        if constexpr (std::is_void_v<T>) {
            co_await net::co_spawn(
                io_context_.get_executor(),
                RunHeld(std::move(slot), std::move(task)),
                net::use_awaitable);
            co_return;
        } else {
            co_return co_await net::co_spawn(
                io_context_.get_executor(),
                RunHeld(std::move(slot), std::move(task)),
                net::use_awaitable);
        }
    }

    template <typename T>
    std::future<T> PostForFuture(net::awaitable<T> task) {
        Slot slot = TryAcquire();
        if (!slot) {
            std::promise<T> rejected;
            rejected.set_exception(std::make_exception_ptr(WorkerMailboxFull()));
            return rejected.get_future();
        }
        return net::co_spawn(
            io_context_.get_executor(),
            RunHeld(std::move(slot), std::move(task)),
            net::use_future);
    }

private:
    class Slot {
    public:
        Slot() noexcept = default;
        explicit Slot(WorkerMailbox& mailbox) noexcept : mailbox_(&mailbox) {}
        Slot(Slot&& other) noexcept : mailbox_(other.mailbox_) { other.mailbox_ = nullptr; }
        Slot& operator=(Slot&& other) noexcept {
            if (this != &other) {
                Release();
                mailbox_ = other.mailbox_;
                other.mailbox_ = nullptr;
            }
            return *this;
        }
        ~Slot() { Release(); }

        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;

        explicit operator bool() const noexcept { return mailbox_ != nullptr; }

    private:
        void Release() noexcept {
            if (mailbox_ != nullptr) {
                mailbox_->outstanding_.fetch_sub(1, std::memory_order_acq_rel);
                mailbox_ = nullptr;
            }
        }

        WorkerMailbox* mailbox_ = nullptr;
    };

    [[nodiscard]] Slot TryAcquire() noexcept {
        const size_t previous = outstanding_.fetch_add(1, std::memory_order_acq_rel);
        if (previous >= capacity_) {
            outstanding_.fetch_sub(1, std::memory_order_acq_rel);
            return Slot{};
        }
        return Slot(*this);
    }

    template <typename T>
    static net::awaitable<T> RunHeld([[maybe_unused]] Slot slot,
                                     net::awaitable<T> task) {
        if constexpr (std::is_void_v<T>) {
            co_await std::move(task);
        } else {
            co_return co_await std::move(task);
        }
    }

    net::io_context& io_context_;
    size_t capacity_;
    std::atomic<size_t> outstanding_{0};
};

}  // namespace acpp
