#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/allocator.hpp"

#include <asio/async_result.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <exception>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

namespace acpp {

// A finite group on one executor. Spawn is only valid during start or from a
// running child. The group joins actual completion callbacks, including children
// added by another child. Cancellation and uncaught failure stop every child.
class AwaitableTaskGroup {
public:
    virtual void Spawn(net::awaitable<void> task) = 0;
    virtual void Cancel() = 0;

protected:
    ~AwaitableTaskGroup() = default;
};

namespace task_group_detail {

struct Child {
    net::cancellation_signal cancellation;
    Child* next = nullptr;
    Child** previous = nullptr;

    void Unlink() noexcept {
        if (!previous) return;
        *previous = next;
        if (next) next->previous = previous;
        next = nullptr;
        previous = nullptr;
    }

    ~Child() { Unlink(); }
};

template <typename Handler>
class Group final : public AwaitableTaskGroup,
                    public std::enable_shared_from_this<Group<Handler>> {
public:
    Group(net::any_io_executor executor, Handler handler)
        : executor_(std::move(executor)), completion_(std::move(handler)) {}

    void Spawn(net::awaitable<void> task) override {
        if (stopping_) throw IoSystemError(net::error::operation_aborted);
        // Acquired and released on the group's executor, never on its caller's.
        auto child = memory::AllocateShared<Child>();
        child->next = head_;
        child->previous = &head_;
        if (head_) head_->previous = &child->next;
        head_ = child.get();
        ++remaining_;
        try {
            net::co_spawn(executor_, std::move(task),
                net::bind_cancellation_slot(child->cancellation.slot(),
                    [self = this->shared_from_this(), child](std::exception_ptr error) {
                        child->Unlink();
                        self->Finish(std::move(error));
                    }));
        } catch (...) {
            child->Unlink();
            --remaining_;
            throw;
        }
    }

    void Cancel() override { Cancel(net::cancellation_type::all); }

    void Cancel(net::cancellation_type type) {
        if (type == net::cancellation_type::none || stopping_) return;
        stopping_ = true;
        // Detach before notification: callbacks may complete other children.
        while (head_) {
            Child* child = head_;
            child->Unlink();
            child->cancellation.emit(type);
        }
    }

    void Finish(std::exception_ptr error = {}) {
        if (error && !failure_) {
            failure_ = std::move(error);
            Cancel(net::cancellation_type::all);
        }
        if (--remaining_ == 0) {
            net::get_associated_cancellation_slot(completion_).clear();
            std::move(completion_)(failure_);
        }
    }

private:
    net::any_io_executor executor_;
    Handler completion_;
    Child* head_ = nullptr;
    size_t remaining_ = 1; // start callback's launch sentinel
    std::exception_ptr failure_;
    bool stopping_ = false;
};

template <typename Start>
net::awaitable<void> RunOnExecutor(Start start) {
    const auto executor = co_await net::this_coro::executor;
    auto token = net::use_awaitable;
    co_await net::async_initiate<decltype(token), void(std::exception_ptr)>(
        [executor, start = std::optional<Start>(std::move(start))](auto handler) mutable {
            static_assert(std::is_nothrow_move_constructible_v<decltype(handler)>);
            auto slot = net::get_associated_cancellation_slot(handler);
            using State = Group<decltype(handler)>;
            std::shared_ptr<State> state;
            try {
                state = memory::AllocateShared<State>(executor, std::move(handler));
            } catch (...) {
                start.reset();
                std::move(handler)(std::current_exception());
                return;
            }
            std::exception_ptr failure;
            try {
                if (slot.is_connected()) {
                    slot.assign([weak = std::weak_ptr<State>(state)](net::cancellation_type type) {
                        if (auto owner = weak.lock()) owner->Cancel(type);
                    });
                }
                (*start)(*state);
            } catch (...) {
                failure = std::current_exception();
            }
            start.reset();
            state->Finish(std::move(failure));
        }, token);
}

}  // namespace task_group_detail

// Start is stored by value in the coroutine, without std::function allocation
// or type erasure. All group/child bookkeeping is allocated on the target thread.
template <typename Start>
net::awaitable<void> RunAwaitableTaskGroup(net::any_io_executor executor, Start start) {
    if ((co_await net::this_coro::executor) == executor) {
        // Normal Worker requests are already on their owner. Do not allocate
        // another co_spawn operation just to return to the same executor.
        co_await task_group_detail::RunOnExecutor(std::move(start));
    } else {
        co_await net::co_spawn(executor,
            task_group_detail::RunOnExecutor(std::move(start)), net::use_awaitable);
    }
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
}

}  // namespace acpp
