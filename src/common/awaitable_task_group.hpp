#pragma once

#include "common/asio_types.hpp"
#include "common/allocator.hpp"
#include "transport/cancellation.hpp"

#include <asio/async_result.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <chrono>
#include <exception>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>


// A finite group on one executor. Spawn is only valid while the group is alive:
// during start, from a running child, or under a ResidentTaskGroup owner. The
// group joins actual completion callbacks, including children added by another
// child. Parent cancellation and uncaught failure stop every child; an optional
// request source cancels only the child bound to that source.
class AwaitableTaskGroup {
public:
    virtual void Spawn(net::awaitable<void> task,
                       transport::CancellationSource* source = nullptr) = 0;
    virtual void Cancel() = 0;

protected:
    ~AwaitableTaskGroup() = default;
};

namespace task_group_detail {

struct Child final : transport::CancellationSubscription {
    net::cancellation_signal cancellation;
    bool source_cancelled = false;
    Child* next = nullptr;
    Child** previous = nullptr;

    void Bind(transport::CancellationSource& source) noexcept {
        Resubscribe(source);
    }

    std::exception_ptr Complete(std::exception_ptr error) noexcept {
        Unsubscribe();
        // A locally cancelled child is isolated; never hide a different error
        // that raced cancellation.
        if (source_cancelled && IsOperationCancelled(error)) return {};
        return error;
    }

    void Unlink() noexcept {
        if (!previous) return;
        *previous = next;
        if (next) next->previous = previous;
        next = nullptr;
        previous = nullptr;
    }

    ~Child() { Unlink(); }

private:
    void OnCancellation(transport::Cancellation) noexcept override {
        source_cancelled = true;
        cancellation.emit(net::cancellation_type::all);
    }
};

template <typename Handler>
class Group final : public AwaitableTaskGroup,
                    public std::enable_shared_from_this<Group<Handler>> {
public:
    Group(net::any_io_executor executor, Handler handler)
        : executor_(std::move(executor)), completion_(std::move(handler)) {}

    void Spawn(net::awaitable<void> task,
               transport::CancellationSource* source = nullptr) override {
        if (stopping_) throw IoSystemError(net::error::operation_aborted);
        // Acquired and released on the group's executor, never on its caller's.
        auto child = memory::AllocateShared<Child>();
        if (source) {
            child->Bind(*source);
            // Stop is delivered synchronously on subscription. Do not start
            // work whose source was already stopped before co_spawn had a slot.
            if (child->source_cancelled) return;
        }
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
                        self->Finish(child->Complete(std::move(error)));
                    }));
        } catch (...) {
            child->Unsubscribe();
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
            child->Unsubscribe();
            child->cancellation.emit(type);
        }
    }

    void Finish(std::exception_ptr error = {}) {
        if (error) {
            const bool cancelled = IsOperationCancelled(error);
            if (!failure_ || (failure_is_cancellation_ && !cancelled)) {
                failure_ = std::move(error);
                failure_is_cancellation_ = cancelled;
            }
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
    bool failure_is_cancellation_ = false;
    bool stopping_ = false;
};

template <typename Start>
net::awaitable<void> RunOnExecutor(Start start) {
    const auto cancellation = co_await net::this_coro::cancellation_state;
    if (cancellation.cancelled() != net::cancellation_type::none) {
        throw IoSystemError(net::error::operation_aborted);
    }
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

// Owner for tasks that outlive the coroutine starting them, such as pooled
// physical sessions held for a Worker's lifetime. The common no-child case
// stores only the executor; join state and the self-retaining group are created
// by the first Spawn. Spawn through Tasks() is valid on the executor until
// AsyncJoin, which cancels every child and resumes after each actual completion.
// As in any group, an uncaught child failure stops all siblings: resident
// children must contain their own failures.
class ResidentTaskGroup final : public AwaitableTaskGroup {
    struct JoinState {
        explicit JoinState(const net::any_io_executor& executor)
            : wake(executor, std::chrono::steady_clock::time_point::max()) {}
        net::steady_timer wake;
        std::exception_ptr failure;
        bool done = false;
    };

    // Owns the join state: children that a destroyed, never-joined owner
    // cancelled still complete into valid storage.
    struct Completion {
        std::shared_ptr<JoinState> join;
        void operator()(std::exception_ptr failure) {
            join->failure = std::move(failure);
            join->done = true;
            join->wake.cancel();
        }
    };
    using Group = task_group_detail::Group<Completion>;

public:
    explicit ResidentTaskGroup(net::any_io_executor executor)
        : executor_(std::move(executor)) {}
    ResidentTaskGroup(const ResidentTaskGroup&) = delete;
    ResidentTaskGroup& operator=(const ResidentTaskGroup&) = delete;
    ~ResidentTaskGroup() { Close(); }

    [[nodiscard]] AwaitableTaskGroup& Tasks() noexcept { return *this; }

    void Spawn(net::awaitable<void> task,
               transport::CancellationSource* source = nullptr) override {
        if (stopping_) throw IoSystemError(net::error::operation_aborted);
        EnsureStarted();
        group_->Spawn(std::move(task), source);
    }

    void Cancel() override {
        stopping_ = true;
        if (group_) group_->Cancel();
    }

    // A join is never abandoned halfway: caller cancellation is ignored.
    net::awaitable<void> AsyncJoin() {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        Close();
        if (!join_) co_return;
        while (!join_->done) {
            IoErrorCode ignored;
            co_await join_->wake.async_wait(net::redirect_error(net::use_awaitable, ignored));
        }
        if (join_->failure && !IsOperationCancelled(join_->failure)) {
            std::rethrow_exception(join_->failure);
        }
    }

private:
    void EnsureStarted() {
        if (group_) return;
        auto join = memory::AllocateShared<JoinState>(executor_);
        auto group = memory::AllocateShared<Group>(executor_, Completion{join});
        join_ = std::move(join);
        group_ = std::move(group);
    }

    void Close() {
        if (closed_) return;
        closed_ = true;
        stopping_ = true;
        if (!group_) return;
        group_->Cancel();
        group_->Finish();  // releases the launch sentinel
    }

    net::any_io_executor executor_;
    std::shared_ptr<JoinState> join_;
    std::shared_ptr<Group> group_;
    bool stopping_ = false;
    bool closed_ = false;
};

