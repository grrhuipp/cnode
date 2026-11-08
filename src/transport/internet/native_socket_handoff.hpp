#pragma once

#include "app/session_group_executor.hpp"
#include "common/allocator.hpp"

#include <asio/as_tuple.hpp>
#include <asio/associated_executor.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/bind_executor.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <cassert>
#include <optional>
#include <unistd.h>

namespace transport::internet::detail {

inline net::io_context& CurrentSocketReactor(net::io_context& fallback) noexcept {
    const auto domain = ExecutionDomain::Current();
    return domain ? domain->Reactor() : fallback;
}

// Only readiness notifications cross the native/business boundary. In particular,
// pending_ reaches zero BEFORE business completions are posted to the frozen
// domain; Prepare never waits for a coroutine which that freeze prevents running.
// Both protocol Impls inherit this resource at a stable address. No native
// operation retains payload, pending read buffers, or a scatter-write cursor.
template<class Protocol>
class NativeSocketHandoff : public ExecutionDomain::NativeResource {
public:
    using Socket = typename Protocol::socket;
    using Target = ExecutionDomain::HandoffTarget;

    explicit NativeSocketHandoff(Socket value)
        : socket(std::move(value)), domain_(ExecutionDomain::Current()) {
        if (domain_) domain_->RegisterResource(*this);
    }

    ~NativeSocketHandoff() override {
        if (domain_) domain_->UnregisterResource(*this);
        assert(!staged_ && pending_ == 0);
    }

    // User cancellation is separate from the handoff epoch, including Cancel
    // racing a successful notification already queued to the domain.
    void MarkCancelled() noexcept { ++cancellation_epoch_; }

    net::awaitable<IoErrorCode> Wait(
        typename Socket::wait_type type, net::cancellation_slot cancellation) {
        struct State {
            net::cancellation_signal native;
            bool cancelled = false;
        } state;
        struct Subscription {
            net::cancellation_slot slot;
            ~Subscription() { if (slot.is_connected()) slot.clear(); }
        } subscription{cancellation};
        const auto cancelled_at = cancellation_epoch_;
        for (;;) {
            if (state.cancelled || cancelled_at != cancellation_epoch_)
                co_return IoErrorCode(io_error::operation_aborted);
            const auto epoch = handoff_epoch_;
            // Awaitable completion clears its cancellation slot. Reinstall
            // for each native wait, including retries after a handoff.
            if (cancellation.is_connected()) {
                cancellation.assign([&state](net::cancellation_type kind) {
                    if (kind == net::cancellation_type::none) return;
                    state.cancelled = true;
                    state.native.emit(kind);
                });
            }
            auto token = net::as_tuple(net::use_awaitable);
            auto [error] = co_await net::async_initiate<decltype(token), void(IoErrorCode)>(
                [this, type, &state](auto handler) {
                    auto executor = net::get_associated_executor(handler, socket.get_executor());
                    ++pending_;
                    try {
                        socket.async_wait(type, net::bind_executor(socket.get_executor(),
                            net::bind_cancellation_slot(state.native.slot(), net::bind_allocator(
                                memory::ProcessAllocator<std::byte>{},
                                [this, &state, executor, handler = std::move(handler)]
                                (IoErrorCode error) mutable {
                                    // Remove the old backend cancellation key before its
                                    // descriptor can be released. The external slot still
                                    // records explicit cancellation until business resumes.
                                    state.native.slot().clear();
                                    assert(pending_ != 0);
                                    const bool notify_drain = --pending_ == 0 && drained_;
                                    if (notify_drain) {
                                        // Cancelling an already armed timer queues its
                                        // existing operation; no new fence allocation
                                        // can fail after the last native wait completes.
                                        (void)drained_->cancel();
                                    }
                                    auto completion = net::bind_allocator(
                                        memory::ProcessAllocator<std::byte>{},
                                        [handler = std::move(handler), error]() mutable {
                                            std::move(handler)(error);
                                        });
                                    if (executor.template target<GroupExecutor>()) {
                                        // The group always forks. Keep its queue and
                                        // release-before-invoke erased handler, without
                                        // rewrapping the identical relationship property.
                                        net::require(executor, net::execution::blocking.never)
                                            .execute(std::move(completion));
                                    } else {
                                        net::post(executor, std::move(completion));
                                    }
                                }))));
                    } catch (...) {
                        --pending_;
                        throw;
                    }
                }, token);
            if (state.cancelled || cancelled_at != cancellation_epoch_)
                co_return IoErrorCode(io_error::operation_aborted);
            // Only migration's own aborted readiness is retried. Successful
            // readiness remains useful; EOF/real socket errors are never hidden.
            if (error != io_error::operation_aborted || epoch == handoff_epoch_)
                co_return error;
        }
    }

    net::awaitable<void> PrepareHandoff(const Target& target) override {
        assert(!staged_);
        ++handoff_epoch_;
        if (pending_ != 0) {
            drained_.emplace(socket.get_executor());
            drained_->expires_at(net::steady_timer::time_point::max());
            if (socket.is_open()) {
                IoErrorCode error;
                socket.cancel(error);
                if (error) throw IoSystemError(error);
            }
            auto [error] = co_await drained_->async_wait(net::as_tuple(net::use_awaitable));
            if (error != net::error::operation_aborted) throw IoSystemError(error);
            drained_.reset();
        }
        if (!socket.is_open()) co_return;
        // All old backend callbacks have returned; only metadata notifications
        // can remain in the business queue. Stage the fallible registration on
        // the target before the noexcept commit publishes ownership.
        const auto protocol = socket.local_endpoint().protocol();
        const bool nonblocking = socket.non_blocking();
        staged_ = std::make_unique<Stage>(*target.reactor, protocol, nonblocking);
        staged_->fd = socket.release();
        co_await net::co_spawn(target.executor, staged_->Assign(), net::use_awaitable);
    }

    void CommitHandoff(const Target&) noexcept override {
        if (!staged_) return;
        socket = std::move(staged_->socket);
        staged_.reset();
    }

    net::awaitable<void> CancelHandoff(const Target&) override {
        // A throwing Prepare is included in rollback. It may have failed before
        // release, during assign, or during restoring nonblocking bookkeeping.
        drained_.reset();
        if (!staged_) co_return;
        try {
            if (staged_->socket.is_open()) {
                co_await net::co_spawn(staged_->socket.get_executor(),
                                      staged_->Release(), net::use_awaitable);
            }
            if (staged_->fd >= 0) {
                socket.assign(staged_->protocol, staged_->fd);
                staged_->fd = -1;
                socket.non_blocking(staged_->nonblocking);
            }
            staged_.reset();
        } catch (...) {
            // No backend waits remain on either socket. Close every possible
            // fd owner before reporting failure; the domain can safely thaw
            // cancelled completions rather than expose a half-moved resource.
            MarkCancelled();
            IoErrorCode ignored;
            socket.close(ignored);
            staged_.reset();
            HandoffFailed();
            throw;
        }
    }

    Socket socket;

protected:
    virtual void HandoffFailed() noexcept = 0;

private:
    struct Stage {
        Stage(net::io_context& reactor, Protocol protocol, bool nonblocking)
            : socket(reactor), protocol(protocol), nonblocking(nonblocking) {}
        ~Stage() { if (fd >= 0) ::close(fd); }
        net::awaitable<void> Assign() {
            socket.assign(protocol, fd);
            fd = -1;
            socket.non_blocking(nonblocking);
            co_return;
        }
        net::awaitable<void> Release() {
            fd = socket.release();
            co_return;
        }
        Socket socket;
        Protocol protocol;
        bool nonblocking;
        int fd = -1;
    };
    std::shared_ptr<ExecutionDomain> domain_;
    std::unique_ptr<Stage> staged_;
    std::optional<net::steady_timer> drained_;
    std::size_t pending_ = 0;
    uint64_t handoff_epoch_ = 0;
    uint64_t cancellation_epoch_ = 0;
};

}  // namespace transport::internet::detail
