#pragma once

#include "common/asio_types.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <cstddef>
#include <optional>
#include <utility>

namespace transport::internet {

// Worker-local coroutine mutex for serialized transport writes. Cancellation
// closes the signal channel so every queued acquirer is resumed; a single
// condition-variable style notification is insufficient for terminal state.
class AsyncWriteGate {
public:
    class Lease {
    public:
        Lease() noexcept = default;
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;

        Lease(Lease&& other) noexcept
            : gate_(std::exchange(other.gate_, nullptr)) {}

        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                Reset();
                gate_ = std::exchange(other.gate_, nullptr);
            }
            return *this;
        }

        ~Lease() noexcept {
            Reset();
        }

        [[nodiscard]] explicit operator bool() const noexcept {
            return gate_ != nullptr;
        }

        void Reset() noexcept {
            if (auto* gate = std::exchange(gate_, nullptr)) {
                gate->Release();
            }
        }

    private:
        friend class AsyncWriteGate;

        explicit Lease(AsyncWriteGate* gate) noexcept
            : gate_(gate) {}

        AsyncWriteGate* gate_ = nullptr;
    };

    AsyncWriteGate() noexcept = default;
    AsyncWriteGate(const AsyncWriteGate&) = delete;
    AsyncWriteGate& operator=(const AsyncWriteGate&) = delete;

    // Owner-thread synchronous fast path. Only contended callers need to
    // construct an acquisition coroutine; leases retain identical ownership.
    [[nodiscard]] Lease TryAcquire() noexcept {
        if (busy_ || cancelled_ || waiters_ != 0) return {};
        busy_ = true;
        return Lease{this};
    }

    [[nodiscard]] net::awaitable<Lease> Acquire(bool ignore_caller_cancellation = false) {
        const auto cancellation = co_await net::this_coro::cancellation_state;
        if (cancelled_ ||
            (!ignore_caller_cancellation &&
             cancellation.cancelled() != net::cancellation_type::none)) {
            co_return Lease{};
        }
        while (busy_ && !cancelled_) {
            if (!signal_) {
                signal_.emplace(co_await net::this_coro::executor, 1);
            }
            ++waiters_;
            struct WaiterScope {
                AsyncWriteGate& gate;
                bool woke = false;
                ~WaiterScope() noexcept {
                    --gate.waiters_;
                    if (woke) gate.notified_ = false;
                    if (gate.waiters_ == 0 && gate.notified_ && gate.signal_) {
                        gate.notified_ = false;
                        gate.signal_->reset();
                    }
                    if (!gate.busy_ && !gate.cancelled_ && !gate.notified_ &&
                        gate.waiters_ != 0 && gate.signal_) {
                        gate.notified_ = true;
                        (void)gate.signal_->try_send(IoErrorCode{});
                    }
                }
            } scope{*this};
            IoErrorCode ec;
            if (ignore_caller_cancellation) {
                std::tie(ec) = co_await signal_->async_receive(
                    net::bind_cancellation_slot(
                        net::cancellation_slot{},
                        net::as_tuple(net::use_awaitable)));
            } else {
                std::tie(ec) = co_await signal_->async_receive(
                    net::as_tuple(net::use_awaitable));
            }
            if (!ec) {
                scope.woke = true;
            }
            if (ec || (!ignore_caller_cancellation &&
                       (co_await net::this_coro::cancellation_state).cancelled() !=
                           net::cancellation_type::none)) {
                co_return Lease{};
            }
            if (!busy_ && !cancelled_) {
                busy_ = true;
                co_return Lease{this};
            }
        }
        if (busy_ || cancelled_) co_return Lease{};
        busy_ = true;
        co_return Lease{this};
    }

    void Cancel() noexcept {
        if (cancelled_) return;
        cancelled_ = true;
        notified_ = false;
        if (signal_) {
            signal_->close();
        }
    }

private:
    void Release() noexcept {
        busy_ = false;
        if (!cancelled_ && !notified_ && waiters_ != 0 && signal_) {
            notified_ = true;
            (void)signal_->try_send(IoErrorCode{});
        }
    }

    std::optional<SignalChannel> signal_;
    std::size_t waiters_ = 0;
    bool busy_ = false;
    bool cancelled_ = false;
    bool notified_ = false;
};

}  // namespace transport::internet
