#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>

#include <cstddef>
#include <optional>
#include <utility>

namespace acpp::transport::internet {

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

    explicit AsyncWriteGate(net::io_context&) noexcept {}

    explicit AsyncWriteGate(const net::any_io_executor&) noexcept {}
    AsyncWriteGate(const AsyncWriteGate&) = delete;
    AsyncWriteGate& operator=(const AsyncWriteGate&) = delete;

    // Owner-thread synchronous fast path. Only contended callers need to
    // construct an acquisition coroutine; leases retain identical ownership.
    [[nodiscard]] Lease TryAcquire() noexcept {
        if (busy_ || cancelled_) return {};
        busy_ = true;
        return Lease{this};
    }

    [[nodiscard]] net::awaitable<Lease> Acquire() {
        while (busy_ && !cancelled_) {
            if (!signal_) {
                signal_.emplace(co_await net::this_coro::executor, 1);
            }
            ++waiters_;
            struct WaiterScope {
                std::size_t& waiters;
                ~WaiterScope() noexcept { --waiters; }
            } scope{waiters_};
            auto [ec] = co_await signal_->async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                co_return Lease{};
            }
        }
        co_return TryAcquire();
    }

    void Cancel() noexcept {
        if (cancelled_) return;
        cancelled_ = true;
        if (signal_) {
            signal_->close();
        }
    }

private:
    void Release() noexcept {
        busy_ = false;
        if (!cancelled_ && waiters_ != 0 && signal_) {
            (void)signal_->try_send(IoErrorCode{});
        }
    }

    std::optional<net::experimental::channel<void(IoErrorCode)>> signal_;
    std::size_t waiters_ = 0;
    bool busy_ = false;
    bool cancelled_ = false;
};

}  // namespace acpp::transport::internet
