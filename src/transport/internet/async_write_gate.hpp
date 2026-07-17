#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/as_tuple.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/use_awaitable.hpp>

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

    explicit AsyncWriteGate(net::io_context& io_context)
        : signal_(io_context, 1) {}

    AsyncWriteGate(const AsyncWriteGate&) = delete;
    AsyncWriteGate& operator=(const AsyncWriteGate&) = delete;

    [[nodiscard]] net::awaitable<Lease> Acquire() {
        while (busy_ && !cancelled_) {
            auto [ec] = co_await signal_.async_receive(
                net::as_tuple(net::use_awaitable));
            if (ec) {
                co_return Lease{};
            }
        }
        if (cancelled_) {
            co_return Lease{};
        }

        busy_ = true;
        co_return Lease{this};
    }

    void Cancel() noexcept {
        if (cancelled_) return;
        cancelled_ = true;
        // Closing is the terminal broadcast: every outstanding receive is
        // completed, and future acquirers observe cancelled_ before waiting.
        signal_.close();
    }

private:
    void Release() noexcept {
        busy_ = false;
        if (!cancelled_) {
            (void)signal_.try_send(IoErrorCode{});
        }
    }

    net::experimental::channel<void(IoErrorCode)> signal_;
    bool busy_ = false;
    bool cancelled_ = false;
};

}  // namespace acpp::transport::internet
