#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/experimental/concurrent_channel.hpp>
#include <asio/post.hpp>
#include <asio/this_coro.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/use_future.hpp>

#include <atomic>
#include <cstddef>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace acpp {

class ServiceChannelFull : public std::runtime_error {
public:
    ServiceChannelFull()
        : std::runtime_error(std::string(ErrorCodeToString(ErrorCode::RESOURCE_EXHAUSTED))) {}
    static constexpr ErrorCode code = ErrorCode::RESOURCE_EXHAUSTED;
};

// A bounded entry to an owner executor. Channel tokens are the admission
// authority; reservations remain held until committed work has really joined.
class ServiceChannel {
    using TokenChannel = net::experimental::concurrent_channel<void(IoErrorCode)>;

    struct State {
        State(net::any_io_executor executor, size_t limit)
            : capacity(limit == 0 ? 1 : limit), tokens(std::move(executor), capacity) {
            for (size_t i = 0; i < capacity; ++i) {
                if (!tokens.try_send(IoErrorCode{})) std::terminate();
            }
        }
        const size_t capacity;
        TokenChannel tokens;
        // Observation only; capacity admission is exclusively controlled by tokens.
        std::atomic<size_t> outstanding{0};
    };

public:
    class Reservation;
    ServiceChannel(net::any_io_executor executor, size_t capacity)
        : executor_(std::move(executor)), state_(std::make_shared<State>(executor_, capacity)) {}
    ServiceChannel(const ServiceChannel&) = delete;
    ServiceChannel& operator=(const ServiceChannel&) = delete;

    [[nodiscard]] net::any_io_executor Executor() const { return executor_; }
    [[nodiscard]] size_t Outstanding() const noexcept {
        return state_->outstanding.load(std::memory_order_acquire);
    }

    template <class T>
    net::awaitable<T> Post(net::awaitable<T> task) {
        auto reservation = TryAcquire();
        if (!reservation) throw ServiceChannelFull();
        if constexpr (std::is_void_v<T>) {
            co_await net::co_spawn(executor_, RunHeld(std::move(reservation), std::move(task)), net::use_awaitable);
        } else {
            co_return co_await net::co_spawn(executor_, RunHeld(std::move(reservation), std::move(task)), net::use_awaitable);
        }
    }

    template <class Function>
    auto Call(Function function) -> net::awaitable<std::invoke_result_t<Function&>> {
        return PostCommitted(Invoke(std::move(function)));
    }

    template <class T>
    net::awaitable<T> PostCommitted(net::awaitable<T> task) {
        auto reservation = TryAcquire();
        if (!reservation) throw ServiceChannelFull();
        co_return co_await JoinCommitted(executor_,
            RunHeld(std::move(reservation), std::move(task)));
    }

    template <class Function>
    auto CallReserved(Reservation& reservation, Function function)
        -> net::awaitable<std::invoke_result_t<Function&>> {
        if (!reservation) throw ServiceChannelFull();
        return JoinCommitted(executor_, Invoke(std::move(function)));
    }

    template <class T>
    net::awaitable<T> PostReserved(Reservation& reservation, net::awaitable<T> task) {
        if (!reservation) throw ServiceChannelFull();
        return JoinCommitted(executor_, std::move(task));
    }

    [[nodiscard]] Reservation TryReserve() noexcept { return TryAcquire(); }

    template <class Function>
    bool Send(Function function) {
        auto reservation = TryAcquire();
        if (!reservation) return false;
        return SendReserved(std::move(reservation), std::move(function));
    }

    template <class Function>
    bool SendReserved(Reservation reservation, Function function) {
        if (!reservation) return false;
        try {
            net::post(executor_,
                [reservation = std::move(reservation), function = std::move(function)]() mutable {
                    std::invoke(function);
                });
            return true;
        } catch (...) {
            return false;
        }
    }

    class Reservation {
    public:
        Reservation() noexcept = default;
        explicit Reservation(std::shared_ptr<State> state) noexcept : state_(std::move(state)) {}
        Reservation(Reservation&& other) noexcept : state_(std::move(other.state_)) {}
        Reservation& operator=(Reservation&& other) noexcept {
            if (this != &other) {
                Release();
                state_ = std::move(other.state_);
            }
            return *this;
        }
        ~Reservation() { Release(); }
        Reservation(const Reservation&) = delete;
        Reservation& operator=(const Reservation&) = delete;
        explicit operator bool() const noexcept { return state_ != nullptr; }
    private:
        void Release() noexcept {
            if (state_) {
                state_->outstanding.fetch_sub(1, std::memory_order_acq_rel);
                if (!state_->tokens.try_send(IoErrorCode{})) std::terminate();
                state_.reset();
            }
        }
        std::shared_ptr<State> state_;
    };

private:
    [[nodiscard]] Reservation TryAcquire() noexcept {
        if (!state_->tokens.try_receive([](IoErrorCode) {})) return {};
        state_->outstanding.fetch_add(1, std::memory_order_acq_rel);
        return Reservation(state_);
    }

    template <class T>
    static net::awaitable<T> RunHeld([[maybe_unused]] Reservation reservation,
                                      net::awaitable<T> task) {
        if constexpr (std::is_void_v<T>) co_await std::move(task);
        else co_return co_await std::move(task);
    }

    template <class Function>
    static auto Invoke(Function function) -> net::awaitable<std::invoke_result_t<Function&>> {
        if constexpr (std::is_void_v<std::invoke_result_t<Function&>>) {
            std::invoke(function);
            co_return;
        } else {
            co_return std::invoke(function);
        }
    }

    template <class T>
    static net::awaitable<T> JoinCommitted(net::any_io_executor executor,
                                           net::awaitable<T> task) {
        const bool previous = co_await net::this_coro::throw_if_cancelled();
        co_await net::this_coro::throw_if_cancelled(false);
        std::exception_ptr failure;
        std::optional<std::conditional_t<std::is_void_v<T>, bool, T>> result;
        try {
            if constexpr (std::is_void_v<T>) {
                co_await net::co_spawn(executor, std::move(task),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
                result.emplace(true);
            } else {
                result.emplace(co_await net::co_spawn(executor, std::move(task),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable)));
            }
        } catch (...) {
            failure = std::current_exception();
        }
        const auto cancellation = co_await net::this_coro::cancellation_state;
        co_await net::this_coro::throw_if_cancelled(previous);
        if (cancellation.cancelled() != net::cancellation_type::none) {
            throw net::system_error(net::error::operation_aborted);
        }
        if (failure) std::rethrow_exception(failure);
        if constexpr (!std::is_void_v<T>) co_return std::move(*result);
    }

    net::any_io_executor executor_;
    std::shared_ptr<State> state_;
};

}  // namespace acpp
