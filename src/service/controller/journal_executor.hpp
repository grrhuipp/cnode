#pragma once

#include "common/asio_types.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <asio/thread_pool.hpp>
#include <atomic>
#include <exception>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace controller {

// One cold-path disk thread shared by all panels. Admission is bounded and
// shutdown joins outstanding work. Cancellation never abandons a disk write:
// its completion must be observed before the caller releases borrowed state.
class JournalExecutor {
public:
    ~JournalExecutor() { pool_.join(); }

    template<class Function>
    net::awaitable<std::invoke_result_t<Function>> Run(Function function) {
        using Result = std::invoke_result_t<Function>;
        if (pending_.fetch_add(1, std::memory_order_relaxed) >= kCapacity) {
            pending_.fetch_sub(1, std::memory_order_relaxed);
            throw std::runtime_error("traffic journal executor queue is full");
        }
        Slot slot{this};
        const bool throw_if_cancelled = co_await net::this_coro::throw_if_cancelled();
        co_await net::this_coro::throw_if_cancelled(false);
        std::exception_ptr failure;
        if constexpr (std::is_void_v<Result>) {
            try {
                co_await net::co_spawn(
                    pool_,
                    Invoke(std::move(slot), std::move(function)),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
            } catch (...) {
                failure = std::current_exception();
            }
            co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
            if (failure) std::rethrow_exception(failure);
            co_return;
        } else {
            std::optional<Result> result;
            try {
                result.emplace(co_await net::co_spawn(
                    pool_,
                    Invoke(std::move(slot), std::move(function)),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable)));
            } catch (...) {
                failure = std::current_exception();
            }
            co_await net::this_coro::throw_if_cancelled(throw_if_cancelled);
            if (failure) std::rethrow_exception(failure);
            co_return std::move(*result);
        }
    }
private:
    struct Slot {
        JournalExecutor* owner;
        explicit Slot(JournalExecutor* value) noexcept : owner(value) {}
        Slot(Slot&& other) noexcept : owner(std::exchange(other.owner, nullptr)) {}
        Slot(const Slot&) = delete;
        ~Slot() { if (owner) owner->pending_.fetch_sub(1, std::memory_order_relaxed); }
    };
    template<class Function>
    static net::awaitable<std::invoke_result_t<Function>> Invoke(
        [[maybe_unused]] Slot slot, Function function) {
        if constexpr (std::is_void_v<std::invoke_result_t<Function>>) {
            function();
            co_return;
        } else {
            co_return function();
        }
    }
    static constexpr size_t kCapacity = 64;
    net::thread_pool pool_{1};
    std::atomic<size_t> pending_{0};
};
} // namespace controller
