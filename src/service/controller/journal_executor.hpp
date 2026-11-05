#pragma once

#include "acppnode/common/asio_types.hpp"
#include <asio/co_spawn.hpp>
#include <asio/thread_pool.hpp>
#include <atomic>
#include <utility>
#include <stdexcept>
#include <type_traits>

namespace acpp::controller {

// One cold-path disk thread shared by all panels. Admission is bounded and
// shutdown joins outstanding work. Cancellation never abandons a disk write:
// its completion must be observed before the caller releases borrowed state.
class JournalExecutor {
public:
    ~JournalExecutor() { pool_.join(); }

    template<class Function>
    net::awaitable<std::invoke_result_t<Function>> Run(Function function) {
        if (pending_.fetch_add(1, std::memory_order_relaxed) >= kCapacity) {
            pending_.fetch_sub(1, std::memory_order_relaxed);
            throw std::runtime_error("traffic journal executor queue is full");
        }
        Slot slot{this};
        co_return co_await net::co_spawn(pool_,
            Invoke(std::move(slot), std::move(function)), net::use_awaitable);
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
        co_return function();
    }
    static constexpr size_t kCapacity = 64;
    net::thread_pool pool_{1};
    std::atomic<size_t> pending_{0};
};
} // namespace acpp::controller
