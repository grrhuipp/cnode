#pragma once

#include "api/api.hpp"
#include "app/stats.hpp"
#include "common/asio_types.hpp"
#include "infra/config.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <asio/thread_pool.hpp>
#include <asio/use_awaitable.hpp>

#include <atomic>
#include <cstddef>
#include <exception>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>

namespace controller {

// UniProxy is additive and has no idempotency token. Only ready records may be
// sent. Unknown records require external reconciliation, never automatic retry.
// 磁盘格式（记录名文法、上限、行解码）见 traffic_journal_format.hpp。
class TrafficJournal {
public:
    struct Batch {
        std::vector<api::UserTraffic> traffic;
        std::vector<std::filesystem::path> records;
    };

    explicit TrafficJournal(const PanelConfig& config);
    ~TrafficJournal();
    TrafficJournal(const TrafficJournal&) = delete;
    TrafficJournal& operator=(const TrafficJournal&) = delete;
    void Suspend() noexcept;
    void Append(const app::UserTrafficCounters& traffic);
    [[nodiscard]] Batch Prepare();
    void Begin(Batch& batch);
    void Acknowledge(const Batch& batch);
    [[nodiscard]] size_t UnknownCount();
    [[nodiscard]] const std::filesystem::path& Directory() const noexcept { return directory_; }

private:
    void CheckHealthy() const;
    void SyncDirectory();
    std::filesystem::path directory_;
    int lock_fd_ = -1;
    int directory_fd_ = -1;
    bool failed_ = false;
};

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

}  // namespace controller
