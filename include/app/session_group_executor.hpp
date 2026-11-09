#pragma once

#include "common/asio_types.hpp"
#include "common/allocator.hpp"
#include "app/worker_mailbox.hpp"

#include <asio/execution.hpp>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <type_traits>
#include <utility>


class GroupCoordinator : public std::enable_shared_from_this<GroupCoordinator> {
public:
    explicit GroupCoordinator(net::io_context& io, size_t capacity = 1024);
    ~GroupCoordinator();
    void Start();
    // Register fixed Worker routes before their request admission starts.
    void RegisterWorker(uint32_t worker_id, net::io_context& reactor);
    [[nodiscard]] uint32_t WorkerCount() const noexcept;
    [[nodiscard]] static GroupCoordinator* ForContext(net::execution_context& context) noexcept;

    struct ReservedOperation {
        ReservedOperation* next = nullptr;
        virtual ~ReservedOperation() = default;
        virtual void Invoke() noexcept = 0;
    };
    void PostReserved(std::unique_ptr<ReservedOperation> operation) noexcept;
    template<class Function> auto PostCall(Function function) {
        return mailbox_.PostCall([this, function = std::move(function)]() mutable
            -> std::invoke_result_t<Function&> {
            EnsureStarted();
            DrainReserved();
            return std::invoke(function);
        });
    }
    template<class T> net::awaitable<T> Post(net::awaitable<T> task) {
        return mailbox_.Post(RunControl(std::move(task)));
    }
    [[nodiscard]] net::io_context& Reactor() noexcept { return reactor_; }
    [[nodiscard]] net::execution_context& Services() noexcept { return *services_; }
    void CloseAdmission() noexcept { mailbox_.CloseAdmission(); }
    net::awaitable<void> AsyncJoin();
    net::awaitable<void> Finalize();
    // After admission closes and accepted controls join, on the coordinator.
    void ReleaseServices() noexcept { services_.reset(); }
private:
    struct ReservedState;
    void EnsureStarted();
    template<class T> net::awaitable<T> RunControl(net::awaitable<T> task) {
        EnsureStarted();
        DrainReserved();
        if constexpr (std::is_void_v<T>) co_await std::move(task);
        else co_return co_await std::move(task);
    }
    void ArmReserved();
    void DrainReserved() noexcept;
    net::io_context& reactor_;
    WorkerMailbox mailbox_;
    std::unique_ptr<ReservedState> reserved_;
    std::unique_ptr<net::execution_context> services_ =
        std::make_unique<net::execution_context>();
};
