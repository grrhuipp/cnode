#pragma once

#include "common/asio_types.hpp"
#include "app/worker_mailbox.hpp"

#include <asio/execution.hpp>
#include <concepts>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <type_traits>
#include <utility>


namespace app {

class GroupCoordinator : public std::enable_shared_from_this<GroupCoordinator> {
public:
    explicit GroupCoordinator(net::io_context& io, size_t capacity = 1024);
    ~GroupCoordinator();
    void Start();
    // Record fixed Worker count before request admission starts.
    void RegisterWorker() noexcept;
    [[nodiscard]] uint32_t WorkerCount() const noexcept;

    struct ReservedOperation {
        ReservedOperation* next = nullptr;
        void (*complete)(ReservedOperation*) noexcept = nullptr;
    };
    template <typename Op>
        requires std::derived_from<Op, ReservedOperation>
    void PostReserved(std::unique_ptr<Op> operation) noexcept {
        operation->ReservedOperation::complete = +[](ReservedOperation* base) noexcept {
            std::unique_ptr<Op> owned(static_cast<Op*>(base));
            owned->Invoke();
        };
        PostReservedNode(operation.release());
    }
    template<class Function> auto PostCall(Function function) {
        return mailbox_.PostCall([this, function = std::move(function)]() mutable
            -> std::invoke_result_t<Function&> {
            EnsureStarted();
            DrainReserved();
            return std::invoke(function);
        });
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
    void PostReservedNode(ReservedOperation* node) noexcept;
    void EnsureStarted();
    void ArmReserved();
    void DrainReserved() noexcept;
    net::io_context& reactor_;
    WorkerMailbox mailbox_;
    std::unique_ptr<ReservedState> reserved_;
    std::unique_ptr<net::execution_context> services_ =
        std::make_unique<net::execution_context>();
};

}  // namespace app
