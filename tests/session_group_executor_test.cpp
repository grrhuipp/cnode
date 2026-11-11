#include <gtest/gtest.h>

#include "app/session_group_executor.hpp"

#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_future.hpp>

#include <atomic>
#include <future>
#include <stdexcept>
#include <thread>

namespace {

void Require(bool condition, const char* what) {
    if (!condition) throw std::runtime_error(what);
}

TEST(SessionGroupExecutor, WorkerRouteRegistrationAndBoundedCoordinatorControl) {
    net::io_context control, first, second;
    auto control_work = net::make_work_guard(control);
    auto first_work = net::make_work_guard(first);
    auto second_work = net::make_work_guard(second);

    auto coordinator = std::make_shared<GroupCoordinator>(control, 2);
    coordinator->RegisterWorker(first);
    coordinator->RegisterWorker(second);

    Require(coordinator->WorkerCount() == 2, "worker count mismatch");
    Require(GroupCoordinator::ForContext(control) == coordinator.get(), "control context binding missing");
    Require(GroupCoordinator::ForContext(first) == coordinator.get(), "worker 0 context binding missing");
    Require(GroupCoordinator::ForContext(second) == coordinator.get(), "worker 1 context binding missing");

    std::thread control_thread([&] { control.run(); });
    std::thread first_thread([&] { first.run(); });
    std::thread second_thread([&] { second.run(); });

    const auto control_tid = net::co_spawn(
        first,
        coordinator->PostCall([] { return std::this_thread::get_id(); }),
        net::use_future).get();
    Require(control_tid != std::this_thread::get_id(), "PostCall did not execute on control thread");

    std::promise<void> reserved_done;
    auto reserved_fut = reserved_done.get_future();
    struct Returned final : GroupCoordinator::ReservedOperation {
        std::promise<void>& complete;
        explicit Returned(std::promise<void>& value) : complete(value) {}
        void Invoke() noexcept override { complete.set_value(); }
    };
    coordinator->PostReserved(std::make_unique<Returned>(reserved_done));
    reserved_fut.get();

    coordinator->CloseAdmission();
    auto finalize = net::co_spawn(
        control,
        [coordinator]() -> net::awaitable<void> {
            co_await coordinator->AsyncJoin();
            coordinator->ReleaseServices();
            co_await coordinator->Finalize();
        },
        net::use_future);
    finalize.get();
    coordinator.reset();

    control_work.reset();
    first_work.reset();
    second_work.reset();
    control_thread.join();
    first_thread.join();
    second_thread.join();
}

}  // namespace
