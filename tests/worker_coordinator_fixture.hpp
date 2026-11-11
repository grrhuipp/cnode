#pragma once

#include "app/session_group_executor.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <chrono>
#include <future>
#include <memory>

// 调用方先收束全部数据 Worker；夹具随后在显式控制执行器上收束协调器。
class WorkerCoordinatorFixture final {
public:
    explicit WorkerCoordinatorFixture(net::io_context& control)
        : control_(control), coordinator_(std::make_shared<GroupCoordinator>(control)) {}
    ~WorkerCoordinatorFixture() {
        auto result = net::co_spawn(control_, Finish(), net::use_future);
        while (result.wait_for(std::chrono::seconds::zero()) != std::future_status::ready) {
            if (control_.stopped()) control_.restart();
            control_.run_one();
        }
        try { result.get(); } catch (...) { std::terminate(); }
    }
    net::awaitable<void> Finish() {
        coordinator_->CloseAdmission();
        co_await coordinator_->AsyncJoin();
        coordinator_->ReleaseServices();
        co_await coordinator_->Finalize();
    }
    [[nodiscard]] const std::shared_ptr<GroupCoordinator>& Get() const noexcept {
        return coordinator_;
    }
private:
    net::io_context& control_;
    std::shared_ptr<GroupCoordinator> coordinator_;
};
