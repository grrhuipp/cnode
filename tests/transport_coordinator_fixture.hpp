#pragma once

#include <gtest/gtest.h>
#include "app/group_coordinator.hpp"
#include <asio/co_spawn.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/use_future.hpp>
#include <thread>

// Own a real control reactor independently of the transport's Worker reactor.
class TransportCoordinatorFixture {
public:
    explicit TransportCoordinatorFixture(net::io_context& worker)
        : guard_(net::make_work_guard(control_)),
          coordinator_(std::make_shared<app::GroupCoordinator>(control_)) {
        (void)worker;
        coordinator_->RegisterWorker();
        thread_ = std::thread([this] { control_.run(); });
    }
    ~TransportCoordinatorFixture() {
        coordinator_->CloseAdmission();
        auto joined = net::co_spawn(control_, Shutdown(), net::use_future);
        joined.wait();
        guard_.reset();
        thread_.join();
        EXPECT_NO_THROW(joined.get());
    }
    app::GroupCoordinator& Coordinator() noexcept { return *coordinator_; }
private:
    net::io_context control_;
    net::awaitable<void> Shutdown() {
        co_await coordinator_->AsyncJoin();
        coordinator_->ReleaseServices();
        co_await coordinator_->Finalize();
    }
    net::executor_work_guard<net::io_context::executor_type> guard_;
    std::shared_ptr<app::GroupCoordinator> coordinator_;
    std::thread thread_;
};
