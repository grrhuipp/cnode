#pragma once

#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <utility>

namespace acpp::tests {

class RuntimeServicesFixture final {
public:
    explicit RuntimeServicesFixture(net::any_io_executor executor)
        : executor_(std::move(executor)) {
        TimeoutScheduler::Install(executor_);
    }

    RuntimeServicesFixture(const RuntimeServicesFixture&) = delete;
    RuntimeServicesFixture& operator=(const RuntimeServicesFixture&) = delete;

    ~RuntimeServicesFixture() { TimeoutScheduler::ReleaseForExecutor(executor_); }

private:
    net::any_io_executor executor_;
};

}  // namespace acpp::tests
