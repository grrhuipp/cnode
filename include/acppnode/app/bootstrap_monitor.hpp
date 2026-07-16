#pragma once

#include "acppnode/app/bootstrap_runtime.hpp"

#include <memory>

namespace acpp {

class RuntimeMonitor {
public:
    explicit RuntimeMonitor(const RuntimeContext& ctx);
    ~RuntimeMonitor();

    RuntimeMonitor(const RuntimeMonitor&) = delete;
    RuntimeMonitor& operator=(const RuntimeMonitor&) = delete;
    RuntimeMonitor(RuntimeMonitor&&) = delete;
    RuntimeMonitor& operator=(RuntimeMonitor&&) = delete;

    void Start();
    net::awaitable<void> Stop();

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
};

}  // namespace acpp
