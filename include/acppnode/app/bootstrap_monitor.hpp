#pragma once

#include "acppnode/common/asio_types.hpp"

#include <memory>

namespace acpp {

struct RuntimeContext;

class RuntimeMonitor {
public:
    explicit RuntimeMonitor(const RuntimeContext& ctx);
    ~RuntimeMonitor();

    RuntimeMonitor(const RuntimeMonitor&) = delete;
    RuntimeMonitor& operator=(const RuntimeMonitor&) = delete;
    RuntimeMonitor(RuntimeMonitor&&) = delete;
    RuntimeMonitor& operator=(RuntimeMonitor&&) = delete;

    void Start();
    void RequestStop() noexcept;
    net::awaitable<void> AsyncJoin();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp
