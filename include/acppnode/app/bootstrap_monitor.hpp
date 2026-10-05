#pragma once

#include <memory>
#include "acppnode/runtime/channel.hpp"

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

    net::awaitable<void> Run();
    [[nodiscard]] bool RequestStop();

private:
    struct Impl;
    std::shared_ptr<Impl> impl_;
    ServiceChannel::Reservation stop_ticket_;
};

}  // namespace acpp
