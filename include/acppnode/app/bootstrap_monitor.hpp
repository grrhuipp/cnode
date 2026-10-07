#pragma once

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

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp
