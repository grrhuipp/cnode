#pragma once

#include "acppnode/common.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>

namespace acpp {

// ============================================================================
// TimeoutToken - 共享定时调度器句柄
// ============================================================================
struct TimeoutToken {
    uint64_t id = 0;

    [[nodiscard]] bool Valid() const noexcept { return id != 0; }
    void Reset() noexcept { id = 0; }
};

// ============================================================================
// TimeoutScheduler - 按 executor 分片的共享超时调度器
//
// 目标：
//   - 用每分片 1 个 steady_timer 承载大量连接的 deadline/timeout
//   - 避免 TcpStream 每连接常驻多个 timer 对象
// ============================================================================
class TimeoutScheduler {
public:
    using Callback = unique_function<void()>;

    // 获取 executor 对应的分片（同一 io_context 复用同一调度器）
    [[nodiscard]] static TimeoutScheduler& ForExecutor(net::any_io_executor executor);

    [[nodiscard]] TimeoutToken ScheduleAfter(
        std::chrono::milliseconds delay,
        Callback cb);

    void Cancel(TimeoutToken& token);

private:
    explicit TimeoutScheduler(net::any_io_executor executor);

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp
