#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/experimental/channel.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
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
//   - 只按最近 deadline 重挂共享 timer，避免每个连接独立 timer
//   - 分片内 Schedule/Cancel/OnTimer 在对应 io_context 线程执行，不做热路径锁同步
// ============================================================================
class TimeoutScheduler {
public:
    using Callback = std::function<void()>;

    // 获取 io_context 对应的分片（同一 io_context 复用同一调度器）。
    // Worker 线程命中 thread_local 缓存后不走全局锁。
    [[nodiscard]] static TimeoutScheduler& ForIoContext(net::io_context& io_context);

    // 在所属 io_context 析构前释放分片，避免进程静态析构阶段 timer
    // 访问已销毁的 reactor。仅在对应 io_context 停止且线程已退出后调用。
    static void ReleaseForIoContext(net::io_context& io_context);

    [[nodiscard]] TimeoutToken ScheduleAfter(
        std::chrono::milliseconds delay,
        Callback cb);

    void Cancel(TimeoutToken& token);

private:
    explicit TimeoutScheduler(net::io_context& io_context);

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class ScheduledSleep {
public:
    explicit ScheduledSleep(net::io_context& io_context);
    ~ScheduledSleep() noexcept;

    ScheduledSleep(const ScheduledSleep&) = delete;
    ScheduledSleep& operator=(const ScheduledSleep&) = delete;

    [[nodiscard]] net::awaitable<void> WaitFor(std::chrono::milliseconds delay);
    void Cancel() noexcept;

private:
    net::io_context& io_context_;
    TimeoutScheduler& scheduler_;
    TimeoutToken token_;
    net::experimental::channel<void(IoErrorCode)> signal_;
    bool waiting_ = false;
};

}  // namespace acpp
