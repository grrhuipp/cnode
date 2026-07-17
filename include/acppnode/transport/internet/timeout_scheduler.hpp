#pragma once

#include "acppnode/common/asio_types.hpp"

#include <asio/experimental/channel.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <utility>

namespace acpp {

class TimeoutSchedulerService;
class TimeoutScheduler;

// ============================================================================
// TimeoutToken - 共享定时调度器句柄
// ============================================================================
class TimeoutToken {
public:
    TimeoutToken() noexcept = default;
    TimeoutToken(const TimeoutToken&) = delete;
    TimeoutToken& operator=(const TimeoutToken&) = delete;

    TimeoutToken(TimeoutToken&& other) noexcept
        : id_(std::exchange(other.id_, 0))
        , owner_(std::exchange(other.owner_, nullptr)) {}

    // Assignment replaces ownership: a still-live destination event is
    // cancelled before the source handle is adopted.
    TimeoutToken& operator=(TimeoutToken&& other);

    [[nodiscard]] bool Valid() const noexcept {
        return id_ != 0 && owner_ != nullptr;
    }
    void Reset() noexcept {
        id_ = 0;
        owner_ = nullptr;
    }

private:
    friend class TimeoutScheduler;

    uint64_t id_ = 0;
    TimeoutScheduler* owner_ = nullptr;
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
    using Callback = std::move_only_function<void()>;

    // 获取 io_context 对应的分片（同一 io_context 复用同一调度器）。
    // Worker 线程命中 thread_local 缓存后不走全局锁。
    [[nodiscard]] static TimeoutScheduler& ForIoContext(net::io_context& io_context);

    // 在所属 io_context 析构前释放分片，避免进程静态析构阶段 timer
    // 访问已销毁的 reactor。仅在对应 io_context 停止且线程已退出后调用。
    static void ReleaseForIoContext(net::io_context& io_context);

    // Callback exceptions are isolated inside the scheduler: one failed
    // timeout must not unwind the owning Worker io_context or skip its batch.
    [[nodiscard]] TimeoutToken ScheduleAfter(
        std::chrono::milliseconds delay,
        Callback cb);

    void Cancel(TimeoutToken& token);

private:
    friend class TimeoutSchedulerService;

    explicit TimeoutScheduler(net::io_context& io_context);
    void Release() noexcept;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

class ScheduledSleep {
public:
    explicit ScheduledSleep(net::io_context& io_context);
    ~ScheduledSleep() noexcept;

    ScheduledSleep(const ScheduledSleep&) = delete;
    ScheduledSleep& operator=(const ScheduledSleep&) = delete;

    // One instance represents one outstanding sleep. Concurrent waits are a
    // logic error because the cancellation token and wake channel are shared.
    [[nodiscard]] net::awaitable<void> WaitFor(std::chrono::milliseconds delay);
    void Cancel() noexcept;

private:
    TimeoutScheduler& scheduler_;
    TimeoutToken token_;
    net::experimental::channel<void(IoErrorCode)> signal_;
    bool waiting_ = false;
};

}  // namespace acpp
