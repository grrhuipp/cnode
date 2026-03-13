#pragma once

#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/timeout_scheduler.hpp"
#include <atomic>
#include <vector>

namespace acpp {

// ============================================================================
// TcpStream - TCP 流实现
// ============================================================================
class TcpStream final : public AsyncStream {
public:
    // 从已接受的 socket 构造
    explicit TcpStream(tcp::socket socket);

    // 禁止拷贝
    TcpStream(const TcpStream&) = delete;
    TcpStream& operator=(const TcpStream&) = delete;

    // 允许移动
    TcpStream(TcpStream&& other) noexcept;
    TcpStream& operator=(TcpStream&& other) noexcept;

    ~TcpStream() override;

    // AsyncStream 接口实现
    cobalt::task<std::size_t> AsyncRead(net::mutable_buffer buf) override;
    cobalt::task<std::size_t> AsyncWrite(net::const_buffer buf) override;

    // MultiBuffer 优化路径
    // ReadMultiBuffer : async_read_some 直填 pool Buffer
    // WriteMultiBuffer: scatter-write (WSASend / writev)，多 Buffer 合并为单次系统调用
    cobalt::task<MultiBuffer> ReadMultiBuffer() override;
    cobalt::task<void>        WriteMultiBuffer(MultiBuffer mb) override;
    void ShutdownRead() override;
    void ShutdownWrite() override;
    void Close() override;
    void Cancel() noexcept override;
    int NativeHandle() const override;
    net::any_io_executor GetExecutor() const override;
    bool IsOpen() const override;

    // GetBaseTcpStream：返回自身（装饰器链终点）
    TcpStream* GetBaseTcpStream() override { return this; }
    const TcpStream* GetBaseTcpStream() const override { return this; }

    // ── 超时控制 & 端点查询（仅 TcpStream 实现，非虚）─────────────────────────
    tcp::endpoint LocalEndpoint() const;
    tcp::endpoint RemoteEndpoint() const;
    void SetIdleTimeout(std::chrono::seconds timeout);
    bool ConsumeIdleTimeout() noexcept;
    void SetReadTimeout(std::chrono::seconds timeout);
    void SetWriteTimeout(std::chrono::seconds timeout);
    bool ConsumeReadTimeout() noexcept;
    bool ConsumeWriteTimeout() noexcept;
    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout);
    void ClearPhaseDeadline();
    bool ConsumePhaseDeadline() noexcept;

    // 流标签（调试用，标识 inbound/outbound）
    void SetStreamLabel(std::string_view label) { stream_label_.assign(label.data(), label.size()); }
    const std::string& StreamLabel() const { return stream_label_; }
    void SetAbortiveClose(bool enable = true) noexcept { abortive_close_ = enable; }

    // 获取底层 socket（用于特殊操作）
    tcp::socket& Socket() { return socket_; }
    const tcp::socket& Socket() const { return socket_; }
    
    // 设置待处理数据（用于 PROXY protocol 等场景）
    void SetPendingData(std::vector<uint8_t> data) {
        pending_data_ = std::move(data);
        pending_offset_ = 0;
    }

    // 静态工厂方法：连接到已解析的端点
    [[nodiscard]]
    static cobalt::task<DialResult> Connect(
        net::any_io_executor executor,
        const tcp::endpoint& endpoint,
        std::chrono::seconds timeout = std::chrono::seconds(10));

    // 静态工厂方法：绑定本地地址后连接
    [[nodiscard]]
    static cobalt::task<DialResult> ConnectWithBind(
        net::any_io_executor executor,
        const net::ip::address& local_addr,
        const tcp::endpoint& remote_endpoint,
        std::chrono::seconds timeout = std::chrono::seconds(10));

private:
    tcp::socket socket_;
    std::string stream_label_;  // 调试标签："in" / "out"
    bool abortive_close_ = false;
    bool read_shutdown_ = false;
    bool write_shutdown_ = false;
    bool counted_active_ = false;
    std::vector<uint8_t> pending_data_;  // 待处理数据（PROXY protocol 解析后的剩余数据）
    size_t pending_offset_ = 0;          // 已消费的偏移，避免 O(n) erase

    // 自适应散读策略（仿 Xray allocStrategy）：
    //   低流量 → 1 个 Buffer；读满后加倍，最多 8 个；未读满则收缩。
    //   高吞吐时将多个 Buffer 合并为单次 readv / WSARecv，减少系统调用。
    uint32_t read_alloc_count_ = 1;
    // 单 Buffer 快速路径下，连续“大包”读命中次数。
    // 避免必须读满 8KB 才升级为 scatter-read，提升中高吞吐场景切换速度。
    uint8_t read_grow_streak_ = 0;

    // 惰性空闲超时：每次 I/O 仅记录 last_io_time_，共享调度器负责触发检查。
    std::chrono::seconds idle_timeout_{0};  // 0 = 不启用
    std::atomic<bool> idle_timed_out_{false};
    steady_clock::time_point last_io_time_; // 最后一次成功 I/O 的时间

    // 方向性 I/O deadline：单次挂起的读/写操作各自独立（共享调度）。
    std::chrono::seconds read_timeout_{0};
    std::chrono::seconds write_timeout_{0};
    std::atomic<bool> read_timed_out_{false};
    std::atomic<bool> write_timed_out_{false};

    // 阶段性绝对 deadline：一次性触发，不随 I/O 重置（共享调度）。
    std::atomic<bool> phase_deadline_timed_out_{false};
    TimeoutScheduler* timeout_scheduler_ = nullptr;
    TimeoutToken idle_timer_token_;
    TimeoutToken read_deadline_token_;
    TimeoutToken write_deadline_token_;
    TimeoutToken phase_deadline_token_;

    void TouchActivity();          // 记录 I/O 活动时间（极轻量，替代原 ResetIdleTimer）
    void ScheduleIdleCheck();      // 启动/续调 idle 检查定时器
    void CancelIdleTimer() noexcept;
    void ArmReadDeadline();
    void ArmWriteDeadline();
    void CancelReadDeadline() noexcept;
    void CancelWriteDeadline() noexcept;
    void CancelPhaseDeadline() noexcept;
    void ReleaseActiveCounter() noexcept;
};

// ============================================================================
// 设置已连接 socket 的选项
// ============================================================================
void SetupConnectedSocket(tcp::socket& sock);

// ============================================================================
// 设置 Listener socket 的选项
// ============================================================================
void SetupListenerSocket(tcp::acceptor& acceptor, const tcp::endpoint& endpoint);

}  // namespace acpp
