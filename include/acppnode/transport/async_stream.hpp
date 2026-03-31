#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/transport/multi_buffer.hpp"

namespace acpp {

class TcpStream;  // 前置声明

class PhaseDeadlineHandle {
public:
    PhaseDeadlineHandle() = default;

    // 直接引用 TcpStream::phase_deadline_timed_out_，零堆分配。
    // 安全性：TcpStream 析构时 CancelPhaseDeadline() 已撤销定时器，
    // 且 PhaseDeadlineHandle 的生命周期不超过持有它的协程帧（TcpStream 在同一帧内）。
    explicit PhaseDeadlineHandle(std::atomic<bool>* expired) noexcept
        : expired_(expired) {}

    [[nodiscard]] bool Expired() const noexcept {
        return expired_ && expired_->load(std::memory_order_acquire);
    }

    explicit operator bool() const noexcept { return expired_ != nullptr; }

private:
    std::atomic<bool>* expired_ = nullptr;
};

// ============================================================================
// AsyncStream - 异步流抽象接口
// 
// 生命周期规范：
// ┌─────────────────────────────────────────────────────────────────────────┐
// │ 1. 所有操作（ShutdownRead/ShutdownWrite/Cancel/Close）必须幂等         │
// │ 2. Close() 后所有 Async 操作应立即返回错误                               │
// │ 3. Cancel() 仅取消挂起操作，不改变连接状态                               │
// │ 4. TLS 流的 AsyncShutdownWrite() 必须发送 close_notify                  │
// └─────────────────────────────────────────────────────────────────────────┘
// ============================================================================
class AsyncStream {
public:
    virtual ~AsyncStream() noexcept = default;

    // ========================================================================
    // 数据传输
    // ========================================================================
    
    /**
     * 异步读取数据
     * 
     * @param buf 目标缓冲区
     * @return 读取字节数；0 表示 EOF（对端关闭写端）
     * @throws boost::system::system_error 网络错误
     */
    virtual cobalt::task<std::size_t> AsyncRead(net::mutable_buffer buf) = 0;

    /**
     * 异步写入数据
     *
     * @param buf 源缓冲区
     * @return 写入字节数
     * @throws boost::system::system_error 网络错误
     */
    virtual cobalt::task<std::size_t> AsyncWrite(net::const_buffer buf) = 0;

    // ========================================================================
    // MultiBuffer 流式接口（对应 Xray buf.Reader / buf.Writer）
    //
    // 默认实现基于 AsyncRead/AsyncWrite，子类可 override 实现更高效的路径：
    //   - TcpStream: scatter-write (writev)
    //   - VMessStream: 解密直写 pool Buffer，省去一次 memcpy
    //
    // 所有权规则：
    //   ReadMultiBuffer()  - 返回的 MultiBuffer 由调用方负责 Free
    //   WriteMultiBuffer() - 接管 mb 所有权，完成后自动 Free
    // ========================================================================

    /**
     * 批量读取数据到 MultiBuffer
     *
     * @return MultiBuffer（空 = EOF）；调用方负责 FreeMultiBuffer
     * @throws boost::system::system_error 网络错误
     */
    virtual cobalt::task<MultiBuffer> ReadMultiBuffer();

    /**
     * 批量写入 MultiBuffer（接管所有权，写完后自动 Free）
     *
     * @throws boost::system::system_error 网络错误
     */
    virtual cobalt::task<void> WriteMultiBuffer(MultiBuffer mb);

    // ========================================================================
    // 关闭操作（所有操作必须幂等）
    // ========================================================================
    
    /**
     * 半关闭读端（同步，幂等）
     * 
     * 效果：后续 AsyncRead() 立即返回 0 (EOF)
     * TCP：调用 shutdown(SHUT_RD)
     */
    virtual void ShutdownRead() {}

    /**
     * 半关闭写端（同步，幂等）
     * 
     * 效果：发送 EOF 信号，后续 AsyncWrite() 返回错误
     * TCP：调用 shutdown(SHUT_WR)，发送 FIN
     * 
     * ⚠️ 对于 TLS 流，应使用 AsyncShutdownWrite() 以发送 close_notify
     */
    virtual void ShutdownWrite() = 0;

    /**
     * 异步半关闭写端（幂等）
     * 
     * 用于需要发送协议级 EOF 的流：
     * - TLS：发送 close_notify alert
     * - VMess：发送 EOF chunk
     * 
     * 默认实现调用同步版本
     */
    virtual cobalt::task<void> AsyncShutdownWrite() {
        ShutdownWrite();
        co_return;
    }

    /**
     * 取消所有挂起的异步操作（幂等）
     * 
     * 效果：所有挂起的 AsyncRead/AsyncWrite 返回 operation_aborted
     * 注意：不改变 socket 状态，不发送任何数据
     */
    virtual void Cancel() noexcept = 0;

    /**
     * 完全关闭连接（幂等）
     * 
     * 效果：
     * 1. 调用 Cancel() 取消挂起操作
     * 2. 关闭底层 socket
     * 3. 释放所有资源
     * 
     * 调用后 IsOpen() 返回 false
     */
    virtual void Close() = 0;

    // ========================================================================
    // 状态查询
    // ========================================================================
    
    /**
     * 获取底层文件描述符
     * 
     * @return fd，或 -1 如果已关闭
     */
    virtual int NativeHandle() const = 0;

    /**
     * 获取关联的 executor
     */
    virtual net::any_io_executor GetExecutor() const = 0;

    /**
     * 判断是否打开
     * 
     * @return true 如果连接仍然有效
     */
    virtual bool IsOpen() const = 0;

    // ========================================================================
    // 底层 TcpStream 访问
    //
    // 底层 TcpStream 访问（兼容层）
    // 新代码优先使用下方 timeout/deadline/endpoint helper，
    // 避免在上层业务直接依赖 TcpStream 具体类型。
    // ========================================================================

    virtual TcpStream* GetBaseTcpStream() { return nullptr; }
    virtual const TcpStream* GetBaseTcpStream() const { return nullptr; }

    // ========================================================================
    // Tcp 能力透传 helper（默认通过 GetBaseTcpStream() 转发）
    // ========================================================================

    void SetIdleTimeout(std::chrono::seconds timeout);
    void SetReadTimeout(std::chrono::seconds timeout);
    void SetWriteTimeout(std::chrono::seconds timeout);

    [[nodiscard]] bool ConsumeIdleTimeout() noexcept;
    [[nodiscard]] bool ConsumeReadTimeout() noexcept;
    [[nodiscard]] bool ConsumeWriteTimeout() noexcept;

    [[nodiscard]] PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout);
    void ClearPhaseDeadline();
    [[nodiscard]] bool ConsumePhaseDeadline() noexcept;

    [[nodiscard]] std::optional<tcp::endpoint> LocalEndpoint() const;
    [[nodiscard]] std::optional<tcp::endpoint> RemoteEndpoint() const;

};

// ============================================================================
// 超时辅助函数 — relay 层统一判定读/写侧是否因超时被 Cancel
// ============================================================================

inline bool ConsumeReadSideTimeout(AsyncStream& stream) {
    // 不使用 || 短路：两个标志位都需要被消费，避免残留
    bool read  = stream.ConsumeReadTimeout();
    bool idle  = stream.ConsumeIdleTimeout();
    return read || idle;
}

inline bool ConsumeWriteSideTimeout(AsyncStream& stream) {
    bool write = stream.ConsumeWriteTimeout();
    bool idle  = stream.ConsumeIdleTimeout();
    return write || idle;
}

// ============================================================================
// DialResult - 拨号结果
// ============================================================================
struct DialResult : ResultStatus {
    std::unique_ptr<AsyncStream> stream;  // 成功时有效

    [[nodiscard]] bool Ok() const noexcept {
        return ResultStatus::Ok() && stream != nullptr;
    }

    [[nodiscard]] static DialResult Success(std::unique_ptr<AsyncStream> s) {
        DialResult r;
        r.stream = std::move(s);
        return r;
    }

    [[nodiscard]] static DialResult Fail(ErrorCode code, const std::string& msg = "") {
        DialResult r;
        r.SetError(code, msg);
        return r;
    }
};

}  // namespace acpp
