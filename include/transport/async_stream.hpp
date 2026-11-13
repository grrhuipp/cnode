#pragma once

#include "common/asio_types.hpp"
#include "common/error.hpp"
#include "transport/link.hpp"
#include "transport/timeout_scheduler.hpp"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>


namespace transport {

class AsyncStream;

// Borrowed observation of one owner's absolute phase deadline. The owner must
// outlive the handle; replacing or clearing a deadline invalidates older views.
class PhaseDeadlineToken {
public:
    PhaseDeadlineToken() = default;

    PhaseDeadlineToken(
        const uint8_t* flags,
        uint8_t expired_mask,
        const uint32_t* generation,
        uint32_t captured_generation) noexcept
        : flags_(flags)
        , expired_mask_(expired_mask)
        , generation_(generation)
        , captured_generation_(captured_generation) {}

    [[nodiscard]] bool Expired() const noexcept {
        return flags_ &&
               generation_ &&
               *generation_ == captured_generation_ &&
               ((*flags_ & expired_mask_) != 0);
    }

    explicit operator bool() const noexcept { return flags_ && generation_; }

private:
    const uint8_t* flags_ = nullptr;
    uint8_t expired_mask_ = 0;
    const uint32_t* generation_ = nullptr;
    uint32_t captured_generation_ = 0;
};

// One logical stream's phase deadline, owned inline by that stream on its
// Worker scheduler. The stream must outlive this member; no private timer or
// background task is owned here.
class StreamPhaseDeadline final : private TimeoutEvent {
public:
    StreamPhaseDeadline(net::io_context& io_context, AsyncStream& owner);
    ~StreamPhaseDeadline() noexcept;
    StreamPhaseDeadline(const StreamPhaseDeadline&) = delete;
    StreamPhaseDeadline& operator=(const StreamPhaseDeadline&) = delete;

    [[nodiscard]] PhaseDeadlineToken Start(std::chrono::seconds timeout);
    // Clear invalidates borrowed handles; Consume only acknowledges expiry.
    void Clear() noexcept;
    [[nodiscard]] bool Consume() noexcept;

private:
    void OnTimeout() noexcept override;

    AsyncStream& owner_;
    uint32_t generation_ = 0;
    uint8_t expired_ = 0;
};

class TcpStream;
// ============================================================================
// AsyncStream - 异步流抽象接口
//
// 生命周期规范：
// ┌─────────────────────────────────────────────────────────────────────────┐
// │ 1. 所有操作（ShutdownRead/ShutdownWrite/Cancel/Close）必须幂等         │
// │ 2. Close() 后读取返回 EOF，写入失败                                     │
// │ 3. Cancel() 仅取消挂起操作，不改变连接状态                               │
// │ 4. TLS 流的 AsyncShutdownWrite() 必须发送 close_notify                  │
// └─────────────────────────────────────────────────────────────────────────┘
// ============================================================================
class AsyncStream : public transport::MultiBufferReader,
                    public transport::MultiBufferWriter {
public:
    virtual ~AsyncStream() noexcept = default;

    // Byte-stream EOF half-closes the peer writer; full-close transports
    // explicitly override this contract.
    transport::EofAction ReadEofAction() const noexcept override {
        return transport::EofAction::ShutdownPeerWrite;
    }

    // ========================================================================
    // 数据传输
    // ========================================================================

    // 返回 0 表示 EOF（对端关闭写端）；网络错误或取消抛 IoSystemError，取消不能伪装成 EOF。
    virtual net::awaitable<std::size_t> AsyncRead(net::mutable_buffer buf) = 0;

    // 失败抛 IoSystemError。
    virtual net::awaitable<std::size_t> AsyncWrite(net::const_buffer buf) = 0;

    // ========================================================================
    // common::MultiBuffer 流式接口（对应 Xray buf.Reader / buf.Writer）
    //
    // 读路径由每个具体 stream 实现，以便先等待可读数据，再申请唯一的 8KB
    // payload Buffer（VMessStream 解密直写 pool Buffer，省去一次 memcpy）；
    // WriteMultiBuffer 默认将 MultiBuffer 展开为 const_buffer 序列转发至
    // WriteBuffers（TcpStream scatter-write / TlsStream 聚帧）。MultiBuffer 按 RAII
    // 持有 Buffer，读出的由调用方持有，写入的由流接管。
    // ========================================================================

    // 空 MultiBuffer 表示 EOF；网络错误或取消抛 IoSystemError，内存不足抛 std::bad_alloc。
    virtual net::awaitable<common::MultiBuffer> ReadMultiBuffer() override = 0;

    // 接管 mb，写完后归还 Buffer；失败抛 IoSystemError。
    virtual net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override;

    /**
     * 批量写入非 owning buffer 序列。
     *
     * 调用方保证 buffers 指向的数据在 co_await 返回前有效。默认实现逐段
     * AsyncWrite；TcpStream/TlsStream/WS 可 override 为 scatter 或协议内聚写，
     * 用于小协议头 + 现有 payload 的零拷贝写出。
     */
    virtual net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;

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
    virtual net::awaitable<void> AsyncShutdownWrite() override {
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

    // Observe cancellation while higher layers wait outside socket I/O.
    transport::CancellationSource& Cancellation() noexcept override;

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

    /**
     * 异常/淘汰路径关闭连接（幂等）
     *
     * 用于会话整体失败、连接池回收、demux 物理连接退场等不需要协议级
     * EOF 的路径。默认设置 TCP abortive close 后调用 Close()；TLS 包装层
     * 必须跳过 close_notify。
     */
    virtual void CloseAbortive();

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
     * 判断是否打开
     *
     * @return true 如果连接仍然有效
     */
    virtual bool IsOpen() const = 0;
    virtual void PrependReadBytes(std::span<const uint8_t> data);
    virtual void PrependReadMultiBuffer(common::MultiBuffer&& mb);

    // ========================================================================
    // Tcp 能力透传
    // ========================================================================

    void SetIdleTimeout(std::chrono::seconds timeout);
    void SetReadTimeout(std::chrono::seconds timeout);
    virtual void SetWriteTimeout(std::chrono::seconds timeout);
    void SetAbortiveClose(bool enable = true) noexcept;
    // Shared byte transports can finish a started write when a logical caller
    // is cancelled. Explicit socket cancellation, closure and timeouts still act.
    [[nodiscard]] bool DeferWriteCancellation() noexcept;

    [[nodiscard]] bool ConsumeIdleTimeout() noexcept;
    [[nodiscard]] bool ConsumeReadTimeout() noexcept;
    [[nodiscard]] virtual bool ConsumeWriteTimeout() noexcept;

    // Logical streams select their inline deadline owner below; ordinary byte
    // streams continue to use the physical connection's aggregate deadlines.
    [[nodiscard]] PhaseDeadlineToken StartPhaseDeadline(std::chrono::seconds timeout);
    void ClearPhaseDeadline();
    [[nodiscard]] bool ConsumePhaseDeadline() noexcept;

    [[nodiscard]] std::optional<tcp::endpoint> LocalEndpoint() const;
    [[nodiscard]] std::optional<tcp::endpoint> RemoteEndpoint() const;
    [[nodiscard]] TcpStream* AsDirectTcpStream() noexcept;

protected:
    // Override for a logical stream, including split transports. Its Cancel()
    // must cancel only that logical stream, never the shared physical stream.
    virtual StreamPhaseDeadline* LogicalPhaseDeadline() noexcept { return nullptr; }

    void NotifyCancellation(common::ErrorCode reason = common::ErrorCode::CANCELLED) noexcept {
        Cancellation().CancelPending(reason);
    }
    void NotifyClosed(common::ErrorCode reason = common::ErrorCode::CANCELLED) noexcept {
        Cancellation().Stop(reason);
    }
    // 仅 transport/internet 包装链和 AsyncStream 自身能力方法使用。
    // 不能作为 app/proxy/relay 公开逃逸到 TcpStream 的入口。
    static TcpStream* BaseTcpStreamOf(AsyncStream& stream) {
        return stream.BaseTcpStream();
    }
    static const TcpStream* BaseTcpStreamOf(const AsyncStream& stream) {
        return stream.BaseTcpStream();
    }
    virtual TcpStream* BaseTcpStream() { return nullptr; }
    virtual const TcpStream* BaseTcpStream() const { return nullptr; }

private:
    transport::CancellationSource cancellation_;
};

// ============================================================================
// 超时辅助函数 — relay 层统一判定读/写侧是否因超时被 Cancel
// ============================================================================

// Stream 为 AsyncStream 或任何暴露同名 Consume*Timeout 的出站端点/UDP 请求控制面。
template <typename Stream>
bool ConsumeReadSideTimeout(Stream& stream) {
    // 不使用 || 短路：两个标志位都需要被消费，避免残留
    bool read  = stream.ConsumeReadTimeout();
    bool idle  = stream.ConsumeIdleTimeout();
    return read || idle;
}

template <typename Stream>
bool ConsumeWriteSideTimeout(Stream& stream) {
    bool write = stream.ConsumeWriteTimeout();
    bool idle  = stream.ConsumeIdleTimeout();
    return write || idle;
}

// ============================================================================
// DialResult - 拨号结果
// ============================================================================
struct DialResult : common::ResultStatus {
    std::unique_ptr<AsyncStream> stream;  // 成功时有效

    [[nodiscard]] bool Ok() const noexcept {
        return common::ResultStatus::Ok() && stream != nullptr;
    }

    [[nodiscard]] static DialResult Success(std::unique_ptr<AsyncStream> s) {
        DialResult r;
        r.stream = std::move(s);
        return r;
    }

    [[nodiscard]] static DialResult Fail(
        common::ErrorCode code,
        std::string_view msg = "") {
        DialResult r;
        r.SetError(code, msg);
        return r;
    }
};

}  // namespace transport

