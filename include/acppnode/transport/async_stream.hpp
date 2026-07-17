#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/transport/link.hpp"

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

namespace acpp {

class TcpStream;  // 前置声明
class BaseWsStream;  // 允许 WS 包装链透传底层 TCP 能力

class PhaseDeadlineHandle {
public:
    PhaseDeadlineHandle() = default;

    PhaseDeadlineHandle(
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
class AsyncStream : public transport::MultiBufferReader, public transport::MultiBufferWriter {
public:
    // Stream 对象是每连接常驻热路径状态。所有 AsyncStream 派生类的
    // std::make_unique 分配都会走 system allocator；ThreadScope 只保留为
    // 热路径作用域标记，不再切换进程 allocator。
    [[nodiscard]] static void* operator new(std::size_t size);
    [[nodiscard]] static void* operator new(std::size_t size, std::align_val_t alignment);
    static void operator delete(void* ptr) noexcept;
    static void operator delete(void* ptr, std::size_t size) noexcept;
    static void operator delete(void* ptr, std::align_val_t alignment) noexcept;
    static void operator delete(void* ptr, std::size_t size, std::align_val_t alignment) noexcept;

    virtual ~AsyncStream() noexcept = default;

    // ========================================================================
    // 数据传输
    // ========================================================================

    /**
     * 异步读取数据
     *
     * @param buf 目标缓冲区
     * @return 读取字节数；0 表示 EOF（对端关闭写端）
     * @throws IoSystemError 网络错误
     */
    virtual net::awaitable<std::size_t> AsyncRead(net::mutable_buffer buf) = 0;

    /**
     * 异步写入数据
     *
     * @param buf 源缓冲区
     * @return 写入字节数
     * @throws IoSystemError 网络错误
     */
    virtual net::awaitable<std::size_t> AsyncWrite(net::const_buffer buf) = 0;

    // ========================================================================
    // buf::MultiBuffer 流式接口（对应 Xray buf.Reader / buf.Writer）
    //
    // 默认实现基于 AsyncRead/AsyncWrite，子类可 override 实现更高效的路径：
    //   - TcpStream: scatter-write (writev)
    //   - VMessStream: 解密直写 pool Buffer，省去一次 memcpy
    //
    // 所有权规则：
    //   ReadMultiBuffer()  - 返回的 buf::MultiBuffer 由调用方负责 Free
    //   WriteMultiBuffer() - 接管 mb 所有权，完成后自动 Free
    // ========================================================================

    /**
     * 批量读取数据到 buf::MultiBuffer
     *
     * @return buf::MultiBuffer（无有效数据 = EOF）；返回值按 RAII 自动归还 Buffer
     * @throws IoSystemError 网络错误
     */
    virtual net::awaitable<buf::MultiBuffer> ReadMultiBuffer();

    /**
     * 批量写入 buf::MultiBuffer（接管所有权，写完后自动 Free）
     *
     * @throws IoSystemError 网络错误
     */
    virtual net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb);

    /**
     * 批量写入非 owning buffer 序列。
     *
     * 调用方保证 buffers 指向的数据在 co_await 返回前有效。默认实现逐段
     * AsyncWrite；TcpStream/TlsStream/WS 可 override 为 scatter 或协议内聚写，
     * 用于小协议头 + 现有 payload 的零拷贝写出。
     */
    virtual net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers);

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
    virtual net::awaitable<void> AsyncShutdownWrite() {
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

    // ========================================================================
    // Tcp 能力透传
    // ========================================================================

    void SetIdleTimeout(std::chrono::seconds timeout);
    void SetReadTimeout(std::chrono::seconds timeout);
    void SetWriteTimeout(std::chrono::seconds timeout);
    void SetStreamLabel(std::string_view label) noexcept;
    void SetAbortiveClose(bool enable = true) noexcept;

    [[nodiscard]] bool ConsumeIdleTimeout() noexcept;
    [[nodiscard]] bool ConsumeReadTimeout() noexcept;
    [[nodiscard]] bool ConsumeWriteTimeout() noexcept;

    [[nodiscard]] PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout);
    void ClearPhaseDeadline();
    [[nodiscard]] bool ConsumePhaseDeadline() noexcept;

    [[nodiscard]] std::optional<tcp::endpoint> LocalEndpoint() const;
    [[nodiscard]] std::optional<tcp::endpoint> RemoteEndpoint() const;

protected:
    // 仅 transport/internet 包装链和 AsyncStream 自身能力方法使用。
    // 不能作为 app/proxy/relay 公开逃逸到 TcpStream 的入口。
    friend class BaseWsStream;
    static TcpStream* BaseTcpStreamOf(AsyncStream& stream) {
        return stream.BaseTcpStream();
    }
    static const TcpStream* BaseTcpStreamOf(const AsyncStream& stream) {
        return stream.BaseTcpStream();
    }
    virtual TcpStream* BaseTcpStream() { return nullptr; }
    virtual const TcpStream* BaseTcpStream() const { return nullptr; }

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
    // The endpoint address used by the most recent transport dial attempt.
    // This is transport metadata only; an outbound decides whether the
    // endpoint represents the final destination or a proxy next hop.
    std::optional<net::ip::address> attempted_remote_addr;

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
