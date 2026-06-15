#pragma once

#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/proxy_protocol.hpp"

#include <chrono>
#include <memory>
#include <span>
#include <string_view>

namespace acpp {

// ============================================================================
// TcpStream - TCP 流实现
// ============================================================================
class TcpStream final : public AsyncStream {
public:
    // 从已接受的 socket 构造
    explicit TcpStream(tcp::socket socket);

    static void* operator new(std::size_t size);
    static void operator delete(void* p) noexcept;
    static void operator delete(void* p, std::size_t size) noexcept;

    // 禁止拷贝
    TcpStream(const TcpStream&) = delete;
    TcpStream& operator=(const TcpStream&) = delete;

    // 允许移动
    TcpStream(TcpStream&& other) noexcept;
    TcpStream& operator=(TcpStream&& other) noexcept;

    ~TcpStream() override;

    // AsyncStream 接口实现
    net::awaitable<std::size_t> AsyncRead(net::mutable_buffer buf) override;
    net::awaitable<std::size_t> AsyncWrite(net::const_buffer buf) override;

    // buf::MultiBuffer 优化路径
    // ReadMultiBuffer : async_read_some 直填 pool Buffer
    // WriteMultiBuffer: scatter-write (WSASend / writev)，多 Buffer 合并为单次系统调用
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<void>        WriteMultiBuffer(buf::MultiBuffer mb) override;
    void ShutdownRead() override;
    void ShutdownWrite() override;
    void Close() override;
    void Cancel() noexcept override;
    int NativeHandle() const override;
    bool IsOpen() const override;

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

    // 流标签（调试用，标识 inbound/outbound）。只存 1 字节枚举，
    // 避免 TcpStream 每连接常驻一个 std::string。
    void SetStreamLabel(std::string_view label) noexcept;
    [[nodiscard]] std::string_view StreamLabel() const noexcept;
    void SetAbortiveClose(bool enable = true) noexcept;

    net::awaitable<ProxyProtocolReadResult> ReadProxyProtocolHeader(
        std::chrono::seconds timeout);

    // 静态工厂方法：连接到已解析的端点
    [[nodiscard]]
    static net::awaitable<DialResult> Connect(
        net::io_context& io_context,
        const tcp::endpoint& endpoint,
        std::chrono::seconds timeout = std::chrono::seconds(10));

    // 静态工厂方法：绑定本地地址后连接
    [[nodiscard]]
    static net::awaitable<DialResult> ConnectWithBind(
        net::io_context& io_context,
        const net::ip::address& local_addr,
        const tcp::endpoint& remote_endpoint,
        std::chrono::seconds timeout = std::chrono::seconds(10));

protected:
    TcpStream* BaseTcpStream() override { return this; }
    const TcpStream* BaseTcpStream() const override { return this; }

private:
    net::awaitable<std::pair<IoErrorCode, std::size_t>> AsyncReceiveSome(
        net::mutable_buffer buffer,
        bool peek = false);
    void SetPendingData(std::span<const uint8_t> data);

    void TouchActivity();          // 记录 I/O 活动序号（极轻量，替代原 ResetIdleTimer）
    void ScheduleIdleCheck();      // 启动/续调 idle 检查定时器
    void CancelIdleTimer() noexcept;
    void ArmReadDeadline();
    void ArmWriteDeadline();
    void DisarmWriteDeadline() noexcept;
    void ScheduleWriteDeadlineCheck();
    void CancelReadDeadline() noexcept;
    void CancelWriteDeadline() noexcept;
    void CancelPhaseDeadline() noexcept;
    void ReleaseActiveCounter() noexcept;
    [[nodiscard]] size_t ConsumePendingData(net::mutable_buffer target) noexcept;
    void ReleasePendingData() noexcept;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace acpp
