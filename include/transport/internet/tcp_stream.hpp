#pragma once

#include "common/buf/multi_buffer.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/proxy_protocol.hpp"
#include <asio/cancellation_signal.hpp>

#include <chrono>
#include <memory>
#include <span>
#include <string_view>


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

    ~TcpStream() override;

    // AsyncStream 接口实现
    net::awaitable<std::size_t> AsyncRead(net::mutable_buffer buf) override;
    net::awaitable<std::size_t> AsyncWrite(net::const_buffer buf) override;

    // buf::MultiBuffer 优化路径
    // ReadMultiBuffer : 可读后才借用单个 8 KiB Buffer，不为空闲连接预借 payload
    // WriteBuffers   : scatter-write (WSASend / writev)，多 Buffer 合并为单次系统调用
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    bool EnableRawRead() noexcept override { return true; }
    net::awaitable<void>        WriteBuffers(std::span<const net::const_buffer> buffers) override;
    void ShutdownRead() override;
    void ShutdownWrite() override;
    void Close() override;
    void Cancel() noexcept override;
    int NativeHandle() const override;
    bool IsOpen() const override;

    // Return bytes read ahead by a completed handshake before unread socket data.
    // Only for this byte layer; a TLS owner must retain plaintext at its own layer.
    void PrependReadData(std::span<const uint8_t> data) override;

    // ── 超时控制 & 端点查询（仅 TcpStream 实现，非虚）─────────────────────────
    tcp::socket::executor_type GetExecutor() noexcept;
    // 仅等待底层 socket 可读，不接收数据、不申请 payload Buffer。
    // TLS 层用它将 8KB 申请延后到首个可读事件之后。
    net::awaitable<IoErrorCode> WaitReadable(net::cancellation_slot cancellation = {});
    tcp::endpoint LocalEndpoint() const;
    tcp::endpoint RemoteEndpoint() const;
    void SetIdleTimeout(std::chrono::seconds timeout);
    bool ConsumeIdleTimeout() noexcept;
    void SetReadTimeout(std::chrono::seconds timeout);
    void SetWriteTimeout(std::chrono::seconds timeout) override;
    bool ConsumeReadTimeout() noexcept;
    bool ConsumeWriteTimeout() noexcept override;
    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout);
    void ClearPhaseDeadline();
    bool ConsumePhaseDeadline() noexcept;
    void TouchActivity() noexcept;

    void SetAbortiveClose(bool enable = true) noexcept;
    void SetWriteCancellationDeferred() noexcept;
    [[nodiscard]] bool IsWriteCancellationDeferred() const noexcept;

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
    // Own/register the same nonblocking fd even while connect is pending.
    static net::awaitable<DialResult> ConnectSocket(
        tcp::socket socket, const tcp::endpoint& endpoint, std::chrono::seconds timeout);
    friend class TlsStream;
    void PrepareTlsIo();
    [[nodiscard]] bool CanRead() const noexcept;
    [[nodiscard]] bool CanWrite() const noexcept;
    [[nodiscard]] std::size_t ReadAvailable(
        net::mutable_buffer target, IoErrorCode& error) noexcept;
    // One nonblocking attempt; only WriteBuffers waits and owns write deadlines.
    [[nodiscard]] std::size_t WriteAvailable(
        std::span<const net::const_buffer> buffers, std::size_t offset,
        IoErrorCode& error) noexcept;

    net::awaitable<std::pair<IoErrorCode, std::size_t>> AsyncReceiveSome(
        net::mutable_buffer buffer,
        bool peek = false);

    [[nodiscard]] size_t ConsumePendingData(net::mutable_buffer target) noexcept;
    void ReleasePendingData() noexcept;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

