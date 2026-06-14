#pragma once

#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/tls_config.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <array>
#include <memory>
#include <string>
#include <vector>

namespace acpp {

// ============================================================================
// OpenSSL 上下文管理（RAII）
// ============================================================================
class SslContext {
public:
    // 创建服务端上下文（从文件加载证书）
    static std::unique_ptr<SslContext> CreateServer(const TlsConfig& config);

    // 创建服务端上下文（自签名，根据 SNI 动态生成证书）
    static std::unique_ptr<SslContext> CreateServerAutoSign(const TlsConfig& config);

    // 创建客户端上下文
    static std::unique_ptr<SslContext> CreateClient(const TlsConfig& config);

    ~SslContext();

    SSL_CTX* Native() { return ctx_; }
    const SSL_CTX* Native() const { return ctx_; }

    // 禁止拷贝
    SslContext(const SslContext&) = delete;
    SslContext& operator=(const SslContext&) = delete;

private:
    explicit SslContext(SSL_CTX* ctx) : ctx_(ctx) {}
    SSL_CTX* ctx_ = nullptr;
};

// ============================================================================
// TlsStream - TLS 加密流
// ============================================================================
class TlsStream final : public AsyncStream {
public:
    // 从底层 TCP 流和 SSL 上下文构造（TcpStream 是 final，编译器可去虚化）
    TlsStream(std::unique_ptr<TcpStream> inner, SSL_CTX* ctx, bool is_server);

    ~TlsStream() override;

    // 禁止拷贝
    TlsStream(const TlsStream&) = delete;
    TlsStream& operator=(const TlsStream&) = delete;

    // 允许移动
    TlsStream(TlsStream&& other) noexcept;
    TlsStream& operator=(TlsStream&& other) noexcept;

    // 设置 SNI（客户端调用）
    void SetServerName(const std::string& name);

    // 设置 ALPN（客户端调用）
    void SetAlpn(const std::vector<std::string>& protocols);

    // 执行 TLS 握手
    net::awaitable<bool> Handshake();

    // 获取协商的 ALPN 协议
    std::string NegotiatedAlpn() const;

    // 获取 SNI（服务端接收到的）
    std::string ReceivedSni() const;

    // AsyncStream 接口实现
    net::awaitable<std::size_t> AsyncRead(net::mutable_buffer buf) override;
    net::awaitable<std::size_t> AsyncWrite(net::const_buffer buf) override;
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    void ShutdownRead() override;
    void ShutdownWrite() override;
    net::awaitable<void> AsyncShutdownWrite() override;
    void Close() override;
    void Cancel() noexcept override;
    int NativeHandle() const override;
    bool IsOpen() const override;

protected:
    TcpStream* BaseTcpStream() override { return &inner_; }
    const TcpStream* BaseTcpStream() const override { return &inner_; }

private:
    // BIO 回调（用于异步 I/O）
    static int BioRead(BIO* bio, char* buf, int len);
    static int BioWrite(BIO* bio, const char* buf, int len);
    static long BioCtrl(BIO* bio, int cmd, long num, void* ptr);
    static int BioCreate(BIO* bio);
    static int BioDestroy(BIO* bio);

    // 刷新待发送数据
    net::awaitable<bool> FlushWriteBio();

    TcpStream inner_;
    SSL* ssl_ = nullptr;
    BIO* read_bio_ = nullptr;   // 用于接收数据
    BIO* write_bio_ = nullptr;  // 用于发送数据
    bool is_server_ = false;
    bool handshake_done_ = false;
    bool shutdown_initiated_ = false;  // 防止多次 SSL_shutdown

    // TLS 底层 I/O pump 的临时缓冲大小。缓冲本体放在执行中的 awaitable 内，
    // 避免每个 TLS stream 对象常驻一块 scratch。
    static constexpr size_t kTlsIoBufferSize = 4096;
};

// ============================================================================
// 工厂函数
// ============================================================================

// 包装现有 TCP 流为 TLS 服务端
[[nodiscard]]
net::awaitable<std::unique_ptr<TlsStream>> WrapTlsServer(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx);

// 包装现有 TCP 流为 TLS 客户端
[[nodiscard]]
net::awaitable<std::unique_ptr<TlsStream>> WrapTlsClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    const std::string& server_name = "",
    const std::vector<std::string>& alpn = {});

// 连接到 TLS 服务器
[[nodiscard]]
net::awaitable<DialResult> ConnectTls(
    net::io_context& io_context,
    const tcp::endpoint& endpoint,
    SslContext& ctx,
    const std::string& server_name = "",
    const std::vector<std::string>& alpn = {},
    std::chrono::seconds timeout = std::chrono::seconds(10));

}  // namespace acpp
