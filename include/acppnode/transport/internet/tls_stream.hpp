#pragma once

#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/tls_config.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include <openssl/ssl.h>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

struct RealityConfig;

// ============================================================================
// OpenSSL 上下文管理（RAII）
// ============================================================================
class SslContext {
public:
    // 创建服务端上下文（从文件加载证书）
    static std::unique_ptr<SslContext> CreateServer(const TlsConfig& config);

    // 创建服务端上下文（自签名，根据 SNI 动态生成证书）
    static std::unique_ptr<SslContext> CreateServerAutoSign(const TlsConfig& config);

    // 创建 REALITY 服务端上下文
    static std::unique_ptr<SslContext> CreateServerReality(
        const RealityConfig& reality,
        const TlsConfig& tls_config);

    // 创建 REALITY 客户端上下文
    static std::unique_ptr<SslContext> CreateClientReality(
        const RealityConfig& reality,
        const TlsConfig& tls_config);

    // 创建客户端上下文
    static std::unique_ptr<SslContext> CreateClient(const TlsConfig& config);

    ~SslContext();

    SSL_CTX* Native() { return ctx_; }
    const SSL_CTX* Native() const { return ctx_; }
    const std::vector<unsigned char>& ServerAlpnWire() const noexcept {
        return server_alpn_wire_;
    }

    // 禁止拷贝
    SslContext(const SslContext&) = delete;
    SslContext& operator=(const SslContext&) = delete;

private:
    explicit SslContext(SSL_CTX* ctx, std::shared_ptr<void> app_state = {})
        : ctx_(ctx)
        , app_state_(std::move(app_state)) {}
    [[nodiscard]] bool ConfigureServerAlpn(
        const std::vector<std::string>& protocols);

    SSL_CTX* ctx_ = nullptr;
    std::shared_ptr<void> app_state_;
    std::vector<unsigned char> server_alpn_wire_;
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

    // 设置客户端验证身份；DNS 名称同时作为 SNI，IP 地址只做 IP SAN 校验。
    [[nodiscard]] bool SetServerIdentity(std::string_view identity);

    // 设置 ALPN（客户端调用）
    [[nodiscard]] bool SetAlpn(const std::vector<std::string>& protocols);

    // 设置 REALITY 客户端认证（客户端调用）
    bool SetRealityClient(const RealityConfig& reality);

    // 执行 TLS 握手
    net::awaitable<bool> Handshake();

    // 获取协商的 ALPN 协议
    std::string NegotiatedAlpn() const;

    // 获取 SNI（服务端接收到的）
    std::string ReceivedSni() const;
    std::string NegotiatedVersion() const;
    std::string NegotiatedFingerprint() const;

    // AsyncStream 接口实现
    net::awaitable<std::size_t> AsyncRead(net::mutable_buffer buf) override;
    net::awaitable<std::size_t> AsyncWrite(net::const_buffer buf) override;
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override;
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override;
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override;
    void ShutdownRead() override;
    void ShutdownWrite() override;
    net::awaitable<void> AsyncShutdownWrite() override;
    void Close() override;
    void CloseAbortive() override;
    void Cancel() noexcept override;
    int NativeHandle() const override;
    bool IsOpen() const override;

protected:
    TcpStream* BaseTcpStream() override;
    const TcpStream* BaseTcpStream() const override;

private:
    struct Impl;

    SSL* NativeSsl() noexcept;
    const SSL* NativeSsl() const noexcept;

    std::unique_ptr<Impl> impl_;
    bool is_server_ = false;
    bool handshake_done_ = false;
    bool shutdown_initiated_ = false;  // 防止多次 SSL_shutdown
    std::shared_ptr<void> app_state_;
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

// 包装现有 TCP 流为 REALITY 客户端
[[nodiscard]]
net::awaitable<std::unique_ptr<TlsStream>> WrapRealityClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    const RealityConfig& reality,
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
