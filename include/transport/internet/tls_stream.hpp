#pragma once

#include "transport/async_stream.hpp"
#include "transport/internet/tcp_stream.hpp"
#include <openssl/ssl.h>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>


namespace transport::internet {

struct RealityClientState;
struct RealityServerConnState;
struct RealityConfig;
struct TlsConfig;
class AutoSignContextRenewal;
struct DetachedTlsState {
    DetachedTcpState tcp;
    SSL* ssl = nullptr;
    bool is_server = true;
    std::vector<uint8_t> plaintext_prefix;

    DetachedTlsState() noexcept = default;
    ~DetachedTlsState() noexcept;
    DetachedTlsState(DetachedTlsState&& other) noexcept;
    DetachedTlsState& operator=(DetachedTlsState&& other) noexcept;
    DetachedTlsState(const DetachedTlsState&) = delete;
    DetachedTlsState& operator=(const DetachedTlsState&) = delete;
};
// ============================================================================
// OpenSSL 上下文管理（RAII）
// ============================================================================
class SslContext {
public:
    // 创建服务端上下文（从文件加载证书）
    static std::unique_ptr<SslContext> CreateServer(const TlsConfig& config);

    // 创建服务端上下文（启动时为配置域名生成固定自签证书）
    static std::unique_ptr<SslContext> CreateServerAutoSign(const TlsConfig& config);

    // 创建 QUIC 服务端上下文：证书来自 config.pem；版本按 config 的 min/max 收敛到
    // QUIC 强制的 TLS 1.3（max 低于 1.3 时失败）；ALPN 只在 |alpn|（非空）中按服务端
    // 偏好选择，无交集时以致命告警拒绝。QUIC 库回调由调用方在返回的 Native() 上安装。
    static std::unique_ptr<SslContext> CreateQuicServer(
        const TlsConfig& config, std::span<const std::string> alpn);

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

    SSL_CTX* Native() const noexcept { return native_owner_.get(); }
    // Pin a published immutable context until SSL_new takes its own reference.
    [[nodiscard]] std::shared_ptr<SSL_CTX> AcquireNative() const noexcept;

    // 禁止拷贝
    SslContext(const SslContext&) = delete;
    SslContext& operator=(const SslContext&) = delete;

private:
    explicit SslContext(bssl::UniquePtr<SSL_CTX> context) : native_owner_(std::move(context)) {}
    // Auto-sign: Native() stays null; handshakes pin the renewal's current snapshot.
    explicit SslContext(std::shared_ptr<AutoSignContextRenewal> renewal) noexcept
        : renewal_(std::move(renewal)) {}

    std::shared_ptr<SSL_CTX> native_owner_;
    std::shared_ptr<AutoSignContextRenewal> renewal_;
};

// ============================================================================
// TlsStream - TLS 加密流
// ============================================================================
class TlsStream final : public AsyncStream {
public:
    // 从底层 TCP 流和 SSL 上下文构造（TcpStream 是 final，编译器可去虚化）
    TlsStream(std::unique_ptr<TcpStream> inner, const SslContext& ctx, bool is_server);

    ~TlsStream() override;

    // Process startup only, before creating Workers. No lazy shared initialization.
    static void InitializeIo();

    // Pinned: handshake coroutines and OpenSSL callbacks borrow this stream.
    TlsStream(const TlsStream&) = delete;
    TlsStream& operator=(const TlsStream&) = delete;

    // 设置客户端验证身份；DNS 名称同时作为 SNI，IP 地址只做 IP SAN 校验。
    [[nodiscard]] bool SetServerIdentity(std::string_view identity);

    // 设置 REALITY 客户端认证（客户端调用）
    bool SetRealityClient(const RealityConfig& reality);
    [[nodiscard]] bool SetRealityServerPreverified(
        std::unique_ptr<RealityServerConnState> state) noexcept;

    // 执行 TLS 握手
    net::awaitable<bool> Handshake();

    // 获取协商的 ALPN 协议
    std::string_view NegotiatedAlpn() const;

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

    // Return decrypted handshake read-ahead before OpenSSL's unread plaintext.
    // Never forwards these bytes to the TCP ciphertext layer.
    void PrependReadData(std::span<const uint8_t> data) override;
    void PrependReadMultiBuffer(buf::MultiBuffer&& mb) override;
    // Vision cmd2 read-direction cutover; retain already-decrypted bytes,
    // then read the raw TCP stream without touching the independent writer.
    [[nodiscard]] bool EnableRawRead() noexcept override;

    [[nodiscard]] std::optional<DetachedTlsState> DetachForHandoff(
        std::span<const uint8_t> plaintext_prefix = {});
    [[nodiscard]] static std::unique_ptr<TlsStream> RestoreFromHandoff(
        net::io_context& io_context, DetachedTlsState state);
protected:
    TcpStream* BaseTcpStream() override;
    const TcpStream* BaseTcpStream() const override;

private:
    struct Impl;
    TlsStream(std::unique_ptr<TcpStream> inner, SSL* existing_ssl, bool is_server);

    net::awaitable<std::size_t> AsyncReadSlow(net::mutable_buffer buf);
    net::awaitable<buf::MultiBuffer> ReadMultiBufferSlow();
    net::awaitable<void> WriteBuffersSlow(std::span<const net::const_buffer> buffers);
    SSL* NativeSsl() noexcept;
    const SSL* NativeSsl() const noexcept;

    std::unique_ptr<Impl> impl_;
    bool is_server_ = false;
    bool handshake_done_ = false;
    bool shutdown_initiated_ = false;  // 防止多次 SSL_shutdown
    std::unique_ptr<RealityClientState> reality_client_state_;
};

// ============================================================================
// 工厂函数
// ============================================================================

// 包装现有 TCP 流为 TLS 服务端
[[nodiscard]]
net::awaitable<std::unique_ptr<TlsStream>> WrapTlsServer(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx);

// 包装现有 TCP 流为 TLS 客户端；ALPN 已在 SslContext 加载期配置
[[nodiscard]]
net::awaitable<std::unique_ptr<TlsStream>> WrapTlsClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    std::string_view server_name = {});

// 包装现有 TCP 流为 REALITY 客户端
[[nodiscard]]
net::awaitable<std::unique_ptr<TlsStream>> WrapRealityClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    const RealityConfig& reality,
    std::string_view server_name = {});

}  // namespace transport::internet

