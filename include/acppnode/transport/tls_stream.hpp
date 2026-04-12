#pragma once

#include "acppnode/transport/async_stream.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <array>
#include <memory>
#include <string>
#include <vector>

namespace acpp {

// ============================================================================
// TLS 配置
// ============================================================================
struct TlsConfig {
    // 服务端配置
    std::string cert_file;              // 证书文件路径
    std::string key_file;               // 私钥文件路径
    std::string ca_file;                // CA 证书（可选，用于客户端验证）
    
    // 客户端配置
    std::string server_name;            // 客户端 SNI / 自签证书默认域名
    bool allow_insecure = false;        // 是否允许不验证证书
    std::vector<std::string> alpn;      // ALPN 协议列表
    
    // 通用配置
    std::string min_version = "1.2";    // 最低 TLS 版本
    std::string max_version = "1.3";    // 最高 TLS 版本
    std::vector<std::string> cipher_suites;  // 密码套件
    
    bool IsServer() const { return !cert_file.empty() && !key_file.empty(); }
};

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
    cobalt::task<bool> Handshake();
    
    // 获取协商的 ALPN 协议
    std::string NegotiatedAlpn() const;
    
    // 获取 SNI（服务端接收到的）
    std::string ReceivedSni() const;
    
    // AsyncStream 接口实现
    cobalt::task<std::size_t> AsyncRead(net::mutable_buffer buf) override;
    cobalt::task<std::size_t> AsyncWrite(net::const_buffer buf) override;
    void ShutdownRead() override;
    void ShutdownWrite() override;
    cobalt::task<void> AsyncShutdownWrite() override;
    void Close() override;
    void Cancel() noexcept override;
    int NativeHandle() const override;
    net::any_io_executor GetExecutor() const override;
    bool IsOpen() const override;

    TcpStream* GetBaseTcpStream() override { return inner_.get(); }
    const TcpStream* GetBaseTcpStream() const override { return inner_.get(); }

    // 获取底层 TCP 流
    TcpStream& Inner() { return *inner_; }
    const TcpStream& Inner() const { return *inner_; }

private:
    // BIO 回调（用于异步 I/O）
    static int BioRead(BIO* bio, char* buf, int len);
    static int BioWrite(BIO* bio, const char* buf, int len);
    static long BioCtrl(BIO* bio, int cmd, long num, void* ptr);
    static int BioCreate(BIO* bio);
    static int BioDestroy(BIO* bio);
    
    // 刷新待发送数据
    cobalt::task<bool> FlushWriteBio();
    
    std::unique_ptr<TcpStream> inner_;
    SSL* ssl_ = nullptr;
    BIO* read_bio_ = nullptr;   // 用于接收数据
    BIO* write_bio_ = nullptr;  // 用于发送数据
    bool is_server_ = false;
    bool handshake_done_ = false;
    bool shutdown_initiated_ = false;  // 防止多次 SSL_shutdown
    
    // TLS record 可以被分段读取，这里保留较小的固定 I/O 缓冲即可。
    static constexpr size_t kTlsIoBufferSize = 4096;
    std::array<uint8_t, kTlsIoBufferSize> read_buffer_{};
};

// ============================================================================
// 工厂函数
// ============================================================================

// 包装现有 TCP 流为 TLS 服务端
[[nodiscard]]
cobalt::task<std::unique_ptr<TlsStream>> WrapTlsServer(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx);

// 包装现有 TCP 流为 TLS 客户端
[[nodiscard]]
cobalt::task<std::unique_ptr<TlsStream>> WrapTlsClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    const std::string& server_name = "",
    const std::vector<std::string>& alpn = {});

// 连接到 TLS 服务器
[[nodiscard]]
cobalt::task<DialResult> ConnectTls(
    net::any_io_executor executor,
    const tcp::endpoint& endpoint,
    SslContext& ctx,
    const std::string& server_name = "",
    const std::vector<std::string>& alpn = {},
    std::chrono::seconds timeout = std::chrono::seconds(10));

}  // namespace acpp
