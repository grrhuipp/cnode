#include "acppnode/transport/tls_stream.hpp"
#include "acppnode/transport/tcp_stream.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <mutex>
#include <unordered_map>

// AWS-LC (BoringSSL) 移除了 NPN 支持，但 SSL_select_next_proto 仍可用于 ALPN 回调
#ifndef OPENSSL_NPN_NEGOTIATED
#define OPENSSL_NPN_NEGOTIATED  1
#define OPENSSL_NPN_NO_OVERLAP  2
#endif
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

namespace acpp {

// ============================================================================
// SslContext 实现
// ============================================================================

std::unique_ptr<SslContext> SslContext::CreateServer(const TlsConfig& config) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        LOG_ERROR("Failed to create SSL server context");
        return nullptr;
    }
    
    // 设置 TLS 版本
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    // 加载证书
    if (SSL_CTX_use_certificate_chain_file(ctx, config.cert_file.c_str()) <= 0) {
        LOG_ERROR("Failed to load certificate: {}", config.cert_file);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    
    // 加载私钥
    if (SSL_CTX_use_PrivateKey_file(ctx, config.key_file.c_str(), SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("Failed to load private key: {}", config.key_file);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    
    // 验证私钥与证书匹配
    if (!SSL_CTX_check_private_key(ctx)) {
        LOG_ERROR("Private key does not match certificate");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    
    // 设置 ALPN 回调（用于 HTTP/2、Trojan 等）
    SSL_CTX_set_alpn_select_cb(ctx, [](SSL* ssl, const unsigned char** out,
                                        unsigned char* outlen,
                                        const unsigned char* in,
                                        unsigned int inlen, void* arg) -> int {
        // 优先选择 h2，否则 http/1.1
        static const unsigned char h2[] = "\x02h2";
        static const unsigned char http11[] = "\x08http/1.1";
        
        if (SSL_select_next_proto((unsigned char**)out, outlen,
                                   in, inlen, h2, sizeof(h2) - 1) == OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_OK;
        }
        if (SSL_select_next_proto((unsigned char**)out, outlen,
                                   in, inlen, http11, sizeof(http11) - 1) == OPENSSL_NPN_NEGOTIATED) {
            return SSL_TLSEXT_ERR_OK;
        }
        return SSL_TLSEXT_ERR_NOACK;
    }, nullptr);
    
    return std::unique_ptr<SslContext>(new SslContext(ctx));
}

// ============================================================================
// 自动签名：根据 SNI 动态生成自签证书
// ============================================================================

namespace {

[[noreturn]] void ThrowTlsWriteError(const char* what) {
    throw boost::system::system_error(boost::asio::error::connection_reset, what);
}

[[noreturn]] void ThrowTlsReadError(const char* what) {
    throw boost::system::system_error(boost::asio::error::connection_reset, what);
}

bool IsBenignServerHandshakeError(unsigned long err_code) {
    if (err_code == 0) return false;
    const auto reason = ERR_GET_REASON(err_code);
#ifdef SSL_R_WRONG_VERSION_NUMBER
    if (reason == SSL_R_WRONG_VERSION_NUMBER) return true;
#endif
#ifdef SSL_R_HTTP_REQUEST
    if (reason == SSL_R_HTTP_REQUEST) return true;
#endif
    return false;
}

struct AutoSignState {
    EVP_PKEY* pkey = nullptr;
    std::mutex mu;
    std::unordered_map<std::string, X509*> cert_cache;

    ~AutoSignState() {
        for (auto& [_, cert] : cert_cache) X509_free(cert);
        if (pkey) EVP_PKEY_free(pkey);
    }

    // 为指定域名生成或获取缓存的证书
    X509* GetOrCreate(const std::string& cn) {
        std::lock_guard lock(mu);
        if (auto it = cert_cache.find(cn); it != cert_cache.end())
            return it->second;

        X509* x509 = X509_new();
        if (!x509) return nullptr;

        X509_set_version(x509, 2);

        // 随机序列号
        static std::atomic<long> serial{1};
        ASN1_INTEGER_set(X509_get_serialNumber(x509),
                         serial.fetch_add(1, std::memory_order_relaxed));

        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 365 * 24 * 60 * 60);

        X509_set_pubkey(x509, pkey);

        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
        X509_set_issuer_name(x509, name);

        // SAN 扩展：泛域名 + 裸域名（如 *.example.com, example.com）
        X509V3_CTX v3ctx;
        X509V3_set_ctx_nodb(&v3ctx);
        X509V3_set_ctx(&v3ctx, x509, x509, nullptr, nullptr, 0);
        std::string san_val = "DNS:" + cn;
        // 泛域名时额外加裸域名
        if (cn.size() > 2 && cn[0] == '*' && cn[1] == '.') {
            san_val += ",DNS:" + cn.substr(2);
        }
        X509_EXTENSION* san_ext = X509V3_EXT_nconf_nid(
            nullptr, &v3ctx, NID_subject_alt_name,
            const_cast<char*>(san_val.c_str()));
        if (san_ext) {
            X509_add_ext(x509, san_ext, -1);
            X509_EXTENSION_free(san_ext);
        }

        if (!X509_sign(x509, pkey, EVP_sha256())) {
            X509_free(x509);
            return nullptr;
        }

        cert_cache[cn] = x509;
        LOG_DEBUG("自签证书已生成: {}", cn);
        return x509;
    }
};

AutoSignState& GetAutoSignState() {
    static AutoSignState state;
    return state;
}

// 从 SNI 提取泛域名：www.example.com → *.example.com
// 裸域名 example.com → *.example.com
// 单标签 localhost → localhost（不做通配）
std::string ToWildcard(std::string_view sni) {
    auto dot = sni.find('.');
    if (dot == std::string_view::npos) return std::string(sni);  // localhost 等
    // *.example.com
    return "*" + std::string(sni.substr(dot));
}

std::string ResolveAutoSignDefaultName(const TlsConfig& config) {
    if (config.server_name.empty()) {
        return "localhost";
    }
    return ToWildcard(config.server_name);
}

// SNI 回调：根据客户端请求的域名切换泛域名证书
int AutoSignSniCallback(SSL* ssl, int* /*ad*/, void* /*arg*/) {
    const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    std::string wildcard = sni ? ToWildcard(sni) : "localhost";

    auto& state = GetAutoSignState();
    X509* cert = state.GetOrCreate(wildcard);
    if (!cert) return SSL_TLSEXT_ERR_ALERT_FATAL;

    SSL_use_certificate(ssl, cert);
    SSL_use_PrivateKey(ssl, state.pkey);
    return SSL_TLSEXT_ERR_OK;
}

}  // namespace

std::unique_ptr<SslContext> SslContext::CreateServerAutoSign(const TlsConfig& config) {
    auto& state = GetAutoSignState();

    // 只在首次调用时生成 EC P-256 密钥
    if (!state.pkey) {
        EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        EVP_PKEY* pkey = nullptr;
        if (!pctx ||
            EVP_PKEY_keygen_init(pctx) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
            EVP_PKEY_keygen(pctx, &pkey) <= 0) {
            if (pctx) EVP_PKEY_CTX_free(pctx);
            LOG_ERROR("EC P-256 密钥生成失败");
            return nullptr;
        }
        EVP_PKEY_CTX_free(pctx);
        state.pkey = pkey;
    }

    // 默认证书优先使用配置的 server_name，避免无 SNI 时退回 localhost。
    const std::string default_name = ResolveAutoSignDefaultName(config);
    X509* default_cert = state.GetOrCreate(default_name);
    if (!default_cert) {
        LOG_ERROR("默认自签证书生成失败");
        return nullptr;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return nullptr;

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    SSL_CTX_use_certificate(ctx, default_cert);
    SSL_CTX_use_PrivateKey(ctx, state.pkey);

    // 注册 SNI 回调，按需切换证书
    SSL_CTX_set_tlsext_servername_callback(ctx, AutoSignSniCallback);

    // ALPN 回调
    SSL_CTX_set_alpn_select_cb(ctx, [](SSL*, const unsigned char** out,
                                        unsigned char* outlen,
                                        const unsigned char* in,
                                        unsigned int inlen, void*) -> int {
        static const unsigned char h2[] = "\x02h2";
        static const unsigned char http11[] = "\x08http/1.1";
        if (SSL_select_next_proto((unsigned char**)out, outlen,
                                   in, inlen, h2, sizeof(h2) - 1) == OPENSSL_NPN_NEGOTIATED)
            return SSL_TLSEXT_ERR_OK;
        if (SSL_select_next_proto((unsigned char**)out, outlen,
                                   in, inlen, http11, sizeof(http11) - 1) == OPENSSL_NPN_NEGOTIATED)
            return SSL_TLSEXT_ERR_OK;
        return SSL_TLSEXT_ERR_NOACK;
    }, nullptr);

    LOG_INFO("TLS 自动签名模式已启用（按 SNI 动态生成证书，默认域名={}）",
             default_name);
    return std::unique_ptr<SslContext>(new SslContext(ctx));
}

std::unique_ptr<SslContext> SslContext::CreateClient(const TlsConfig& config) {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        LOG_ERROR("Failed to create SSL client context");
        return nullptr;
    }
    
    // 设置 TLS 版本
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    if (config.allow_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(ctx);
    }
    
    return std::unique_ptr<SslContext>(new SslContext(ctx));
}

SslContext::~SslContext() {
    if (ctx_) {
        SSL_CTX_free(ctx_);
    }
}

// ============================================================================
// TlsStream 实现
// ============================================================================

TlsStream::TlsStream(std::unique_ptr<TcpStream> inner, SSL_CTX* ctx, bool is_server)
    : inner_(std::move(inner))
    , is_server_(is_server) {
    
    ssl_ = SSL_new(ctx);
    if (!ssl_) {
        throw std::runtime_error("Failed to create SSL object");
    }
    
    // 创建内存 BIO 对
    read_bio_ = BIO_new(BIO_s_mem());
    write_bio_ = BIO_new(BIO_s_mem());
    
    if (!read_bio_ || !write_bio_) {
        if (read_bio_) BIO_free(read_bio_);
        if (write_bio_) BIO_free(write_bio_);
        SSL_free(ssl_);
        throw std::runtime_error("Failed to create BIO objects");
    }
    
    // 设置非阻塞模式
    BIO_set_nbio(read_bio_, 1);
    BIO_set_nbio(write_bio_, 1);
    
    SSL_set_bio(ssl_, read_bio_, write_bio_);
    
    if (is_server_) {
        SSL_set_accept_state(ssl_);
    } else {
        SSL_set_connect_state(ssl_);
    }
}

TlsStream::~TlsStream() {
    if (ssl_) {
        SSL_free(ssl_);  // 这会自动释放关联的 BIO
    }
}

TlsStream::TlsStream(TlsStream&& other) noexcept
    : inner_(std::move(other.inner_))
    , ssl_(other.ssl_)
    , read_bio_(other.read_bio_)
    , write_bio_(other.write_bio_)
    , is_server_(other.is_server_)
    , handshake_done_(other.handshake_done_)
    , shutdown_initiated_(other.shutdown_initiated_)
    , read_buffer_(other.read_buffer_) {
    other.ssl_ = nullptr;
    other.read_bio_ = nullptr;
    other.write_bio_ = nullptr;
    other.shutdown_initiated_ = true;  // 防止被移动的对象再调用 shutdown
}

TlsStream& TlsStream::operator=(TlsStream&& other) noexcept {
    if (this != &other) {
        if (ssl_) {
            SSL_free(ssl_);
        }
        inner_ = std::move(other.inner_);
        ssl_ = other.ssl_;
        read_bio_ = other.read_bio_;
        write_bio_ = other.write_bio_;
        is_server_ = other.is_server_;
        handshake_done_ = other.handshake_done_;
        shutdown_initiated_ = other.shutdown_initiated_;
        read_buffer_ = other.read_buffer_;
        other.ssl_ = nullptr;
        other.read_bio_ = nullptr;
        other.write_bio_ = nullptr;
        other.shutdown_initiated_ = true;  // 防止被移动的对象再调用 shutdown
    }
    return *this;
}

void TlsStream::SetServerName(const std::string& name) {
    if (!is_server_ && ssl_) {
        SSL_set_tlsext_host_name(ssl_, name.c_str());
    }
}

void TlsStream::SetAlpn(const std::vector<std::string>& protocols) {
    if (protocols.empty() || !ssl_) return;
    
    // 构建 ALPN 格式：长度前缀 + 协议名
    std::vector<unsigned char> alpn;
    for (const auto& proto : protocols) {
        alpn.push_back(static_cast<unsigned char>(proto.size()));
        alpn.insert(alpn.end(), proto.begin(), proto.end());
    }
    
    SSL_set_alpn_protos(ssl_, alpn.data(), static_cast<unsigned int>(alpn.size()));
}

cobalt::task<bool> TlsStream::Handshake() {
    if (handshake_done_) {
        co_return true;
    }
    
    while (true) {
        int ret = SSL_do_handshake(ssl_);
        
        if (ret == 1) {
            handshake_done_ = true;
            co_return true;
        }
        
        int err = SSL_get_error(ssl_, ret);
        
        if (err == SSL_ERROR_WANT_READ) {
            // 先发送待发数据
            if (!co_await FlushWriteBio()) {
                co_return false;
            }
            
            // 从底层读取数据
            auto n = co_await inner_->AsyncRead(net::buffer(read_buffer_));
            if (n == 0) {
                LOG_ACCESS_DEBUG("TLS handshake: connection closed during read");
                co_return false;
            }
            
            // 写入 read_bio
            BIO_write(read_bio_, read_buffer_.data(), static_cast<int>(n));
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (!co_await FlushWriteBio()) {
                co_return false;
            }
        } else {
            const unsigned long err_code = ERR_get_error();
            char buf[256];
            ERR_error_string_n(err_code, buf, sizeof(buf));
            if (is_server_ && IsBenignServerHandshakeError(err_code)) {
                LOG_ACCESS_DEBUG("TLS handshake ignored (non-TLS traffic on TLS port): {}", buf);
            } else {
                LOG_CONN_FAIL("TLS handshake error: {}", buf);
            }
            co_return false;
        }
    }
}

cobalt::task<bool> TlsStream::FlushWriteBio() {
    auto pending = static_cast<int>(BIO_pending(write_bio_));
    if (pending <= 0) {
        co_return true;
    }

    // 单次 BIO_read + 单次 AsyncWrite，避免多次 syscall
    // 典型 TLS record ≤ 16KB + overhead，栈缓冲覆盖绝大多数场景
    static constexpr size_t kFlushBufSize = 17 * 1024;

    try {
        if (static_cast<size_t>(pending) <= kFlushBufSize) {
            alignas(64) std::array<uint8_t, kFlushBufSize> buf{};
            int read = BIO_read(write_bio_, buf.data(), pending);
            if (read > 0) {
                size_t written = co_await inner_->AsyncWrite(net::buffer(buf.data(), read));
                if (written != static_cast<size_t>(read)) {
                    co_return false;
                }
            }
        } else {
            // 超大 pending（TLS 握手大证书链等），堆分配回退
            std::vector<uint8_t> buf(pending);
            int read = BIO_read(write_bio_, buf.data(), pending);
            if (read > 0) {
                size_t written = co_await inner_->AsyncWrite(net::buffer(buf.data(), read));
                if (written != static_cast<size_t>(read)) {
                    co_return false;
                }
            }
        }
    } catch (...) {
        co_return false;
    }
    co_return true;
}

std::string TlsStream::NegotiatedAlpn() const {
    if (!ssl_) return "";
    
    const unsigned char* data = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl_, &data, &len);
    
    if (data && len > 0) {
        // ISSUE-02-02: 使用 unsafe::ptr_cast 替代 reinterpret_cast
        return std::string(unsafe::ptr_cast<const char>(data), len);
    }
    return "";
}

std::string TlsStream::ReceivedSni() const {
    if (!ssl_ || !is_server_) return "";
    
    const char* name = SSL_get_servername(ssl_, TLSEXT_NAMETYPE_host_name);
    return name ? name : "";
}

cobalt::task<std::size_t> TlsStream::AsyncRead(net::mutable_buffer buf) {
    if (!handshake_done_) {
        if (!co_await Handshake()) {
            ThrowTlsReadError("TLS handshake failed during read");
        }
    }
    
    while (true) {
        int ret = SSL_read(ssl_, buf.data(), static_cast<int>(buf.size()));
        
        if (ret > 0) {
            co_return static_cast<std::size_t>(ret);
        }
        
        int err = SSL_get_error(ssl_, ret);
        
        if (err == SSL_ERROR_ZERO_RETURN) {
            co_return 0;  // Clean shutdown
        }
        
        if (err == SSL_ERROR_WANT_READ) {
            // 先刷新写缓冲
            if (!co_await FlushWriteBio()) {
                ThrowTlsReadError("TLS flush write BIO failed");
            }
            
            // 从底层读取
            auto n = co_await inner_->AsyncRead(net::buffer(read_buffer_));
            if (n == 0) {
                ThrowTlsReadError("TLS peer closed without close_notify");
            }
            BIO_write(read_bio_, read_buffer_.data(), static_cast<int>(n));
        } else if (err == SSL_ERROR_WANT_WRITE) {
            if (!co_await FlushWriteBio()) {
                ThrowTlsReadError("TLS flush write BIO failed");
            }
        } else {
            ThrowTlsReadError("TLS read failed");
        }
    }
}

cobalt::task<std::size_t> TlsStream::AsyncWrite(net::const_buffer buf) {
    if (!handshake_done_) {
        if (!co_await Handshake()) {
            ThrowTlsWriteError("TLS handshake failed during write");
        }
    }
    
    size_t total_written = 0;
    const uint8_t* data = static_cast<const uint8_t*>(buf.data());
    size_t remaining = buf.size();
    
    while (remaining > 0) {
        int ret = SSL_write(ssl_, data + total_written, static_cast<int>(remaining));
        
        if (ret > 0) {
            total_written += ret;
            remaining -= ret;
            
            // 刷新写缓冲
            if (!co_await FlushWriteBio()) {
                ThrowTlsWriteError("TLS flush write BIO failed");
            }
        } else {
            int err = SSL_get_error(ssl_, ret);
            if (err == SSL_ERROR_WANT_WRITE) {
                if (!co_await FlushWriteBio()) {
                    ThrowTlsWriteError("TLS flush write BIO failed");
                }
            } else if (err == SSL_ERROR_WANT_READ) {
                auto n = co_await inner_->AsyncRead(net::buffer(read_buffer_));
                if (n > 0) {
                    BIO_write(read_bio_, read_buffer_.data(), static_cast<int>(n));
                } else {
                    ThrowTlsWriteError("TLS write peer closed while waiting for read");
                }
            } else {
                ThrowTlsWriteError("TLS write failed");
            }
        }
    }

    if (total_written != buf.size()) {
        ThrowTlsWriteError("TLS partial write");
    }

    co_return total_written;
}

void TlsStream::ShutdownRead() {
    inner_->ShutdownRead();
}

void TlsStream::ShutdownWrite() {
    if (ssl_ && handshake_done_ && !shutdown_initiated_) {
        shutdown_initiated_ = true;
        SSL_shutdown(ssl_);

        // 分块 flush close_notify，避免每连接为大 pending BIO 再做 heap 分配。
        int fd = inner_->NativeHandle();
        if (fd >= 0) {
            alignas(64) std::array<uint8_t, kTlsIoBufferSize> buf{};
            while (true) {
                auto pending = static_cast<int>(BIO_pending(write_bio_));
                if (pending <= 0) break;

                int chunk = std::min<int>(pending, static_cast<int>(buf.size()));
                int read = BIO_read(write_bio_, buf.data(), chunk);
                if (read <= 0) break;

                int sent_total = 0;
                while (sent_total < read) {
                    int sent = ::send(
                        fd,
                        unsafe::ptr_cast<const char>(buf.data()) + sent_total,
                        read - sent_total,
                        MSG_NOSIGNAL);
                    if (sent <= 0) {
                        break;
                    }
                    sent_total += sent;
                }

                if (sent_total < read) {
                    break;
                }
            }
        }
    }
    inner_->ShutdownWrite();
}

cobalt::task<void> TlsStream::AsyncShutdownWrite() {
    // ISSUE-01-04: TLS 层 AsyncShutdownWrite 发送 close_notify
    // 根据 RFC 5246/8446，优雅关闭需要发送 close_notify alert
    if (ssl_ && handshake_done_ && !shutdown_initiated_) {
        shutdown_initiated_ = true;
        LOG_ACCESS_DEBUG("TLS: sending close_notify");
        int ret = SSL_shutdown(ssl_);
        if (ret == 0) {
            // 第一次 SSL_shutdown 返回 0 表示 close_notify 已发送
            // 但尚未收到对端的 close_notify
            LOG_ACCESS_DEBUG("TLS: close_notify sent, waiting for peer");
        } else if (ret == 1) {
            LOG_ACCESS_DEBUG("TLS: bidirectional shutdown complete");
        }
        co_await FlushWriteBio();
    }
    co_await inner_->AsyncShutdownWrite();
}

void TlsStream::Close() {
    if (ssl_ && !shutdown_initiated_) {
        shutdown_initiated_ = true;
        SSL_shutdown(ssl_);
    }
    inner_->Close();
}

void TlsStream::Cancel() noexcept {
    inner_->Cancel();
}

int TlsStream::NativeHandle() const {
    return inner_->NativeHandle();
}

net::any_io_executor TlsStream::GetExecutor() const {
    return inner_->GetExecutor();
}

bool TlsStream::IsOpen() const {
    return inner_->IsOpen() && ssl_ != nullptr;
}

// ============================================================================
// 工厂函数实现
// ============================================================================

cobalt::task<std::unique_ptr<TlsStream>> WrapTlsServer(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx) {
    
    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx.Native(), true);
    
    if (!co_await stream->Handshake()) {
        co_return nullptr;
    }
    
    co_return stream;
}

cobalt::task<std::unique_ptr<TlsStream>> WrapTlsClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    const std::string& server_name,
    const std::vector<std::string>& alpn) {
    
    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx.Native(), false);
    
    if (!server_name.empty()) {
        stream->SetServerName(server_name);
    }
    if (!alpn.empty()) {
        stream->SetAlpn(alpn);
    }
    
    if (!co_await stream->Handshake()) {
        co_return nullptr;
    }
    
    co_return stream;
}

cobalt::task<DialResult> ConnectTls(
    net::any_io_executor executor,
    const tcp::endpoint& endpoint,
    SslContext& ctx,
    const std::string& server_name,
    const std::vector<std::string>& alpn,
    std::chrono::seconds timeout) {
    
    // 先建立 TCP 连接
    auto tcp_result = co_await TcpStream::Connect(executor, endpoint, timeout);
    if (!tcp_result.Ok()) {
        co_return tcp_result;
    }
    
    auto* tcp_raw = dynamic_cast<TcpStream*>(tcp_result.stream.get());
    if (!tcp_raw) {
        co_return DialResult::Fail(
            ErrorCode::INVALID_ARGUMENT,
            "TLS upgrade requires TcpStream as base transport");
    }
    tcp_result.stream.release();
    auto tcp = std::unique_ptr<TcpStream>(tcp_raw);
    auto tls_stream = co_await WrapTlsClient(
        std::move(tcp), ctx, server_name, alpn);
    
    if (!tls_stream) {
        co_return DialResult::Fail(ErrorCode::TLS_HANDSHAKE_FAILED, "TLS handshake failed");
    }
    
    co_return DialResult::Success(std::move(tls_stream));
}

}  // namespace acpp
