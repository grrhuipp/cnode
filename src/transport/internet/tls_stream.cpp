#include "acppnode/transport/internet/tls_stream.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "tls_client_context.hpp"
#include "reality_tls.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include "autosign_cert.hpp"
#include <openssl/err.h>
#include <openssl/tls1.h>
#include <asio/ssl.hpp>
#include <asio/write.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <span>

namespace acpp {

// ============================================================================
// SslContext 实现
// ============================================================================

namespace {

int SelectServerAlpnCallback(
    SSL* ssl,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* /*arg*/) {
    auto* ctx = static_cast<SslContext*>(
        SSL_CTX_get_app_data(SSL_get_SSL_CTX(ssl)));
    if (!ctx) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    const auto& configured = ctx->ServerAlpnWire();
    if (configured.empty()) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    unsigned char* selected = nullptr;
    const int rc = SSL_select_next_proto(
        &selected,
        outlen,
        configured.data(),
        static_cast<unsigned int>(configured.size()),
        in,
        inlen);
    if (rc != OPENSSL_NPN_NEGOTIATED || !selected || *outlen == 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    *out = selected;
    return SSL_TLSEXT_ERR_OK;
}

}  // namespace

std::unique_ptr<SslContext> SslContext::CreateServer(const TlsConfig& config) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        LOG_ERROR("Failed to create SSL server context");
        return nullptr;
    }

    if (!ConfigureTlsProtocolVersions(
            ctx, config.min_version, config.max_version)) {
        LOG_ERROR("Invalid TLS server protocol version policy");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

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

    auto out = std::unique_ptr<SslContext>(new SslContext(ctx));
    if (!out->ConfigureServerAlpn(config.alpn)) {
        LOG_ERROR("Invalid TLS server ALPN policy");
        return nullptr;
    }
    return out;
}

// ============================================================================
// 自动签名：根据 SNI 动态生成自签证书
// ============================================================================

namespace {

[[noreturn]] void ThrowTlsWriteError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
}

[[noreturn]] void ThrowTlsReadError(const char* what) {
    throw IoSystemError(io_error::connection_reset, what);
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

std::string ResolveAutoSignDefaultName(const TlsConfig& config) {
    if (config.server_name.empty()) {
        return "localhost";
    }
    return config.server_name;
}

int AutoSignCertCallback(SSL* ssl, void* arg) {
    auto* default_name = static_cast<std::string*>(arg);
    const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    const std::string certificate_name = sni ? std::string(sni) : *default_name;

    auto& state = transport::internet::GetAutoSignState();
    auto material = state.GetOrCreate(certificate_name);
    if (!material.cert || !material.key) return 0;

    if (SSL_use_certificate(ssl, material.cert) != 1 ||
        SSL_use_PrivateKey(ssl, material.key) != 1) {
        return 0;
    }
    return 1;
}


}  // namespace

std::unique_ptr<SslContext> SslContext::CreateServerAutoSign(const TlsConfig& config) {
    // 默认证书优先使用配置的 server_name，避免无 SNI 时退回 localhost。
    const std::string default_name = ResolveAutoSignDefaultName(config);
    auto& state = transport::internet::GetAutoSignState();
    auto default_material = state.GetOrCreate(default_name);
    if (!default_material.cert || !default_material.key) {
        LOG_ERROR("默认自签证书生成失败");
        return nullptr;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return nullptr;

    if (!ConfigureTlsProtocolVersions(
            ctx, config.min_version, config.max_version)) {
        LOG_ERROR("Invalid auto-sign TLS protocol version policy");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);

    SSL_CTX_use_certificate(ctx, default_material.cert);
    SSL_CTX_use_PrivateKey(ctx, default_material.key);

    auto default_name_state = std::make_shared<std::string>(default_name);
    SSL_CTX_set_cert_cb(ctx, AutoSignCertCallback, default_name_state.get());

    LOG_INFO("TLS 自动签名模式已启用（按 SNI 动态生成证书，默认域名={}）",
             default_name);
    auto out = std::unique_ptr<SslContext>(
        new SslContext(ctx, std::move(default_name_state)));
    if (!out->ConfigureServerAlpn(config.alpn)) {
        LOG_ERROR("Invalid auto-sign TLS ALPN policy");
        return nullptr;
    }
    return out;
}

bool SslContext::ConfigureServerAlpn(
    const std::vector<std::string>& protocols) {
    if (!EncodeTlsAlpnProtocols(protocols, server_alpn_wire_)) return false;

    if (!server_alpn_wire_.empty()) {
        SSL_CTX_set_app_data(ctx_, this);
        SSL_CTX_set_alpn_select_cb(ctx_, SelectServerAlpnCallback, nullptr);
    }
    return true;
}

// ============================================================================
// TlsStream 实现
// ============================================================================

namespace {

class TlsTcpLayer {
public:
    using executor_type = tcp::socket::executor_type;
    using lowest_layer_type = TlsTcpLayer;

    explicit TlsTcpLayer(std::unique_ptr<TcpStream> stream)
        : stream_(std::move(stream)) {
        if (!stream_) {
            throw std::invalid_argument("TlsTcpLayer requires TcpStream");
        }
    }

    TlsTcpLayer(TlsTcpLayer&&) noexcept = default;
    TlsTcpLayer& operator=(TlsTcpLayer&&) noexcept = default;

    executor_type get_executor() noexcept {
        return stream_->GetExecutor();
    }

    lowest_layer_type& lowest_layer() noexcept {
        return *this;
    }

    const lowest_layer_type& lowest_layer() const noexcept {
        return *this;
    }

    TcpStream& Tcp() noexcept {
        return *stream_;
    }

    const TcpStream& Tcp() const noexcept {
        return *stream_;
    }

    template <typename MutableBufferSequence, typename CompletionToken>
    auto async_read_some(const MutableBufferSequence& buffers,
                         CompletionToken&& token) {
        return net::async_initiate<CompletionToken, void(IoErrorCode, std::size_t)>(
            [this](auto&& handler, MutableBufferSequence buffers) mutable {
                auto ex = get_executor();
                if (!stream_->TlsLayerCanRead()) {
                    net::post(ex,
                        [handler = std::forward<decltype(handler)>(handler)]() mutable {
                            std::move(handler)(io_error::eof, 0);
                        });
                    return;
                }

                auto it = net::buffer_sequence_begin(buffers);
                auto end = net::buffer_sequence_end(buffers);
                for (; it != end; ++it) {
                    net::mutable_buffer buffer = *it;
                    if (buffer.size() == 0) {
                        continue;
                    }
                    const std::size_t pending =
                        stream_->ConsumeTlsLayerPendingData(buffer);
                    if (pending > 0) {
                        net::post(ex,
                            [handler = std::forward<decltype(handler)>(handler),
                             pending]() mutable {
                                std::move(handler)(IoErrorCode{}, pending);
                            });
                        return;
                    }
                    break;
                }

                stream_->BeginTlsLayerRead();
                stream_->TlsLayerSocket().async_read_some(
                    buffers,
                    [this,
                     handler = std::forward<decltype(handler)>(handler)](
                        IoErrorCode ec, std::size_t n) mutable {
                        stream_->EndTlsLayerRead(ec, n);
                        std::move(handler)(ec, n);
                    });
            },
            token,
            buffers);
    }

    template <typename ConstBufferSequence, typename CompletionToken>
    auto async_write_some(const ConstBufferSequence& buffers,
                          CompletionToken&& token) {
        return net::async_initiate<CompletionToken, void(IoErrorCode, std::size_t)>(
            [this](auto&& handler, ConstBufferSequence buffers) mutable {
                auto ex = get_executor();
                if (!stream_->TlsLayerCanWrite()) {
                    net::post(ex,
                        [handler = std::forward<decltype(handler)>(handler)](
                            ) mutable {
                            std::move(handler)(io_error::broken_pipe, 0);
                        });
                    return;
                }

                stream_->BeginTlsLayerWrite();
                stream_->TlsLayerSocket().async_write_some(
                    buffers,
                    [this,
                     handler = std::forward<decltype(handler)>(handler)](
                        IoErrorCode ec, std::size_t n) mutable {
                        stream_->EndTlsLayerWrite(ec, n);
                        std::move(handler)(ec, n);
                    });
            },
            token,
            buffers);
    }

private:
    std::unique_ptr<TcpStream> stream_;
};

SSL* NewSsl(SSL_CTX* ctx) {
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        throw std::runtime_error("Failed to create SSL object");
    }
    SSL_set_mode(ssl, SSL_MODE_RELEASE_BUFFERS);
    return ssl;
}

}  // namespace

struct TlsStream::Impl {
    using SslStream = net::ssl::stream<TlsTcpLayer>;

    Impl(std::unique_ptr<TcpStream> inner, SSL_CTX* ctx)
        : stream(TlsTcpLayer(std::move(inner)), NewSsl(ctx)) {
        memory::OnTlsStreamNew();
    }

    ~Impl() {
        memory::OnTlsStreamFree();
    }

    SslStream stream;
};

TlsStream::TlsStream(std::unique_ptr<TcpStream> inner, SSL_CTX* ctx, bool is_server)
    : impl_(std::make_unique<Impl>(std::move(inner), ctx))
    , is_server_(is_server) {}

TlsStream::~TlsStream() = default;

TlsStream::TlsStream(TlsStream&& other) noexcept
    : impl_(std::move(other.impl_))
    , is_server_(other.is_server_)
    , handshake_done_(other.handshake_done_)
    , shutdown_initiated_(other.shutdown_initiated_)
    , app_state_(std::move(other.app_state_)) {
    other.shutdown_initiated_ = true;
}

TlsStream& TlsStream::operator=(TlsStream&& other) noexcept {
    if (this != &other) {
        impl_ = std::move(other.impl_);
        is_server_ = other.is_server_;
        handshake_done_ = other.handshake_done_;
        shutdown_initiated_ = other.shutdown_initiated_;
        app_state_ = std::move(other.app_state_);
        other.shutdown_initiated_ = true;
    }
    return *this;
}

SSL* TlsStream::NativeSsl() noexcept {
    return impl_ ? impl_->stream.native_handle() : nullptr;
}

const SSL* TlsStream::NativeSsl() const noexcept {
    return impl_ ? impl_->stream.native_handle() : nullptr;
}

TcpStream* TlsStream::BaseTcpStream() {
    return impl_ ? &impl_->stream.next_layer().Tcp() : nullptr;
}

const TcpStream* TlsStream::BaseTcpStream() const {
    return impl_ ? &impl_->stream.next_layer().Tcp() : nullptr;
}

bool TlsStream::SetServerIdentity(std::string_view identity) {
    SSL* ssl = NativeSsl();
    return !is_server_ && ConfigureTlsServerIdentity(ssl, identity);
}

bool TlsStream::SetAlpn(const std::vector<std::string>& protocols) {
    SSL* ssl = NativeSsl();
    if (!ssl) return false;

    std::vector<unsigned char> alpn;
    if (!EncodeTlsAlpnProtocols(protocols, alpn)) return false;
    return SSL_set_alpn_protos(ssl, alpn.data(), alpn.size()) == 0;
}

net::awaitable<bool> TlsStream::Handshake() {
    if (handshake_done_) {
        co_return true;
    }

    auto [ec] = co_await impl_->stream.async_handshake(
        is_server_ ? net::ssl::stream_base::server
                   : net::ssl::stream_base::client,
        net::as_tuple(net::use_awaitable));

    if (ec) {
        const unsigned long err_code = ERR_get_error();
        if (is_server_ && IsBenignServerHandshakeError(err_code)) {
            LOG_ACCESS_DEBUG("TLS handshake ignored (non-TLS traffic on TLS port): {}", ec.message());
        } else {
            LOG_CONN_FAIL("TLS handshake error: {}", ec.message());
        }
        co_return false;
    }

    if (app_state_ && !VerifyRealityClientHandshake(NativeSsl(), app_state_)) {
        co_return false;
    }

    handshake_done_ = true;
    co_return true;
}

std::string TlsStream::NegotiatedAlpn() const {
    const SSL* ssl = NativeSsl();
    if (!ssl) return "";

    const unsigned char* data = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl, &data, &len);

    if (data && len > 0) {
        return std::string(unsafe::ptr_cast<const char>(data), len);
    }
    return "";
}

std::string TlsStream::ReceivedSni() const {
    const SSL* ssl = NativeSsl();
    if (!ssl || !is_server_) return "";

    const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    return name ? name : "";
}

net::awaitable<std::size_t> TlsStream::AsyncRead(net::mutable_buffer buf) {
    if (!handshake_done_ && !co_await Handshake()) {
        ThrowTlsReadError("TLS handshake failed during read");
    }

    auto [ec, n] = co_await impl_->stream.async_read_some(
        buf, net::as_tuple(net::use_awaitable));
    if (ec) {
        if (ec == io_error::eof ||
            ec == net::ssl::error::stream_truncated ||
            ec == io_error::operation_aborted) {
            co_return 0;
        }
        throw IoSystemError(ec);
    }
    co_return n;
}

net::awaitable<buf::MultiBuffer> TlsStream::ReadMultiBuffer() {
    if (!handshake_done_ && !co_await Handshake()) {
        ThrowTlsReadError("TLS handshake failed during read");
    }

    buf::BufferGuard out{buf::Buffer::New()};
    if (!out) {
        co_return buf::MultiBuffer{};
    }

    auto [ec, n] = co_await impl_->stream.async_read_some(
        net::mutable_buffer(out->Tail().data(), out->Available()),
        net::as_tuple(net::use_awaitable));
    if (ec || n == 0) {
        if (!ec ||
            ec == io_error::eof ||
            ec == net::ssl::error::stream_truncated ||
            ec == io_error::operation_aborted) {
            co_return buf::MultiBuffer{};
        }
        throw IoSystemError(ec);
    }

    out->Produce(static_cast<uint32_t>(n));
    co_return buf::MultiBuffer{out.release()};
}

net::awaitable<std::size_t> TlsStream::AsyncWrite(net::const_buffer buf) {
    if (!handshake_done_ && !co_await Handshake()) {
        ThrowTlsWriteError("TLS handshake failed during write");
    }

    auto [ec, n] = co_await net::async_write(
        impl_->stream, buf, net::as_tuple(net::use_awaitable));
    if (ec) {
        throw IoSystemError(ec);
    }
    co_return n;
}

net::awaitable<void> TlsStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (!handshake_done_ && !co_await Handshake()) {
        ThrowTlsWriteError("TLS handshake failed during write");
    }
    if (buffers.empty()) {
        co_return;
    }

    auto [ec, n] = co_await net::async_write(
        impl_->stream, buffers, net::as_tuple(net::use_awaitable));
    (void)n;
    if (ec) {
        throw IoSystemError(ec);
    }
}

net::awaitable<void> TlsStream::WriteMultiBuffer(buf::MultiBuffer mb) {
    if (!handshake_done_ && !co_await Handshake()) {
        ThrowTlsWriteError("TLS handshake failed during write");
    }
    if (!buf::HasData(mb)) {
        co_return;
    }

    ConstBufferSpanBuilder<8> out;
    out.AppendMultiBuffer(mb);
    if (!out.empty()) {
        auto [ec, n] = co_await net::async_write(
            impl_->stream, out.Span(), net::as_tuple(net::use_awaitable));
        (void)n;
        if (ec) {
            throw IoSystemError(ec);
        }
    }
}

void TlsStream::ShutdownRead() {
    if (impl_) {
        impl_->stream.next_layer().Tcp().ShutdownRead();
    }
}

void TlsStream::ShutdownWrite() {
    if (handshake_done_ && !shutdown_initiated_) {
        shutdown_initiated_ = true;
    }
    if (impl_) {
        impl_->stream.next_layer().Tcp().ShutdownWrite();
    }
}

net::awaitable<void> TlsStream::AsyncShutdownWrite() {
    if (impl_ && handshake_done_ && !shutdown_initiated_) {
        shutdown_initiated_ = true;
        LOG_ACCESS_DEBUG("TLS: sending close_notify");
        auto [ec] = co_await impl_->stream.async_shutdown(
            net::as_tuple(net::use_awaitable));
        if (ec && ec != net::ssl::error::stream_truncated &&
            ec != io_error::eof && ec != io_error::operation_aborted) {
            LOG_ACCESS_DEBUG("TLS: close_notify failed: {}", ec.message());
        }
    }
    if (impl_) {
        co_await impl_->stream.next_layer().Tcp().AsyncShutdownWrite();
    }
}

void TlsStream::Close() {
    shutdown_initiated_ = true;
    if (impl_) {
        impl_->stream.next_layer().Tcp().Close();
    }
}

void TlsStream::CloseAbortive() {
    shutdown_initiated_ = true;
    if (impl_) {
        impl_->stream.next_layer().Tcp().SetAbortiveClose(true);
        impl_->stream.next_layer().Tcp().Close();
    }
}

void TlsStream::Cancel() noexcept {
    if (impl_) {
        impl_->stream.next_layer().Tcp().Cancel();
    }
}

int TlsStream::NativeHandle() const {
    return impl_ ? impl_->stream.next_layer().Tcp().NativeHandle() : -1;
}

bool TlsStream::IsOpen() const {
    return impl_ && impl_->stream.next_layer().Tcp().IsOpen() && NativeSsl() != nullptr;
}


// ============================================================================
// 工厂函数实现
// ============================================================================

net::awaitable<std::unique_ptr<TlsStream>> WrapTlsServer(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx) {

    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx.Native(), true);

    if (!co_await stream->Handshake()) {
        co_return nullptr;
    }

    co_return stream;
}

net::awaitable<std::unique_ptr<TlsStream>> WrapTlsClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    const std::string& server_name,
    const std::vector<std::string>& alpn) {

    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx.Native(), false);

    if (!server_name.empty() && !stream->SetServerIdentity(server_name)) {
        co_return nullptr;
    }
    if (!alpn.empty() && !stream->SetAlpn(alpn)) {
        co_return nullptr;
    }

    if (!co_await stream->Handshake()) {
        co_return nullptr;
    }

    co_return stream;
}

net::awaitable<std::unique_ptr<TlsStream>> WrapRealityClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    const RealityConfig& reality,
    const std::string& server_name,
    const std::vector<std::string>& alpn) {

    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx.Native(), false);

    if (!server_name.empty() && !stream->SetServerIdentity(server_name)) {
        co_return nullptr;
    }
    if (!alpn.empty() && !stream->SetAlpn(alpn)) {
        co_return nullptr;
    }
    if (!stream->SetRealityClient(reality)) {
        co_return nullptr;
    }

    if (!co_await stream->Handshake()) {
        co_return nullptr;
    }

    co_return stream;
}

net::awaitable<DialResult> ConnectTls(
    net::io_context& io_context,
    const tcp::endpoint& endpoint,
    SslContext& ctx,
    const std::string& server_name,
    const std::vector<std::string>& alpn,
    std::chrono::seconds timeout) {

    // 先建立 TCP 连接
    auto tcp_result = co_await TcpStream::Connect(io_context, endpoint, timeout);
    if (!tcp_result.Ok()) {
        co_return tcp_result;
    }

    auto* tcp_raw = tcp_result.stream
        ? dynamic_cast<TcpStream*>(tcp_result.stream.get())
        : nullptr;
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
