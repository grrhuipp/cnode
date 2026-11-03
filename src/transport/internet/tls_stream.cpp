#include "acppnode/transport/internet/tls_stream.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "tls_client_context.hpp"
#include "reality_tls.hpp"
#include "acppnode/transport/internet/async_write_gate.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/unsafe.hpp"       // ISSUE-02-02: unsafe cast 收敛
#include "autosign_cert.hpp"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/tls1.h>
#include <asio/ssl/error.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/co_spawn.hpp>
#include <algorithm>
#include <array>
#include <span>
#include <exception>
#include <climits>
#include <optional>

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

struct AutoSignContextState final : SslContext::ContextState {
    explicit AutoSignContextState(std::string name)
        : default_name(std::move(name)) {}

    std::string default_name;
    transport::internet::AutoSignState certificates;
};

std::string ResolveAutoSignDefaultName(const TlsConfig& config) {
    if (config.server_name.empty()) {
        return "localhost";
    }
    return config.server_name;
}

int AutoSignCertCallback(SSL* ssl, void* arg) {
    auto* state = static_cast<AutoSignContextState*>(arg);
    const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    const std::string certificate_name =
        sni ? std::string(sni) : state->default_name;

    auto material = state->certificates.GetOrCreate(certificate_name);
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
    auto state = std::make_unique<AutoSignContextState>(default_name);
    auto default_material = state->certificates.GetOrCreate(default_name);
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

    SSL_CTX_use_certificate(ctx, default_material.cert);
    SSL_CTX_use_PrivateKey(ctx, default_material.key);

    SSL_CTX_set_cert_cb(ctx, AutoSignCertCallback, state.get());

    LOG_INFO("TLS 自动签名模式已启用（按 SNI 动态生成证书，默认域名={}）",
             default_name);
    auto out = std::unique_ptr<SslContext>(
        new SslContext(ctx, std::move(state)));
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

// Populated explicitly before Worker startup. BIO_METHOD and SSL-owned memory
// stay with the library allocator; only our operation payload uses Worker PMR.
std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)> tls_bio_method{nullptr, BIO_meth_free};

}  // namespace

struct TlsStream::Impl : memory::ThreadAllocated, private transport::CancellationSubscription {
    using Gate = transport::internet::AsyncWriteGate;
    enum class Kind { Handshake, Read, Write, Shutdown };

    struct Invocation {
        // A full record fits; larger handshake flights apply BIO backpressure.
        static constexpr std::size_t kOutputLimit = 64 * 1024;
        memory::ByteVector output;
        IoErrorCode transport_error;
        std::exception_ptr failure;
        unsigned long library_error = 0;
        int ssl_error = SSL_ERROR_NONE;
        int result = 0;
    };

    // At most one reader and one writer can own output. The turns live in those
    // operations, not in a connection queue, and preserve SSL record sequence
    // while allowing reads during a backpressured physical write.
    struct OutputTurn {
        OutputTurn(Impl& owner) : owner(owner), previous(owner.output_tail) {
            if (previous) wake.emplace(owner.Executor(), 1);
            if (previous) previous->next = this;
            owner.output_tail = this;
        }
        ~OutputTurn() {
            if (previous) previous->next = next;
            if (next) next->previous = previous;
            else owner.output_tail = previous;
            if (!previous && next) (void)next->wake->try_send(IoErrorCode{});
        }
        Impl& owner;
        OutputTurn* previous;
        OutputTurn* next = nullptr;
        std::optional<SignalChannel> wake;
    };

    struct InputWait {
        InputWait(Impl& owner, net::cancellation_slot parent)
            : owner(owner), parent(parent) {
            if (parent.is_connected())
                parent.assign([this](net::cancellation_type type) { wake.emit(type); });
            owner.input_wait = &wake;
        }
        ~InputWait() {
            owner.input_wait = nullptr;
            parent.clear();
        }
        Impl& owner;
        net::cancellation_slot parent;
        net::cancellation_signal wake;
    };

    struct ActiveDirection {
        explicit ActiveDirection(bool& active) : active(active) {
            if (active) throw std::logic_error("concurrent TLS operations in one direction");
            active = true;
        }
        ~ActiveDirection() { active = false; }
        bool& active;
    };

    struct PendingReadData : memory::ThreadAllocated {
        buf::MultiBuffer data;
    };

    Impl(std::unique_ptr<TcpStream> inner, SSL_CTX* context, bool server)
        : tcp(std::move(inner))
        , ssl(nullptr, SSL_free)
        , engine_gate(Executor())
        , input_gate(Executor()) {
        if (!tls_bio_method)
            throw std::logic_error("TlsStream::InitializeIo must precede Worker startup");
        tcp->PrepareTlsIo();
        ssl.reset(SSL_new(context));
        if (!ssl) throw std::bad_alloc();
        SSL_set_mode(ssl.get(), SSL_MODE_RELEASE_BUFFERS);
        SSL_set_max_send_fragment(ssl.get(), buf::Buffer::kSize);
        BIO* bio = BIO_new(tls_bio_method.get());
        if (!bio) throw std::bad_alloc();
        BIO_set_data(bio, this);
        BIO_set_init(bio, 1);
        SSL_set_bio(ssl.get(), bio, bio);
        if (server) SSL_set_accept_state(ssl.get());
        else SSL_set_connect_state(ssl.get());
        Resubscribe(tcp->Cancellation());
    }

    ~Impl() {
        Unsubscribe();
    }

    acpp::tcp::socket::executor_type Executor() {
        if (!tcp) throw std::invalid_argument("TlsStream requires TcpStream");
        return tcp->GetExecutor();
    }

    void OnCancellation(transport::Cancellation event) noexcept override {
        ++cancel_epoch;
        if (event.terminal) {
            engine_gate.Cancel();
            input_gate.Cancel();
            for (auto* turn = output_tail; turn; turn = turn->previous)
                if (turn->wake) turn->wake->close();
        } else {
            Resubscribe(tcp->Cancellation());
        }
    }

    void CheckCancellation(std::uint64_t epoch) const {
        if (epoch != cancel_epoch || !tcp->IsOpen())
            throw IoSystemError(io_error::operation_aborted);
    }

    void Abort() noexcept {
        engine_gate.Cancel();
        input_gate.Cancel();
        tcp->SetAbortiveClose(true);
        tcp->Close();
    }

    static int BioRead(BIO* bio, char* data, int size) noexcept {
        BIO_clear_retry_flags(bio);
        auto& self = *static_cast<Impl*>(BIO_get_data(bio));
        if (size <= 0) return 0;
        if (!self.invocation) return -1;
        IoErrorCode ec;
        const auto n = self.tcp->ReadAvailable(net::buffer(data, size), ec);
        if (n != 0) {
            ++self.input_generation;
            // A different SSL operation may consume readiness before the
            // reactor delivers it. Wake that wait to retry retained SSL input.
            if (self.input_wait) self.input_wait->emit(net::cancellation_type::terminal);
            return static_cast<int>(n);
        }
        if (ec == io_error::would_block || ec == io_error::try_again) {
            BIO_set_retry_read(bio);
            return -1;
        }
        self.invocation->transport_error = ec;
        return ec == io_error::eof ? 0 : -1;
    }

    static int BioWrite(BIO* bio, const char* data, int size) noexcept {
        BIO_clear_retry_flags(bio);
        auto& self = *static_cast<Impl*>(BIO_get_data(bio));
        if (size <= 0) return 0;
        if (!self.invocation) return -1;
        auto& call = *self.invocation;
        const auto count = std::min<std::size_t>(
            size, Invocation::kOutputLimit - call.output.size());
        if (count == 0) {
            BIO_set_retry_write(bio);
            return -1;
        }
        try {
            const auto required = call.output.size() + count;
            if (required > call.output.capacity())
                call.output.reserve(std::min(Invocation::kOutputLimit,
                    std::max(required, call.output.capacity() * 2)));
            const auto* first = reinterpret_cast<const uint8_t*>(data);
            call.output.insert(call.output.end(), first, first + count);
            return static_cast<int>(count);
        } catch (...) {
            // No C++ exception may cross a library callback.
            call.failure = std::current_exception();
            return -1;
        }
    }

    static long BioControl(BIO*, int command, long, void*) noexcept {
        // Output is accepted synchronously and flushed by the owning operation.
        return command == BIO_CTRL_FLUSH ? 1 : 0;
    }

    void Invoke(Invocation& call, Kind kind, net::mutable_buffer target,
                net::const_buffer source) noexcept {
        ERR_clear_error();
        invocation = &call;
        switch (kind) {
            case Kind::Handshake: call.result = SSL_do_handshake(ssl.get()); break;
            case Kind::Read:
                call.result = SSL_read(ssl.get(), target.data(),
                    static_cast<int>(std::min<std::size_t>(target.size(), INT_MAX)));
                break;
            case Kind::Write:
                call.result = SSL_write(ssl.get(), source.data(),
                    static_cast<int>(source.size()));
                break;
            case Kind::Shutdown: call.result = SSL_shutdown(ssl.get()); break;
        }
        // SSL_get_error depends on this thread's error queue. Capture everything
        // before any other SSL call, callback, or coroutine suspension.
        if (call.result <= 0) call.ssl_error = SSL_get_error(ssl.get(), call.result);
        call.library_error = ERR_get_error();
        while (ERR_get_error() != 0) {}
        invocation = nullptr;
    }

    [[noreturn]] void Fail(const Invocation& call) {
        Abort();
        if (call.failure) std::rethrow_exception(call.failure);
        if (call.transport_error == io_error::eof)
            throw IoSystemError(net::ssl::error::stream_truncated);
        if (call.transport_error) throw IoSystemError(call.transport_error);
        if (call.library_error)
            throw IoSystemError(IoErrorCode(
                static_cast<int>(call.library_error), net::error::get_ssl_category()));
        if (call.ssl_error == SSL_ERROR_ZERO_RETURN)
            throw IoSystemError(io_error::eof);
        throw IoSystemError(net::ssl::error::unexpected_result);
    }

    net::awaitable<void> WaitForInput(std::uint64_t epoch, std::uint64_t generation) {
        // The other direction may advance SSL while this operation waits for
        // the single TCP read deadline. Retry SSL instead of waiting for a new
        // network edge when its state has already changed.
        auto lease = input_gate.TryAcquire();
        if (!lease) lease = co_await input_gate.Acquire();
        CheckCancellation(epoch);
        if (!lease) throw IoSystemError(io_error::operation_aborted);
        if (generation != input_generation) co_return;
        const auto cancellation = co_await net::this_coro::cancellation_state;
        InputWait waiting(*this, cancellation.slot());
        const auto ec = co_await tcp->WaitReadable(waiting.wake.slot());
        CheckCancellation(epoch);
        if (cancellation.cancelled() != net::cancellation_type::none)
            throw IoSystemError(io_error::operation_aborted);
        if (ec == io_error::operation_aborted && generation != input_generation) co_return;
        if (ec) throw IoSystemError(ec);
    }

    net::awaitable<int> Perform(
        Kind kind, net::mutable_buffer target = {}, net::const_buffer source = {},
        buf::BufferGuard* allocated = nullptr) {
        const auto epoch = cancel_epoch;
        auto lease = engine_gate.TryAcquire();
        if (!lease) lease = co_await engine_gate.Acquire();
        CheckCancellation(epoch);
        if (!lease) throw IoSystemError(io_error::operation_aborted);
        for (;;) {
            if (allocated && !*allocated) {
                *allocated = buf::BufferGuard{buf::Buffer::New()};
                if (!*allocated) throw std::bad_alloc();
                target = net::buffer((*allocated)->Tail().data(), (*allocated)->Available());
            }
            int result, error;
            std::uint64_t generation;
            {
                Invocation call;
                Invoke(call, kind, target, source);
                generation = input_generation;
                result = call.result;
                error = call.ssl_error;
                if (call.failure) Fail(call);
                // No empty relay buffer survives a read retry, even when TLS
                // consumed only a partial record or a post-handshake message.
                if (allocated && result <= 0 && error == SSL_ERROR_WANT_READ)
                    *allocated = {};
                if (!call.output.empty()) {
                    try {
                        // Reserve the physical turn before the first suspension
                        // or another SSL call can generate a subsequent record.
                        OutputTurn turn(*this);
                        if (result > 0 || error == SSL_ERROR_WANT_READ)
                            lease.Reset();
                        if (turn.previous) {
                            auto [ec] = co_await turn.wake->async_receive(
                                net::bind_allocator(memory::ThreadLocalAllocator<std::byte>{},
                                    net::as_tuple(net::use_awaitable)));
                            if (ec) throw IoSystemError(io_error::operation_aborted);
                            CheckCancellation(epoch);
                        }
                        const auto size = co_await tcp->AsyncWrite(net::buffer(call.output));
                        if (size != call.output.size())
                            throw IoSystemError(io_error::broken_pipe);
                        CheckCancellation(epoch);
                    } catch (...) {
                        Abort();
                        throw;
                    }
                }
                if (result > 0) co_return result;
                // TLS close_notify sends our half-close without waiting for the
                // peer's half. Its later data must remain available to SSL_read.
                if (kind == Kind::Shutdown &&
                    (SSL_get_shutdown(ssl.get()) & SSL_SENT_SHUTDOWN) != 0)
                    co_return 0;
                if (kind == Kind::Read && error == SSL_ERROR_ZERO_RETURN) co_return 0;
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                    Fail(call);
                if (error == SSL_ERROR_WANT_WRITE && call.output.empty()) Fail(call);
            } // Ciphertext is released before a readable wait.
            if (error == SSL_ERROR_WANT_READ) {
                // WANT_READ has no partially accepted BIO output. Another
                // direction may consume/advance the handshake while this
                // operation retains its original SSL_write retry arguments.
                lease.Reset();
                co_await WaitForInput(epoch, generation);
                if (!lease) {
                    lease = engine_gate.TryAcquire();
                    if (!lease) lease = co_await engine_gate.Acquire();
                    CheckCancellation(epoch);
                    if (!lease) throw IoSystemError(io_error::operation_aborted);
                }
            }
        }
    }

    net::awaitable<int> Read(net::mutable_buffer target, buf::BufferGuard* allocated) {
        ActiveDirection active(read_active);
        if ((SSL_get_shutdown(ssl.get()) & SSL_RECEIVED_SHUTDOWN) != 0) co_return 0;
        // Socket wait has no payload allocation. Always retry SSL first when its
        // reusable read buffer contains a record or retained plaintext.
        if (allocated && SSL_pending(ssl.get()) == 0 && SSL_has_pending(ssl.get()) == 0)
            co_await WaitForInput(cancel_epoch, input_generation);
        co_return co_await Perform(Kind::Read, target, {}, allocated);
    }

    net::awaitable<void> Write(std::span<const net::const_buffer> buffers) {
        ActiveDirection active(write_active);
        try {
            for (auto buffer : buffers) {
                while (buffer.size() != 0) {
                    // Bound each application operation's output independently
                    // of the caller's payload size and keep SSL retries stable.
                    const auto fragment = net::buffer(
                        buffer, std::min<std::size_t>(buffer.size(), buf::Buffer::kSize));
                    const int n = co_await Perform(Kind::Write, {}, fragment);
                    buffer += static_cast<std::size_t>(n);
                }
            }
        } catch (...) {
            // A cancelled/failed logical frame may already have sent records.
            // Never reuse that byte transport with an incomplete frame.
            Abort();
            throw;
        }
    }

    std::unique_ptr<TcpStream> tcp;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl;
    Gate engine_gate;
    Gate input_gate;
    std::unique_ptr<PendingReadData> pending_read;
    Invocation* invocation = nullptr; // Borrowed only inside one synchronous SSL call.
    OutputTurn* output_tail = nullptr;
    net::cancellation_signal* input_wait = nullptr;
    std::uint64_t input_generation = 0;
    std::uint64_t cancel_epoch = 0;
    bool read_active = false;
    bool write_active = false;
    bool handshaking = false;
};

void TlsStream::InitializeIo() {
    if (tls_bio_method) return;
    std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)> method(
        BIO_meth_new(BIO_TYPE_SOURCE_SINK, "cnode nonblocking TLS"), BIO_meth_free);
    if (!method ||
        BIO_meth_set_read(method.get(), Impl::BioRead) != 1 ||
        BIO_meth_set_write(method.get(), Impl::BioWrite) != 1 ||
        BIO_meth_set_ctrl(method.get(), Impl::BioControl) != 1)
        throw std::bad_alloc();
    tls_bio_method = std::move(method);
}

TlsStream::TlsStream(std::unique_ptr<TcpStream> inner, SSL_CTX* ctx, bool is_server)
    : impl_(std::make_unique<Impl>(std::move(inner), ctx, is_server))
    , is_server_(is_server) {}

TlsStream::~TlsStream() = default;

TlsStream::TlsStream(TlsStream&& other) noexcept
    : impl_(std::move(other.impl_))
    , is_server_(other.is_server_)
    , handshake_done_(other.handshake_done_)
    , shutdown_initiated_(other.shutdown_initiated_)
    , reality_client_state_(std::move(other.reality_client_state_)) {
    other.shutdown_initiated_ = true;
}

TlsStream& TlsStream::operator=(TlsStream&& other) noexcept {
    if (this != &other) {
        impl_ = std::move(other.impl_);
        is_server_ = other.is_server_;
        handshake_done_ = other.handshake_done_;
        shutdown_initiated_ = other.shutdown_initiated_;
        reality_client_state_ = std::move(other.reality_client_state_);
        other.shutdown_initiated_ = true;
    }
    return *this;
}

SSL* TlsStream::NativeSsl() noexcept {
    return impl_ ? impl_->ssl.get() : nullptr;
}

const SSL* TlsStream::NativeSsl() const noexcept {
    return impl_ ? impl_->ssl.get() : nullptr;
}

TcpStream* TlsStream::BaseTcpStream() {
    return impl_ ? impl_->tcp.get() : nullptr;
}

const TcpStream* TlsStream::BaseTcpStream() const {
    return impl_ ? impl_->tcp.get() : nullptr;
}

bool TlsStream::SetServerIdentity(std::string_view identity) {
    SSL* ssl = NativeSsl();
    return !is_server_ && ConfigureTlsServerIdentity(ssl, identity);
}

bool TlsStream::SetAlpn(std::span<const std::string> protocols) {
    SSL* ssl = NativeSsl();
    if (!ssl) return false;

    memory::ByteVector alpn;
    if (!EncodeTlsAlpnProtocols(protocols, alpn)) return false;
    return SSL_set_alpn_protos(ssl, alpn.data(), alpn.size()) == 0;
}

net::awaitable<bool> TlsStream::Handshake() {
    if (handshake_done_) {
        co_return true;
    }
    if (!impl_ || !impl_->tcp->IsOpen()) co_return false;
    Impl::ActiveDirection active(impl_->handshaking);

    struct RealityHandshakeCleanup {
        TlsStream& self;
        ~RealityHandshakeCleanup() noexcept {
            SSL* ssl = self.NativeSsl();
            ClearRealityClientState(ssl, self.reality_client_state_);
            if (self.is_server_) {
                ClearRealityServerConnState(ssl);
            }
        }
    } reality_cleanup{*this};

    try {
        (void)co_await impl_->Perform(Impl::Kind::Handshake);
    } catch (const IoSystemError& error) {
        const auto& ec = error.code();
        if (is_server_ && ec.category() == net::error::get_ssl_category() &&
            IsBenignServerHandshakeError(static_cast<unsigned long>(ec.value()))) {
            LOG_NET_DEBUG("TLS handshake ignored (non-TLS traffic on TLS port): {}", ec.message());
        } else {
            LOG_NET_WARN("TLS handshake error: {}", ec.message());
        }
        impl_->Abort();
        co_return false;
    }

    if (reality_client_state_ &&
        !VerifyRealityClientHandshake(NativeSsl(), *reality_client_state_)) {
        if (!reality_client_state_->spider_x.empty()) {
            const std::string_view host = reality_client_state_->server_name.empty()
                ? std::string_view("localhost")
                : std::string_view(reality_client_state_->server_name);
            static constexpr std::string_view kReqPrefix = "GET ";
            static constexpr std::string_view kReqMid = " HTTP/1.1\r\nHost: ";
            static constexpr std::string_view kReqSuffix =
                "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Connection: close\r\n\r\n";
            const std::array<net::const_buffer, 5> request_buffers{
                net::buffer(kReqPrefix.data(), kReqPrefix.size()),
                net::buffer(reality_client_state_->spider_x.data(),
                            reality_client_state_->spider_x.size()),
                net::buffer(kReqMid.data(), kReqMid.size()),
                net::buffer(host.data(), host.size()),
                net::buffer(kReqSuffix.data(), kReqSuffix.size()),
            };
            try {
                co_await impl_->Write(request_buffers);
                buf::BufferGuard drain;
                (void)co_await impl_->Read({}, &drain);
            } catch (const IoSystemError&) {
                // The camouflage exchange is best-effort; authentication still
                // fails regardless of the origin's response or close behavior.
            }
        }
        impl_->Abort();
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

void TlsStream::PrependReadData(std::span<const uint8_t> data) {
    if (data.empty()) return;
    if (!impl_ || !impl_->tcp->CanRead()) {
        throw IoSystemError(io_error::operation_aborted, "TLS read closed");
    }
    buf::MultiBuffer prefix;
    if (!buf::AppendSpanToMultiBuffer(data, prefix)) {
        throw std::bad_alloc();
    }
    if (impl_->pending_read) {
        impl_->pending_read->data.MoveTo(prefix);
    } else {
        impl_->pending_read = std::make_unique<Impl::PendingReadData>();
    }
    impl_->pending_read->data = std::move(prefix);
}

net::awaitable<std::size_t> TlsStream::AsyncRead(net::mutable_buffer buffer) {
    if (!impl_ || !impl_->tcp->CanRead() || buffer.size() == 0) co_return 0;
    if (impl_->pending_read) {
        const auto n = impl_->pending_read->data.ConsumePrefixTo(
            std::span<uint8_t>(static_cast<uint8_t*>(buffer.data()), buffer.size()));
        if (impl_->pending_read->data.empty()) impl_->pending_read.reset();
        co_return n;
    }
    if (!handshake_done_ && !co_await Handshake())
        ThrowTlsReadError("TLS handshake failed during read");
    try {
        co_return static_cast<std::size_t>(co_await impl_->Read(buffer, nullptr));
    } catch (const IoSystemError& error) {
        if (error.code() == io_error::eof && !impl_->tcp->CanRead()) co_return 0;
        throw;
    }
}

net::awaitable<buf::MultiBuffer> TlsStream::ReadMultiBuffer() {
    if (!impl_ || !impl_->tcp->CanRead()) co_return buf::MultiBuffer{};
    if (impl_->pending_read) {
        auto data = std::move(impl_->pending_read->data);
        impl_->pending_read.reset();
        co_return data;
    }
    if (!handshake_done_ && !co_await Handshake())
        ThrowTlsReadError("TLS handshake failed during read");
    buf::BufferGuard out;
    try {
        const int n = co_await impl_->Read({}, &out);
        if (n == 0) co_return buf::MultiBuffer{};
        out->Produce(static_cast<uint32_t>(n));
        co_return buf::MultiBuffer{std::move(out)};
    } catch (const IoSystemError& error) {
        if (error.code() == io_error::eof && !impl_->tcp->CanRead())
            co_return buf::MultiBuffer{};
        throw;
    }
}

net::awaitable<std::size_t> TlsStream::AsyncWrite(net::const_buffer buffer) {
    const std::array buffers{buffer};
    co_await WriteBuffers(buffers);
    co_return buffer.size();
}

net::awaitable<void> TlsStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (!impl_ || !impl_->tcp->CanWrite() || shutdown_initiated_)
        throw IoSystemError(io_error::broken_pipe);
    if (!handshake_done_ && !co_await Handshake())
        ThrowTlsWriteError("TLS handshake failed during write");
    if (buffers.empty()) co_return;
    if (impl_->tcp->IsWriteCancellationDeferred()) {
        // Isolate the whole physical frame, not just individual socket writes:
        // coroutine cancellation must not abandon later TLS records mid-frame.
        co_await net::co_spawn(impl_->tcp->GetExecutor(), impl_->Write(buffers),
            net::bind_cancellation_slot(net::cancellation_slot{},
                net::bind_allocator(memory::ThreadLocalAllocator<std::byte>{},
                    net::use_awaitable)));
    } else {
        co_await impl_->Write(buffers);
    }
}

net::awaitable<void> TlsStream::WriteMultiBuffer(buf::MultiBuffer mb) {
    if (!buf::HasData(mb)) co_return;
    ConstBufferSpanBuilder<8> buffers;
    buffers.AppendMultiBuffer(mb);
    co_await WriteBuffers(buffers.Span());
}

void TlsStream::ShutdownRead() {
    if (impl_) {
        impl_->pending_read.reset();
        impl_->tcp->ShutdownRead();
    }
}

void TlsStream::ShutdownWrite() {
    if (handshake_done_ && !shutdown_initiated_) {
        shutdown_initiated_ = true;
    }
    if (impl_) {
        impl_->tcp->ShutdownWrite();
    }
}

net::awaitable<void> TlsStream::AsyncShutdownWrite() {
    if (!impl_ || shutdown_initiated_) co_return;
    if (impl_->handshaking) throw std::logic_error("TLS shutdown during handshake");
    shutdown_initiated_ = true;
    if (handshake_done_ && impl_->tcp->CanWrite()) {
        Impl::ActiveDirection active(impl_->write_active);
        try {
            (void)co_await impl_->Perform(Impl::Kind::Shutdown);
        } catch (...) {
            impl_->Abort();
            throw;
        }
    }
    impl_->tcp->ShutdownWrite();
}

void TlsStream::Close() {
    NotifyClosed();
    shutdown_initiated_ = true;
    if (impl_) {
        impl_->pending_read.reset();
        impl_->tcp->Close();
    }
}

void TlsStream::CloseAbortive() {
    NotifyClosed();
    shutdown_initiated_ = true;
    if (impl_) {
        impl_->pending_read.reset();
        impl_->Abort();
    }
}

void TlsStream::Cancel() noexcept {
    NotifyCancellation();
    if (impl_) {
        impl_->tcp->Cancel();
    }
}

int TlsStream::NativeHandle() const {
    return impl_ ? impl_->tcp->NativeHandle() : -1;
}

bool TlsStream::IsOpen() const {
    return impl_ && impl_->tcp->IsOpen() && NativeSsl() != nullptr;
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
    std::string_view server_name,
    std::span<const std::string> alpn) {

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
    std::string_view server_name,
    std::span<const std::string> alpn) {

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
}  // namespace acpp
