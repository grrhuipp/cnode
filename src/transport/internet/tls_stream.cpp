#include "transport/internet/tls_stream.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "tls_client_context.hpp"
#include "reality_tls.hpp"
#include "transport/internet/async_write_gate.hpp"
#include "transport/internet/stream_settings.hpp"
#include "transport/internet/transport_security.hpp"
#include "common/buffer_util.hpp"
#include "infra/log.hpp"
#include "common/unsafe.hpp"
#include "autosign_cert.hpp"
#include "autosign_context.hpp"
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
#include <format>
#include <optional>
#include <stdexcept>


// ============================================================================
// SslContext 实现
// ============================================================================

namespace {

[[nodiscard]] bool AlpnWireContains(
    const unsigned char* wire, unsigned int size, std::string_view protocol) noexcept {
    for (unsigned int offset = 0; offset < size;) {
        const unsigned int length = wire[offset++];
        if (size - offset < length) return false;
        if (std::string_view(unsafe::ptr_cast<const char>(wire + offset), length) == protocol) {
            return true;
        }
        offset += length;
    }
    return false;
}

// RFC 7301 §3.2: without a common protocol the server answers with a fatal
// no_application_protocol alert. Like Go crypto/tls (the Xray server), an
// h2 server still accepts an http/1.1-only client without selecting ALPN.
int SelectServerAlpnCallback(
    SSL* /*ssl*/,
    const unsigned char** out,
    unsigned char* outlen,
    const unsigned char* in,
    unsigned int inlen,
    void* arg) {
    const auto& configured = *static_cast<const std::vector<unsigned char>*>(arg);
    unsigned char* selected = nullptr;
    const int rc = SSL_select_next_proto(
        &selected,
        outlen,
        configured.data(),
        static_cast<unsigned int>(configured.size()),
        in,
        inlen);
    if (rc == OPENSSL_NPN_NEGOTIATED) {
        *out = selected;
        return SSL_TLSEXT_ERR_OK;
    }
    const bool http11_fallback =
        AlpnWireContains(configured.data(), static_cast<unsigned int>(configured.size()), "h2") &&
        AlpnWireContains(in, inlen, "http/1.1");
    return http11_fallback ? SSL_TLSEXT_ERR_NOACK : SSL_TLSEXT_ERR_ALERT_FATAL;
}

}  // namespace

std::unique_ptr<SslContext> SslContext::CreateServer(const TlsConfig& config) {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        LOG_ERROR("failed to create TLS server context");
        return nullptr;
    }

    if (!ConfigureTlsProtocolVersions(
            ctx, config.min_version, config.max_version)) {
        LOG_ERROR("invalid TLS server protocol version policy");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (!config.pem) {
        LOG_ERROR("TLS certificate files were not loaded with the configuration");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (!ConfigureTlsCertificatePem(ctx, *config.pem)) {
        LOG_ERROR("failed to load TLS certificate from {}", config.cert_file);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    auto out = std::unique_ptr<SslContext>(new SslContext(ctx));
    if (!out->ConfigureServerAlpn(config.alpn)) {
        LOG_ERROR("invalid TLS server ALPN policy");
        return nullptr;
    }
    return out;
}

// ============================================================================
// 自动签名：启动时为配置域名生成固定自签证书
// ============================================================================

namespace {

[[noreturn]] void ThrowTlsHandshakeFailure(const char* what) {
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


}  // namespace

std::unique_ptr<SslContext> SslContext::CreateServerAutoSign(const TlsConfig& config) {
    auto context = CreateAutoSignSnapshot(config);
    if (!context) return {};
    context->renewal_ = AutoSignContextRenewal::Start(
        std::move(context->native_owner_), [config] {
            auto replacement = CreateAutoSignSnapshot(config);
            return replacement ? std::move(replacement->native_owner_) : std::shared_ptr<SSL_CTX>{};
        });
    context->ctx_ = nullptr;
    context->shared_state_ = nullptr;
    return context;
}

std::shared_ptr<SSL_CTX> SslContext::AcquireNative() const noexcept {
    return renewal_ ? renewal_->Acquire() : native_owner_;
}

std::unique_ptr<SslContext> SslContext::CreateAutoSignSnapshot(const TlsConfig& config) {
    const std::string default_name = ResolveAutoSignDefaultName(config);
    auto material = transport::internet::AutoSignCertificate::Create(default_name);
    if (!material) {
        LOG_ERROR("failed to generate default self-signed TLS certificate");
        return nullptr;
    }

    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return nullptr;

    if (!ConfigureTlsProtocolVersions(
            ctx, config.min_version, config.max_version)) {
        LOG_ERROR("invalid auto-sign TLS protocol version policy");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (SSL_CTX_use_certificate(ctx, material->Certificate()) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, material->Key()) != 1) {
        LOG_ERROR("failed to install default self-signed TLS certificate");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    LOG_INFO("TLS auto-sign certificate created (domain={} validity=one year renewal=30 days before expiry)",
             default_name);
    auto out = std::unique_ptr<SslContext>(new SslContext(ctx));
    if (!out->ConfigureServerAlpn(config.alpn)) {
        LOG_ERROR("invalid auto-sign TLS ALPN policy");
        return nullptr;
    }
    return out;
}

bool SslContext::ConfigureServerAlpn(
    const std::vector<std::string>& protocols) {
    auto& wire = shared_state_->server_alpn_wire;
    if (!EncodeTlsAlpnProtocols(protocols, wire)) return false;

    if (!wire.empty()) {
        SSL_CTX_set_alpn_select_cb(ctx_, SelectServerAlpnCallback, &wire);
    }
    return true;
}

// ============================================================================
// TransportSecurity 实现
// ============================================================================

namespace {

[[nodiscard]] std::unique_ptr<SslContext> CreateSecurityContext(
    const StreamSettings& settings, StreamEndpointRole role) {
    if (role == StreamEndpointRole::Inbound) {
        if (settings.IsReality()) {
            return SslContext::CreateServerReality(settings.reality, settings.tls);
        }
        return settings.tls.HasCertificatePair()
            ? SslContext::CreateServer(settings.tls)
            : SslContext::CreateServerAutoSign(settings.tls);
    }
    return settings.IsReality()
        ? SslContext::CreateClientReality(settings.reality, settings.tls)
        : SslContext::CreateClient(settings.tls);
}

}  // namespace

TransportSecurity::TransportSecurity(
    const StreamSettings& settings, StreamEndpointRole role) : role_(role) {
    if (settings.prepared_security && settings.prepared_security->role_ == role) {
        context_ = settings.prepared_security->context_;
        xhttp_download_ = settings.prepared_security->xhttp_download_;
        return;
    }
    if (settings.IsTlsLike()) {
        context_ = CreateSecurityContext(settings, role);
        if (!context_) {
            throw std::invalid_argument(std::format(
                "cannot build {} {} context",
                settings.IsReality() ? "REALITY" : "TLS",
                role == StreamEndpointRole::Inbound ? "server" : "client"));
        }
    }
    if (role == StreamEndpointRole::Outbound && settings.IsXHttp() &&
        settings.xhttp.download_settings) {
        xhttp_download_ = std::make_shared<TransportSecurity>(
            settings.xhttp.download_settings->stream_settings,
            StreamEndpointRole::Outbound);
    }
}

TransportSecurity::~TransportSecurity() = default;

void TransportSecurity::Prepare(StreamSettings& settings, StreamEndpointRole role) {
    // Build independently first; a failed replacement leaves the published
    // configuration intact. Avoid inheriting a stale prepared context when a
    // caller updates TLS/REALITY fields in a copied settings object.
    auto source = settings;
    source.prepared_security.reset();
    settings.prepared_security = std::make_shared<TransportSecurity>(source, role);
}

// ============================================================================
// TlsStream 实现
// ============================================================================

namespace {

// Populated explicitly before Worker startup. BIO_METHOD and SSL-owned memory
// stay with the library allocator; only our operation payload uses Worker PMR.
std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)> tls_bio_method{nullptr, BIO_meth_free};

}  // namespace

struct TlsStream::Impl final : memory::ThreadAllocated, private transport::CancellationSubscription {
    using Gate = transport::internet::AsyncWriteGate;
    enum class Kind { Handshake, Read, Write, Shutdown };

    struct Invocation {
        // Only unsent ciphertext needs owned storage; bound handshake flights
        // and never retain a library buffer across another SSL call.
        static constexpr std::size_t kOutputLimit = 64 * 1024;
        std::optional<memory::ByteVector> output;
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

    // Decrypted read-ahead returned by a handshake consumer. Heap-held so an
    // idle connection without read-ahead carries no MultiBuffer state.
    struct PrependedPlaintext : memory::ThreadAllocated {
        buf::MultiBuffer data;
    };

    Impl(std::unique_ptr<TcpStream> inner, const SslContext& context, bool server)
        : tcp(std::move(inner))
        , ssl(nullptr, SSL_free) {
        if (!tcp) throw std::invalid_argument("TlsStream requires TcpStream");
        if (!tls_bio_method)
            throw std::logic_error("TlsStream::InitializeIo must precede Worker startup");
        tcp->PrepareTlsIo();
        const auto snapshot = context.AcquireNative();
        if (!snapshot) throw std::runtime_error("TLS certificate expired without a renewed snapshot");
        ssl.reset(SSL_new(snapshot.get()));
        if (!ssl) throw std::bad_alloc();
        SSL_set_mode(ssl.get(), SSL_MODE_RELEASE_BUFFERS);
        SSL_set_read_ahead(ssl.get(), 0);
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

    ::tcp::socket::executor_type Executor() {
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
        if (self.raw_read) {
            self.invocation->transport_error = io_error::operation_not_supported;
            return -1;
        }
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
        const auto queued = call.output ? call.output->size() : 0;
        const auto count = std::min<std::size_t>(
            size, Invocation::kOutputLimit - queued);
        if (count == 0) {
            BIO_set_retry_write(bio);
            return -1;
        }
        std::size_t sent = 0;
        if (!self.output_tail && !call.output) {
            // The engine lease excludes other SSL calls. Once output has been
            // queued, even a new control record must stay behind that turn.
            const auto buffer = net::buffer(data, count);
            IoErrorCode error;
            sent = self.tcp->WriteAvailable(
                std::span<const net::const_buffer>(&buffer, 1), 0, error);
            if (error && error != io_error::would_block &&
                error != io_error::try_again && error != io_error::interrupted) {
                call.transport_error = error;
                return -1;
            }
            if (sent == count) return static_cast<int>(count);
        }
        try {
            if (!call.output) call.output.emplace();
            auto& output = *call.output;
            const auto required = output.size() + count - sent;
            if (required > output.capacity())
                output.reserve(std::min(Invocation::kOutputLimit,
                    std::max(required, output.capacity() * 2)));
            const auto* first = reinterpret_cast<const uint8_t*>(data);
            output.insert(output.end(), first + sent, first + count);
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

    net::awaitable<void> WaitForInput(std::uint64_t epoch, std::uint64_t generation,
                                      bool deferred = false) {
        // The other direction may advance SSL while this operation waits for
        // the single TCP read deadline. Retry SSL instead of waiting for a new
        // network edge when its state has already changed.
        auto lease = input_gate.TryAcquire();
        if (!lease) lease = co_await input_gate.Acquire(deferred);
        CheckCancellation(epoch);
        if (!lease) throw IoSystemError(io_error::operation_aborted);
        if (generation != input_generation) co_return;
        const auto cancellation = co_await net::this_coro::cancellation_state;
        InputWait waiting(*this, deferred ? net::cancellation_slot{} : cancellation.slot());
        const auto ec = co_await tcp->WaitReadable(waiting.wake.slot());
        CheckCancellation(epoch);
        if (!deferred && cancellation.cancelled() != net::cancellation_type::none)
            throw IoSystemError(io_error::operation_aborted);
        if (ec == io_error::operation_aborted && generation != input_generation) co_return;
        if (ec) throw IoSystemError(ec);
    }

    net::awaitable<int> Perform(
        Kind kind, net::mutable_buffer target = {}, net::const_buffer source = {},
        buf::BufferGuard* allocated = nullptr) {
        const auto epoch = cancel_epoch;
        const bool deferred = (kind == Kind::Write && tcp->IsWriteCancellationDeferred());
        auto lease = engine_gate.TryAcquire();
        if (!lease) lease = co_await engine_gate.Acquire(deferred);
        CheckCancellation(epoch);
        if (!lease) throw IoSystemError(io_error::operation_aborted);
        for (;;) {
            // A local receive shutdown is not a truncated peer TLS record.
            // Recheck after input/engine waits before SSL or buffer allocation.
            if (kind == Kind::Read && !tcp->CanRead()) co_return 0;
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
                // A failed direct send is terminal even if SSL has already set
                // SSL_SENT_SHUTDOWN while constructing close_notify.
                if (call.failure || call.transport_error) Fail(call);
                // Synchronous transport progress may retire the connection
                // while reconciling its activity deadline.
                CheckCancellation(epoch);
                // No empty relay buffer survives a read retry, even when TLS
                // consumed only a partial record or a post-handshake message.
                if (allocated && result <= 0 && error == SSL_ERROR_WANT_READ)
                    *allocated = {};
                const bool shutdown_sent = kind == Kind::Shutdown &&
                    (SSL_get_shutdown(ssl.get()) & SSL_SENT_SHUTDOWN) != 0;
                if (call.output) {
                    try {
                        // Reserve the physical turn before the first suspension
                        // or another SSL call can generate a subsequent record.
                        OutputTurn turn(*this);
                        if (result > 0 || shutdown_sent || error == SSL_ERROR_WANT_READ)
                            lease.Reset();
                        if (turn.previous) {
                            IoErrorCode ec;
                            if (deferred) {
                                std::tie(ec) = co_await turn.wake->async_receive(
                                    net::bind_cancellation_slot(
                                        net::cancellation_slot{},
                                        net::bind_allocator(memory::ProcessAllocator<std::byte>{},
                                            net::as_tuple(net::use_awaitable))));
                            } else {
                                std::tie(ec) = co_await turn.wake->async_receive(
                                    net::bind_allocator(memory::ProcessAllocator<std::byte>{},
                                        net::as_tuple(net::use_awaitable)));
                            }
                            if (ec) throw IoSystemError(io_error::operation_aborted);
                            CheckCancellation(epoch);
                        }
                        const auto size = co_await tcp->AsyncWrite(net::buffer(*call.output));
                        if (size != call.output->size())
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
                if (shutdown_sent) co_return 0;
                if (kind == Kind::Read && error == SSL_ERROR_ZERO_RETURN) co_return 0;
                if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
                    Fail(call);
                if (error == SSL_ERROR_WANT_WRITE && !call.output) Fail(call);
            } // Ciphertext is released before a readable wait.
            if (error == SSL_ERROR_WANT_READ) {
                // WANT_READ has no partially accepted BIO output. Another
                // direction may consume/advance the handshake while this
                // operation retains its original SSL_write retry arguments.
                lease.Reset();
                co_await WaitForInput(epoch, generation, deferred);
                if (!lease) {
                    lease = engine_gate.TryAcquire();
                    if (!lease) lease = co_await engine_gate.Acquire(deferred);
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
            // Bound each application operation's output independently of the
            // caller's payload size and keep SSL retries stable. A fragment is
            // packed across caller buffers: one frame's header and payload
            // share a record and a TCP send, rather than leaving the payload
            // record behind the header under Nagle until the peer's delayed ACK.
            buf::BufferGuard staging;
            std::size_t index = 0;
            std::size_t offset = 0;
            const auto skip_empty = [&] {
                while (index != buffers.size() && offset == buffers[index].size()) {
                    ++index;
                    offset = 0;
                }
            };
            skip_empty();
            while (index != buffers.size()) {
                const auto current = buffers[index] + offset;
                net::const_buffer fragment;
                if (current.size() >= buf::Buffer::kSize || index + 1 == buffers.size()) {
                    fragment = net::buffer(
                        current, std::min<std::size_t>(current.size(), buf::Buffer::kSize));
                } else {
                    if (!staging) {
                        staging = buf::BufferGuard{buf::Buffer::New()};
                        if (!staging) throw std::bad_alloc();
                    }
                    const auto target = staging->Tail();
                    std::size_t packed = 0;
                    for (auto i = index, at = offset;
                         i != buffers.size() && packed != target.size(); ++i, at = 0) {
                        const auto piece = buffers[i] + at;
                        packed += net::buffer_copy(
                            net::buffer(target.data() + packed, target.size() - packed), piece);
                    }
                    fragment = net::buffer(target.data(), packed);
                }
                auto n = static_cast<std::size_t>(co_await Perform(Kind::Write, {}, fragment));
                while (n != 0) {
                    const auto step = std::min(n, buffers[index].size() - offset);
                    offset += step;
                    n -= step;
                    skip_empty();
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
    std::unique_ptr<PrependedPlaintext> prepended_plaintext;
    Invocation* invocation = nullptr; // Borrowed only inside one synchronous SSL call.
    OutputTurn* output_tail = nullptr;
    net::cancellation_signal* input_wait = nullptr;
    std::uint64_t input_generation = 0;
    std::uint64_t cancel_epoch = 0;
    bool read_active = false;
    bool write_active = false;
    bool handshaking = false;
    bool raw_read = false;
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

TlsStream::TlsStream(std::unique_ptr<TcpStream> inner, const SslContext& ctx, bool is_server)
    : impl_(std::make_unique<Impl>(std::move(inner), ctx, is_server))
    , is_server_(is_server) {}

TlsStream::~TlsStream() = default;

// impl_, its TcpStream and its SSL exist from construction until destruction.
SSL* TlsStream::NativeSsl() noexcept {
    return impl_->ssl.get();
}

const SSL* TlsStream::NativeSsl() const noexcept {
    return impl_->ssl.get();
}

TcpStream* TlsStream::BaseTcpStream() {
    return impl_->tcp.get();
}

const TcpStream* TlsStream::BaseTcpStream() const {
    return impl_->tcp.get();
}

bool TlsStream::SetServerIdentity(std::string_view identity) {
    return !is_server_ && ConfigureTlsServerIdentity(NativeSsl(), identity);
}

net::awaitable<bool> TlsStream::Handshake() {
    if (handshake_done_) {
        co_return true;
    }
    if (!impl_->tcp->IsOpen()) co_return false;
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
        if (ec == io_error::operation_aborted || ec == io_error::eof ||
            ec == net::ssl::error::stream_truncated) {
            LOG_NET_DEBUG("TLS handshake ended > {}", ec.message());
        } else if (is_server_ && ec.category() == net::error::get_ssl_category() &&
                   IsBenignServerHandshakeError(static_cast<unsigned long>(ec.value()))) {
            LOG_NET_DEBUG("TLS handshake ignored (non-TLS traffic on TLS port) > {}", ec.message());
        } else {
            LOG_NET_WARN("TLS handshake failed > {}", ec.message());
        }
        impl_->Abort();
        co_return false;
    }

    if (reality_client_state_ &&
        !VerifyRealityClientHandshake(NativeSsl(), *reality_client_state_)) {
        memory::ThreadLocalString spider_x = std::move(reality_client_state_->spider_x);
        memory::ThreadLocalString server_name = std::move(reality_client_state_->server_name);
        if (server_name.empty()) {
            if (const char* sni = SSL_get_servername(
                    NativeSsl(), TLSEXT_NAMETYPE_host_name);
                sni && *sni != '\0') {
                server_name.assign(sni);
            }
        }
        ClearRealityClientState(NativeSsl(), reality_client_state_);
        if (!spider_x.empty()) {
            const std::string_view host = server_name.empty()
                ? std::string_view("localhost")
                : std::string_view(server_name);
            static constexpr std::string_view kReqPrefix = "GET ";
            static constexpr std::string_view kReqMid = " HTTP/1.1\r\nHost: ";
            static constexpr std::string_view kReqSuffix =
                "\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
                "Connection: close\r\n\r\n";
            const std::array<net::const_buffer, 5> request_buffers{
                net::buffer(kReqPrefix.data(), kReqPrefix.size()),
                net::buffer(spider_x.data(), spider_x.size()),
                net::buffer(kReqMid.data(), kReqMid.size()),
                net::buffer(host.data(), host.size()),
                net::buffer(kReqSuffix.data(), kReqSuffix.size()),
            };
            try {
                co_await impl_->Write(request_buffers);
                memory::ThreadLocalString{}.swap(spider_x);
                memory::ThreadLocalString{}.swap(server_name);
                buf::BufferGuard drain;
                (void)co_await impl_->Read({}, &drain);
            } catch (const std::exception&) {
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

std::string_view TlsStream::NegotiatedAlpn() const {
    const SSL* ssl = NativeSsl();

    const unsigned char* data = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl, &data, &len);

    if (data && len > 0) {
        return std::string_view(unsafe::ptr_cast<const char>(data), len);
    }
    return {};
}

bool TlsStream::EnableRawRead() noexcept {
    if (!handshake_done_ || impl_->handshaking || impl_->read_active ||
        impl_->invocation || !impl_->tcp->CanRead()) return false;
    // With read-ahead disabled, completed SSL_read never fetches the next
    // record. Refuse an outstanding partial encrypted record rather than
    // losing it or mistaking it for raw Vision bytes.
    if (SSL_has_pending(NativeSsl()) && SSL_pending(NativeSsl()) == 0) return false;
    impl_->raw_read = true;
    return true;
}

void TlsStream::PrependReadData(std::span<const uint8_t> data) {
    if (data.empty()) return;
    if (!impl_->tcp->CanRead()) {
        throw IoSystemError(io_error::operation_aborted, "TLS read closed");
    }
    buf::MultiBuffer prefix;
    if (!buf::AppendSpanToMultiBuffer(data, prefix)) {
        throw std::bad_alloc();
    }
    if (impl_->prepended_plaintext) {
        impl_->prepended_plaintext->data.MoveTo(prefix);
    } else {
        impl_->prepended_plaintext = std::make_unique<Impl::PrependedPlaintext>();
    }
    impl_->prepended_plaintext->data = std::move(prefix);
}

net::awaitable<std::size_t> TlsStream::AsyncRead(net::mutable_buffer buffer) {
    if (!impl_->tcp->CanRead() || buffer.size() == 0) co_return 0;
    if (impl_->prepended_plaintext) {
        const auto n = impl_->prepended_plaintext->data.ConsumePrefixTo(
            std::span<uint8_t>(static_cast<uint8_t*>(buffer.data()), buffer.size()));
        if (impl_->prepended_plaintext->data.empty()) impl_->prepended_plaintext.reset();
        co_return n;
    }
    if (!handshake_done_ && !co_await Handshake())
        ThrowTlsHandshakeFailure("TLS handshake failed during read");
    if (impl_->raw_read && SSL_pending(NativeSsl()) == 0) {
        Impl::ActiveDirection active(impl_->read_active);
        co_return co_await impl_->tcp->AsyncRead(buffer);
    }
    try {
        co_return static_cast<std::size_t>(co_await impl_->Read(buffer, nullptr));
    } catch (const IoSystemError& error) {
        if (error.code() == io_error::eof && !impl_->tcp->CanRead()) co_return 0;
        throw;
    }
}

net::awaitable<buf::MultiBuffer> TlsStream::ReadMultiBuffer() {
    if (!impl_->tcp->CanRead()) co_return buf::MultiBuffer{};
    if (impl_->prepended_plaintext) {
        auto data = std::move(impl_->prepended_plaintext->data);
        impl_->prepended_plaintext.reset();
        co_return data;
    }
    if (!handshake_done_ && !co_await Handshake())
        ThrowTlsHandshakeFailure("TLS handshake failed during read");
    if (impl_->raw_read && SSL_pending(NativeSsl()) == 0) {
        Impl::ActiveDirection active(impl_->read_active);
        co_return co_await impl_->tcp->ReadMultiBuffer();
    }
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
    if (!impl_->tcp->CanWrite() || shutdown_initiated_)
        throw IoSystemError(io_error::broken_pipe);
    if (!handshake_done_ && !co_await Handshake())
        ThrowTlsHandshakeFailure("TLS handshake failed during write");
    while (!buffers.empty() && buffers.front().size() == 0) buffers = buffers.subspan(1);
    if (buffers.empty()) co_return;
    if (impl_->tcp->IsWriteCancellationDeferred()) {
        // Isolate the whole physical frame, not just individual socket writes:
        // coroutine cancellation must not abandon later TLS records mid-frame.
        const bool previous_throw = co_await net::this_coro::throw_if_cancelled();
        co_await net::this_coro::throw_if_cancelled(false);
        std::exception_ptr failure;
        try {
            co_await impl_->Write(buffers);
        } catch (...) {
            failure = std::current_exception();
        }
        co_await net::this_coro::throw_if_cancelled(previous_throw);
        if (failure) std::rethrow_exception(failure);
    } else {
        co_await impl_->Write(buffers);
    }
}

void TlsStream::ShutdownRead() {
    impl_->prepended_plaintext.reset();
    impl_->tcp->ShutdownRead();
}

void TlsStream::ShutdownWrite() {
    if (handshake_done_ && !shutdown_initiated_) {
        shutdown_initiated_ = true;
    }
    impl_->tcp->ShutdownWrite();
}

net::awaitable<void> TlsStream::AsyncShutdownWrite() {
    if (shutdown_initiated_) co_return;
    if (impl_->handshaking) throw std::logic_error("TLS shutdown during handshake");
    shutdown_initiated_ = true;
    // Vision cmd2 removes the outer TLS framing in the peer's raw direction.
    // An outer close_notify would then corrupt its inner TLS stream. Ordinary
    // opposite-direction SSL_write remains enabled until this half-close.
    if (handshake_done_ && impl_->tcp->CanWrite() && !impl_->raw_read) {
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
    impl_->prepended_plaintext.reset();
    impl_->tcp->Close();
}

void TlsStream::CloseAbortive() {
    NotifyClosed();
    shutdown_initiated_ = true;
    impl_->prepended_plaintext.reset();
    impl_->Abort();
}

void TlsStream::Cancel() noexcept {
    NotifyCancellation();
    impl_->tcp->Cancel();
}

int TlsStream::NativeHandle() const {
    return impl_->tcp->NativeHandle();
}

bool TlsStream::IsOpen() const {
    return impl_->tcp->IsOpen();
}


// ============================================================================
// 工厂函数实现
// ============================================================================

net::awaitable<std::unique_ptr<TlsStream>> WrapTlsServer(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx) {

    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx, true);

    if (!co_await stream->Handshake()) {
        co_return nullptr;
    }

    co_return stream;
}

net::awaitable<std::unique_ptr<TlsStream>> WrapTlsClient(
    std::unique_ptr<TcpStream> inner,
    SslContext& ctx,
    std::string_view server_name) {

    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx, false);

    if (!server_name.empty() && !stream->SetServerIdentity(server_name)) {
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
    std::string_view server_name) {

    auto stream = std::make_unique<TlsStream>(std::move(inner), ctx, false);

    const std::string_view effective_sni =
        server_name.empty() ? std::string_view(reality.server_name) : server_name;
    if (!effective_sni.empty() && !stream->SetServerIdentity(effective_sni)) {
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
