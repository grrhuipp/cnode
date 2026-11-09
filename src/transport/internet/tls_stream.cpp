#include "transport/internet/tls_stream.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "reality_tls.hpp"
#include "transport/internet/async_write_gate.hpp"
#include "transport/internet/stream_settings.hpp"
#include "common/buffer_util.hpp"
#include "infra/log.hpp"
#include "common/unsafe.hpp"
#include "common/domain_name.hpp"
#include "common/ip_address.hpp"
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/tls1.h>
#include <openssl/mem.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <unistd.h>
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

#include <cerrno>
#include <cstring>
#include <limits>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

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
    if (protocols.empty()) return true;
    auto wire = std::make_unique<std::vector<unsigned char>>();
    if (!EncodeTlsAlpnProtocols(protocols, *wire)) return false;
    static const int index = SSL_CTX_get_ex_new_index(
        0, nullptr, nullptr, nullptr,
        [](void*, void* ptr, CRYPTO_EX_DATA*, int, long, void*) {
            delete static_cast<std::vector<unsigned char>*>(ptr);
        });
    if (index < 0 ||
        SSL_CTX_set_ex_data(native_owner_.get(), index, wire.get()) != 1) {
        return false;
    }
    SSL_CTX_set_alpn_select_cb(
        native_owner_.get(), SelectServerAlpnCallback, wire.release());
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
        std::uint64_t generation = 0;
        unsigned long library_error = 0;
        int ssl_error = SSL_ERROR_NONE;
        int result = 0;
    };

    // At most one reader and one writer can own output. The turns live in those
    // operations, not in a connection queue, and preserve SSL record sequence
    // while allowing reads during a backpressured physical write.
    struct OutputTurn {
        OutputTurn(Impl& owner) : owner(owner), previous(owner.output_tail) {
            if (previous) wake.emplace(owner.tcp->GetExecutor(), 1);
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
        SSL_CTX* raw = context.Native();
        std::shared_ptr<SSL_CTX> snapshot;
        if (raw == nullptr) {
            snapshot = context.AcquireNative();
            raw = snapshot.get();
            if (!raw) throw std::runtime_error("TLS certificate expired without a renewed snapshot");
        }
        ssl.reset(SSL_new(raw));
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
    Impl(std::unique_ptr<TcpStream> inner, SSL* existing_ssl)
        : tcp(std::move(inner))
        , ssl(existing_ssl, SSL_free) {
        if (!tcp || !ssl) throw std::invalid_argument("TlsStream restore requires valid TcpStream and SSL");
        BIO* bio = SSL_get_rbio(ssl.get());
        if (!bio) throw std::logic_error("TlsStream restore missing SSL BIO");
        BIO_set_data(bio, this);
        Resubscribe(tcp->Cancellation());
    }

    ~Impl() {
        Unsubscribe();
    }

    void DetachSubscription() noexcept { Unsubscribe(); }

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
        call.generation = input_generation;
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

    net::awaitable<void> FlushPendingOutput(
        Invocation& call, Gate::Lease& lease, std::uint64_t epoch,
        bool deferred, bool release_lease) {
        try {
            // Reserve the physical turn before the first suspension
            // or another SSL call can generate a subsequent record.
            OutputTurn turn(*this);
            if (release_lease) lease.Reset();
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
            const net::const_buffer out_buf = net::buffer(*call.output);
            co_await tcp->WriteBuffers(std::span<const net::const_buffer>(&out_buf, 1));
            CheckCancellation(epoch);
        } catch (...) {
            Abort();
            throw;
        }
    }
    // Returns true if completed synchronously without pending BIO output;
    // otherwise `lease` and `pending_call` are ready for `FinishPerform`.
    bool TryInvokeOnce(Kind kind, Gate::Lease& lease,
                       std::optional<Invocation>& pending_call,
                       std::uint64_t epoch, net::mutable_buffer target,
                       net::const_buffer source, buf::BufferGuard* allocated,
                       int& sync_result) {
        lease = engine_gate.TryAcquire();
        if (!lease) return false;
        CheckCancellation(epoch);
        if (kind == Kind::Read && !tcp->CanRead()) {
            sync_result = 0;
            return true;
        }
        if (allocated && !*allocated) {
            *allocated = buf::BufferGuard{buf::Buffer::New()};
            if (!*allocated) throw std::bad_alloc();
            target = net::buffer((*allocated)->Tail().data(), (*allocated)->Available());
        }
        auto& call = pending_call.emplace();
        Invoke(call, kind, target, source);
        if (call.failure || call.transport_error) Fail(call);
        CheckCancellation(epoch);
        if (allocated && call.result <= 0 && call.ssl_error == SSL_ERROR_WANT_READ)
            *allocated = {};
        if (!call.output) {
            if (call.result > 0) {
                sync_result = call.result;
                return true;
            }
            if (kind == Kind::Read && call.ssl_error == SSL_ERROR_ZERO_RETURN) {
                sync_result = 0;
                return true;
            }
            if (call.ssl_error != SSL_ERROR_WANT_READ) Fail(call);
        }
        return false;
    }

    net::awaitable<int> FinishPerform(
        Kind kind, Gate::Lease lease, std::optional<Invocation> pending_call,
        std::uint64_t epoch, bool deferred,
        net::mutable_buffer target, net::const_buffer source,
        buf::BufferGuard* allocated) {
        if (!lease) {
            lease = engine_gate.TryAcquire();
            if (!lease) lease = co_await engine_gate.Acquire(deferred);
            CheckCancellation(epoch);
            if (!lease) throw IoSystemError(io_error::operation_aborted);
        }
        for (;;) {
            int result = 0;
            int error = SSL_ERROR_NONE;
            std::uint64_t generation = 0;
            {
                std::optional<Invocation> current;
                if (pending_call) {
                    current = std::move(pending_call);
                    pending_call.reset();
                } else {
                    if (kind == Kind::Read && !tcp->CanRead()) co_return 0;
                    if (allocated && !*allocated) {
                        *allocated = buf::BufferGuard{buf::Buffer::New()};
                        if (!*allocated) throw std::bad_alloc();
                        target = net::buffer((*allocated)->Tail().data(), (*allocated)->Available());
                    }
                    auto& call = current.emplace();
                    Invoke(call, kind, target, source);
                    if (call.failure || call.transport_error) Fail(call);
                    CheckCancellation(epoch);
                    if (allocated && call.result <= 0 && call.ssl_error == SSL_ERROR_WANT_READ)
                        *allocated = {};
                }
                auto& call = *current;
                generation = call.generation;
                result = call.result;
                error = call.ssl_error;
                const bool shutdown_sent = kind == Kind::Shutdown &&
                    (SSL_get_shutdown(ssl.get()) & SSL_SENT_SHUTDOWN) != 0;
                if (call.output) {
                    co_await FlushPendingOutput(
                        call, lease, epoch, deferred,
                        result > 0 || shutdown_sent || error == SSL_ERROR_WANT_READ);
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
            }
            if (!lease) {
                lease = engine_gate.TryAcquire();
                if (!lease) lease = co_await engine_gate.Acquire(deferred);
                CheckCancellation(epoch);
                if (!lease) throw IoSystemError(io_error::operation_aborted);
            }
        }
    }

    net::awaitable<int> Perform(Kind kind) {
        return FinishPerform(
            kind, {}, std::nullopt, cancel_epoch,
            (kind == Kind::Write && tcp->IsWriteCancellationDeferred()), {}, {}, nullptr);
    }

    net::awaitable<std::size_t> AsyncRead(net::mutable_buffer target) {
        if (!tcp->CanRead() || target.size() == 0) co_return 0;
        ActiveDirection active(read_active);
        try {
            if ((SSL_get_shutdown(ssl.get()) & SSL_RECEIVED_SHUTDOWN) != 0) co_return 0;
            const auto epoch = cancel_epoch;
            Gate::Lease lease;
            std::optional<Invocation> call;
            int sync_result = 0;
            if (TryInvokeOnce(Kind::Read, lease, call, epoch, target, {}, nullptr, sync_result))
                co_return static_cast<std::size_t>(sync_result);
            co_return static_cast<std::size_t>(co_await FinishPerform(
                Kind::Read, std::move(lease), std::move(call), epoch, false,
                target, {}, nullptr));
        } catch (const IoSystemError& error) {
            if (error.code() == io_error::eof && !tcp->CanRead()) co_return 0;
            throw;
        }
    }

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() {
        if (!tcp->CanRead()) co_return buf::MultiBuffer{};
        ActiveDirection active(read_active);
        try {
            if ((SSL_get_shutdown(ssl.get()) & SSL_RECEIVED_SHUTDOWN) != 0)
                co_return buf::MultiBuffer{};
            // Socket wait has no payload allocation. Always retry SSL first when its
            // reusable read buffer contains a record/retained plaintext or when TCP
            // still holds bounded nonblocking drain budget from the last readiness.
            if (SSL_pending(ssl.get()) == 0 && SSL_has_pending(ssl.get()) == 0 &&
                !tcp->TryConsumeReadableBudget()) {
                co_await WaitForInput(cancel_epoch, input_generation);
            }
            const auto epoch = cancel_epoch;
            buf::BufferGuard out;
            Gate::Lease lease;
            std::optional<Invocation> call;
            int n = 0;
            if (!TryInvokeOnce(Kind::Read, lease, call, epoch, {}, {}, &out, n)) {
                n = co_await FinishPerform(
                    Kind::Read, std::move(lease), std::move(call), epoch, false,
                    {}, {}, &out);
            }
            if (n == 0) co_return buf::MultiBuffer{};
            out->Produce(static_cast<uint32_t>(n));
            co_return buf::MultiBuffer{std::move(out)};
        } catch (const IoSystemError& error) {
            if (error.code() == io_error::eof && !tcp->CanRead())
                co_return buf::MultiBuffer{};
            throw;
        }
    }

    net::awaitable<void> Write(
        std::span<const net::const_buffer> buffers,
        buf::MultiBuffer owned = {}) {
        struct ClearOwned {
            buf::MultiBuffer& mb;
            ~ClearOwned() noexcept { mb.clear(); }
        } clear_owned{owned};
        ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> owned_spans;
        if (!owned.empty()) {
            if (owned.byte_size() == 0) co_return;
            owned_spans.AppendMultiBuffer(owned);
            buffers = owned_spans.Span();
        }
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
                const auto epoch = cancel_epoch;
                Gate::Lease lease;
                std::optional<Invocation> call;
                int sync_result = 0;
                if (!TryInvokeOnce(
                        Kind::Write, lease, call, epoch, {}, fragment, nullptr, sync_result)) {
                    sync_result = co_await FinishPerform(
                        Kind::Write, std::move(lease), std::move(call), epoch,
                        tcp->IsWriteCancellationDeferred(), {}, fragment, nullptr);
                }
                auto n = static_cast<std::size_t>(sync_result);
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

TlsStream::TlsStream(std::unique_ptr<TcpStream> inner, SSL* existing_ssl, bool is_server)
    : impl_(std::make_unique<Impl>(std::move(inner), existing_ssl))
    , is_server_(is_server)
    , handshake_done_(true) {}

DetachedTlsState::~DetachedTlsState() noexcept {
    if (ssl) SSL_free(ssl);
}

DetachedTlsState::DetachedTlsState(DetachedTlsState&& other) noexcept
    : tcp(std::move(other.tcp))
    , ssl(std::exchange(other.ssl, nullptr))
    , is_server(other.is_server)
    , plaintext_prefix(std::move(other.plaintext_prefix)) {}

DetachedTlsState& DetachedTlsState::operator=(DetachedTlsState&& other) noexcept {
    if (this != &other) {
        if (ssl) SSL_free(ssl);
        tcp = std::move(other.tcp);
        ssl = std::exchange(other.ssl, nullptr);
        is_server = other.is_server;
        plaintext_prefix = std::move(other.plaintext_prefix);
    }
    return *this;
}

std::optional<DetachedTlsState> TlsStream::DetachForHandoff(
    std::span<const uint8_t> plaintext_prefix) {
    if (!handshake_done_ || impl_->handshaking || impl_->read_active ||
        impl_->write_active || impl_->invocation || !impl_->tcp ||
        !impl_->tcp->IsOpen()) {
        return std::nullopt;
    }
    DetachedTlsState state;
    state.is_server = is_server_;
    const size_t extra = impl_->prepended_plaintext
        ? impl_->prepended_plaintext->data.byte_size() : 0;
    if (plaintext_prefix.size() + extra != 0) {
        state.plaintext_prefix.resize(plaintext_prefix.size() + extra);
        if (!plaintext_prefix.empty()) {
            std::memcpy(
                state.plaintext_prefix.data(),
                plaintext_prefix.data(),
                plaintext_prefix.size());
        }
        if (impl_->prepended_plaintext) {
            (void)impl_->prepended_plaintext->data.CopyPrefixTo(
                std::span<uint8_t>(state.plaintext_prefix).subspan(plaintext_prefix.size()));
        }
    }
    impl_->prepended_plaintext.reset();
    auto detached_tcp = impl_->tcp->DetachForHandoff();
    if (!detached_tcp) return std::nullopt;
    state.tcp = std::move(*detached_tcp);
    impl_->DetachSubscription();
    if (BIO* bio = SSL_get_rbio(impl_->ssl.get())) {
        BIO_set_data(bio, nullptr);
    }
    state.ssl = impl_->ssl.release();
    NotifyClosed();
    shutdown_initiated_ = true;
    return state;
}

std::unique_ptr<TlsStream> TlsStream::RestoreFromHandoff(
    net::io_context& io_context, DetachedTlsState state) {
    if (!state.ssl || state.tcp.fd < 0) return nullptr;
    auto tcp = TcpStream::RestoreFromHandoff(io_context, std::move(state.tcp));
    if (!tcp) return nullptr;
    SSL* ssl = std::exchange(state.ssl, nullptr);
    std::unique_ptr<TlsStream> stream(
        new TlsStream(std::move(tcp), ssl, state.is_server));
    if (!state.plaintext_prefix.empty()) {
        stream->PrependReadData(state.plaintext_prefix);
    }
    return stream;
}
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
        ClearRealityClientState(NativeSsl(), reality_client_state_);
        if (!spider_x.empty()) {
            const char* sni = SSL_get_servername(
                NativeSsl(), TLSEXT_NAMETYPE_host_name);
            const std::string_view host = (sni && *sni != '\0')
                ? std::string_view(sni)
                : std::string_view("localhost");
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
                (void)co_await impl_->ReadMultiBuffer();
            } catch (const std::exception&) {
                // The camouflage exchange is best-effort; authentication still
                // fails regardless of the origin's response or close behavior.
            }
        }
        impl_->Abort();
        co_return false;
    }

    impl_->tcp->ResetReadableBudget();
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
    PrependReadMultiBuffer(std::move(prefix));
}

void TlsStream::PrependReadMultiBuffer(buf::MultiBuffer&& mb) {
    if (mb.byte_size() == 0) {
        mb.clear();
        return;
    }
    if (!impl_->tcp->CanRead()) {
        mb.clear();
        throw IoSystemError(io_error::operation_aborted, "TLS read closed");
    }
    if (impl_->prepended_plaintext) {
        impl_->prepended_plaintext->data.MoveTo(mb);
    } else {
        impl_->prepended_plaintext = std::make_unique<Impl::PrependedPlaintext>();
    }
    impl_->prepended_plaintext->data = std::move(mb);
}

net::awaitable<std::size_t> TlsStream::AsyncRead(net::mutable_buffer buffer) {
    if (handshake_done_ && !impl_->prepended_plaintext &&
        (!impl_->raw_read || SSL_pending(NativeSsl()) != 0)) {
        return impl_->AsyncRead(buffer);
    }
    return AsyncReadSlow(buffer);
}

net::awaitable<std::size_t> TlsStream::AsyncReadSlow(net::mutable_buffer buffer) {
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
    co_return co_await impl_->AsyncRead(buffer);
}

net::awaitable<buf::MultiBuffer> TlsStream::ReadMultiBuffer() {
    if (handshake_done_ && !impl_->prepended_plaintext &&
        (!impl_->raw_read || SSL_pending(NativeSsl()) != 0)) {
        return impl_->ReadMultiBuffer();
    }
    return ReadMultiBufferSlow();
}

net::awaitable<buf::MultiBuffer> TlsStream::ReadMultiBufferSlow() {
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
    co_return co_await impl_->ReadMultiBuffer();
}

net::awaitable<std::size_t> TlsStream::AsyncWrite(net::const_buffer buffer) {
    const std::array buffers{buffer};
    co_await WriteBuffers(buffers);
    co_return buffer.size();
}

net::awaitable<void> TlsStream::WriteMultiBuffer(buf::MultiBuffer mb) {
    if (mb.byte_size() != 0 && handshake_done_ && !shutdown_initiated_ &&
        impl_->tcp->CanWrite() && !impl_->tcp->IsWriteCancellationDeferred()) {
        return impl_->Write({}, std::move(mb));
    }
    return AsyncStream::WriteMultiBuffer(std::move(mb));
}

net::awaitable<void> TlsStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (handshake_done_ && !shutdown_initiated_ &&
        impl_->tcp->CanWrite() && !impl_->tcp->IsWriteCancellationDeferred()) {
        return impl_->Write(buffers);
    }
    return WriteBuffersSlow(buffers);
}

net::awaitable<void> TlsStream::WriteBuffersSlow(
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

// ============================================================================
// AutoSignCertificate & AutoSignContextRenewal
// ============================================================================

namespace transport::internet {
namespace {

EVP_PKEY* GenerateEcP256Key() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* generated = nullptr;
    if (!pctx ||
        EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pctx, &generated) <= 0) {
        if (pctx) EVP_PKEY_CTX_free(pctx);
        if (generated) EVP_PKEY_free(generated);
        return nullptr;
    }
    EVP_PKEY_CTX_free(pctx);
    return generated;
}

bool PushGeneralName(GENERAL_NAMES* names, int type, ASN1_STRING* value) {
    GENERAL_NAME* name = GENERAL_NAME_new();
    if (!name) {
        ASN1_STRING_free(value);
        return false;
    }
    GENERAL_NAME_set0_value(name, type, value);
    if (sk_GENERAL_NAME_push(names, name) == 0) {
        GENERAL_NAME_free(name);
        return false;
    }
    return true;
}

bool PushDnsName(GENERAL_NAMES* names, std::string_view value) {
    if (value.empty() ||
        value.size() > static_cast<size_t>(std::numeric_limits<int>::max())) {
        return false;
    }
    for (const unsigned char ch : value) {
        if (ch <= 0x20 || ch > 0x7e) return false;
    }
    ASN1_IA5STRING* dns_name = ASN1_IA5STRING_new();
    if (!dns_name ||
        ASN1_STRING_set(
            dns_name, value.data(), static_cast<int>(value.size())) != 1) {
        if (dns_name) ASN1_IA5STRING_free(dns_name);
        return false;
    }
    return PushGeneralName(names, GEN_DNS, dns_name);
}

bool AddSubjectAlternativeNames(X509* certificate, const std::string& identity) {
    GENERAL_NAMES* names = GENERAL_NAMES_new();
    if (!names) return false;

    ASN1_OCTET_STRING* ip_address = a2i_IPADDRESS(identity.c_str());
    bool built = false;
    if (ip_address) {
        built = PushGeneralName(names, GEN_IPADD, ip_address);
    } else {
        built = PushDnsName(names, identity);
        if (built && identity.starts_with("*.")) {
            built = PushDnsName(names, std::string_view(identity).substr(2));
        }
    }

    X509_EXTENSION* extension = built
        ? X509V3_EXT_i2d(NID_subject_alt_name, 0, names)
        : nullptr;
    const bool added = extension && X509_add_ext(certificate, extension, -1) == 1;
    if (extension) X509_EXTENSION_free(extension);
    GENERAL_NAMES_free(names);
    return added;
}

}  // namespace

AutoSignCertificate::~AutoSignCertificate() {
    X509_free(certificate_);
    EVP_PKEY_free(key_);
}

std::unique_ptr<AutoSignCertificate> AutoSignCertificate::Create(std::string_view identity) {
    // RFC 5280's commonName limit is 64 characters, not a DNS SAN limit.
    // DNS identities belong in SAN; a descriptive CN covers longer names.
    if (identity.empty() || identity.find('\0') != std::string_view::npos) return {};
    if (identity.ends_with('.')) identity.remove_suffix(1);
    if (identity.empty() || identity.ends_with('.')) return {};
    const std::string name_text(identity);
    const std::string_view cn = identity.size() <= 64
        ? identity : std::string_view("acppnode self-signed certificate");
    auto material = std::unique_ptr<AutoSignCertificate>(new AutoSignCertificate);
    material->key_ = GenerateEcP256Key();
    material->certificate_ = X509_new();
    if (!material->key_ || !material->certificate_) {
        ERR_clear_error();
        return {};
    }
    X509* x509 = material->certificate_;
    X509_NAME* name = X509_get_subject_name(x509);
    // These credentials are regenerated on configuration reload/restart,
    // never in response to untrusted ClientHello traffic.
    constexpr long kValiditySeconds = 365L * 24 * 60 * 60;
    if (X509_set_version(x509, 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1) != 1 ||
        !X509_gmtime_adj(X509_get_notBefore(x509), -300) ||
        !X509_gmtime_adj(X509_get_notAfter(x509), kValiditySeconds) ||
        X509_set_pubkey(x509, material->key_) != 1 ||
        !name ||
        X509_NAME_add_entry_by_txt(
            name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(cn.data()),
            static_cast<int>(cn.size()), -1, 0) != 1 ||
        X509_set_issuer_name(x509, name) != 1 ||
        !AddSubjectAlternativeNames(x509, name_text) ||
        X509_sign(x509, material->key_, EVP_sha256()) <= 0) {
        ERR_clear_error();
        return {};
    }
    return material;
}

}  // namespace transport::internet

class AutoSignRenewalScheduler {
public:
    static AutoSignRenewalScheduler& Instance() {
        static AutoSignRenewalScheduler scheduler;
        return scheduler;
    }
    void Add(const std::shared_ptr<AutoSignContextRenewal>& state) {
        std::lock_guard lock(mutex_);
        if (failed_) throw std::runtime_error("auto-sign renewal scheduler stopped");
        std::erase_if(states_, [](const auto& entry) { return entry.expired(); });
        // Configuration-controlled registrations only. Refuse overload instead
        // of retaining an unbounded signing queue or spawning extra threads.
        if (states_.size() >= kCapacity)
            throw std::runtime_error("auto-sign context renewal capacity exhausted");
        states_.push_back(state);
        Notify();
    }
    ~AutoSignRenewalScheduler() {
        thread_.request_stop();
        Notify();
        if (thread_.joinable()) thread_.join();
        ::close(timer_);
        ::close(wake_);
    }
private:
    AutoSignRenewalScheduler() {
        wake_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        timer_ = ::timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC | TFD_NONBLOCK);
        if (wake_ < 0 || timer_ < 0) {
            const auto error = errno;
            if (wake_ >= 0) ::close(wake_);
            if (timer_ >= 0) ::close(timer_);
            throw std::system_error(error, std::generic_category(), "auto-sign event descriptors");
        }
        try {
            thread_ = std::jthread([this](std::stop_token stop) {
                try {
                    Run(stop);
                } catch (const std::exception& error) {
                    LOG_ERROR("TLS auto-sign renewal scheduler stopped > {}", error.what());
                    std::lock_guard lock(mutex_);
                    failed_ = true;
                }
            });
        } catch (...) {
            ::close(timer_);
            ::close(wake_);
            throw;
        }
    }
    void Notify() noexcept {
        const uint64_t value = 1;
        while (::write(wake_, &value, sizeof(value)) < 0 && errno == EINTR) {}
        // EAGAIN means the event counter is already readable.
    }
    void Wait(AutoSignContextRenewal::Clock::time_point next) {
        if (next <= AutoSignContextRenewal::Clock::now()) return;
        itimerspec timeout{};
        if (next != AutoSignContextRenewal::Clock::time_point::max()) {
            const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(next.time_since_epoch());
            timeout.it_value.tv_sec = seconds.count();
            timeout.it_value.tv_nsec = std::chrono::duration_cast<std::chrono::nanoseconds>(
                next.time_since_epoch() - seconds).count();
        }
        if (::timerfd_settime(timer_, TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET,
                              &timeout, nullptr) != 0) {
            // Linux also reports an unread clock-change cancellation when
            // rearming; the new timer is armed, but rescan the due set first.
            if (errno == ECANCELED) return;
            throw std::system_error(errno, std::generic_category(), "auto-sign timer arm");
        }
        pollfd events[]{{wake_, POLLIN, 0}, {timer_, POLLIN, 0}};
        int ready;
        do { ready = ::poll(events, 2, -1); } while (ready < 0 && errno == EINTR);
        if (ready < 0) throw std::system_error(errno, std::generic_category(), "auto-sign event wait");
        for (const auto& event : events) {
            if (event.revents & (POLLERR | POLLHUP | POLLNVAL))
                throw std::runtime_error("auto-sign event descriptor failed");
            if (event.revents & POLLIN) {
                uint64_t count;
                ssize_t bytes;
                do { bytes = ::read(event.fd, &count, sizeof(count)); } while (bytes < 0 && errno == EINTR);
                // A real wall-clock discontinuity cancels the absolute timer.
                // Recompute the nearest certificate's deadline, without polling.
                if (bytes < 0 && errno != EAGAIN && errno != ECANCELED)
                    throw std::system_error(errno, std::generic_category(), "auto-sign event read");
            }
        }
    }
    void Run(std::stop_token stop) {
        using Clock = AutoSignContextRenewal::Clock;
        while (!stop.stop_requested()) {
            std::unique_lock lock(mutex_);
            std::erase_if(states_, [](const auto& entry) { return entry.expired(); });
            auto next = Clock::time_point::max();
            std::shared_ptr<AutoSignContextRenewal> due;
            const auto now = Clock::now();
            for (const auto& weak : states_) {
                if (auto state = weak.lock()) {
                    const auto attempt_at = state->next_attempt_.load(std::memory_order_acquire);
                    if (attempt_at <= now) {
                        due = std::move(state);
                        break;
                    }
                    next = std::min(next, attempt_at);
                }
            }
            lock.unlock();
            if (!due) {
                Wait(next);
                continue;
            }
            bool renewed = false;
            try {
                renewed = due->Publish(due->builder_());
            } catch (const std::exception& error) {
                LOG_ERROR("TLS auto-sign renewal failed > {}", error.what());
            } catch (...) {
                LOG_ERROR("TLS auto-sign renewal failed > unknown exception");
            }
            const auto minimum_retry = Clock::now() + std::chrono::minutes(1);
            if (!renewed) {
                // Existing connections retain their own SSL_CTX. New handshakes
                // fail closed after notAfter if renewal cannot recover.
                due->next_attempt_.store(minimum_retry, std::memory_order_release);
                LOG_ERROR("TLS auto-sign renewal unavailable; retrying in one minute");
            } else if (due->next_attempt_.load(std::memory_order_acquire) < minimum_retry) {
                due->next_attempt_.store(minimum_retry, std::memory_order_release);
            }
        }
    }
    static constexpr size_t kCapacity = 4096;
    std::mutex mutex_;
    int wake_ = -1;
    int timer_ = -1;
    bool failed_ = false;
    std::vector<std::weak_ptr<AutoSignContextRenewal>> states_;
    std::jthread thread_;
};

AutoSignContextRenewal::AutoSignContextRenewal(std::shared_ptr<SSL_CTX> initial, Builder builder)
    : builder_(std::move(builder)) {
    if (!Publish(std::move(initial)))
        throw std::invalid_argument("auto-sign certificate has invalid validity");
}

bool AutoSignContextRenewal::Publish(std::shared_ptr<SSL_CTX> context) {
    if (!context) return false;
    const X509* certificate = SSL_CTX_get0_certificate(context.get());
    int64_t expires_seconds = 0;
    if (!certificate || ASN1_TIME_to_posix(X509_get0_notAfter(certificate), &expires_seconds) != 1)
        return false;
    const auto expires = Clock::time_point(std::chrono::seconds(expires_seconds));
    if (expires <= Clock::now()) return false;
    const auto previous = current_.load(std::memory_order_acquire);
    if (previous && expires <= previous->expires) return false;
    current_.store(std::make_shared<const Snapshot>(Snapshot{std::move(context), expires}),
                   std::memory_order_release);
    next_attempt_.store(expires - std::chrono::hours(24 * 30), std::memory_order_release);
    return true;
}

std::shared_ptr<AutoSignContextRenewal> AutoSignContextRenewal::Start(
    std::shared_ptr<SSL_CTX> initial, Builder builder) {
    auto state = std::shared_ptr<AutoSignContextRenewal>(
        new AutoSignContextRenewal(std::move(initial), std::move(builder)));
    AutoSignRenewalScheduler::Instance().Add(state);
    return state;
}

std::shared_ptr<SSL_CTX> AutoSignContextRenewal::Acquire(Clock::time_point now) const noexcept {
    const auto snapshot = current_.load(std::memory_order_acquire);
    if (!snapshot || now >= snapshot->expires) return {};
    return snapshot->context;
}

// ============================================================================
// TLS Client Context & PEM Material
// ============================================================================

namespace {

// Real chains and CA bundles are far smaller; the bound keeps a mistyped path
// to a device or an unrelated large file from stalling configuration load.
constexpr std::size_t kMaxTlsPemFileBytes = 1024 * 1024;

struct FileDescriptor {
    int fd = -1;
    FileDescriptor() = default;
    explicit FileDescriptor(int value) noexcept : fd(value) {}
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    ~FileDescriptor() {
        if (fd >= 0) ::close(fd);
    }
};

// The private key passes through here, so the file is read unbuffered into one
// allocation sized up front: no stdio/stream buffer and no growth copy keeps
// key bytes outside the returned string, and every error path wipes it.
std::string ReadTlsPemFile(const std::string& path, std::string_view kind) {
    const auto fail = [&](std::string_view reason) {
        return std::invalid_argument(
            std::format("cannot read TLS {} file '{}': {}", kind, path, reason));
    };
    if (path.find('\0') != std::string::npos) {
        throw std::invalid_argument(
            std::format("cannot open TLS {} file '{}'", kind, path));
    }
    FileDescriptor file(::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    if (file.fd < 0) {
        throw std::invalid_argument(
            std::format("cannot open TLS {} file '{}'", kind, path));
    }
    struct stat st{};
    if (::fstat(file.fd, &st) != 0) throw fail("read error");
    if (!S_ISREG(st.st_mode)) throw fail("not a regular file");
    if (st.st_size < 0) throw fail("read error");
    if (st.st_size == 0) throw fail("empty");
    if (static_cast<unsigned long long>(st.st_size) > kMaxTlsPemFileBytes) {
        throw fail("larger than 1 MiB");
    }

    std::string contents(static_cast<std::size_t>(st.st_size), '\0');
    std::size_t offset = 0;
    bool read_error = false;
    while (offset < contents.size()) {
        const ssize_t count = ::read(
            file.fd, contents.data() + offset, contents.size() - offset);
        if (count < 0) {
            if (errno == EINTR) continue;
            read_error = true;
            break;
        }
        if (count == 0) break;
        offset += static_cast<std::size_t>(count);
    }
    // One byte more than announced means the file changed while being read.
    char probe = 0;
    ssize_t extra = 0;
    if (!read_error && offset == contents.size()) {
        do {
            extra = ::read(file.fd, &probe, 1);
        } while (extra < 0 && errno == EINTR);
        if (extra < 0) read_error = true;
    }
    OPENSSL_cleanse(&probe, sizeof(probe));
    if (read_error || offset != contents.size() || extra != 0) {
        OPENSSL_cleanse(contents.data(), contents.size());
        throw fail(read_error ? "read error" : "changed while reading");
    }
    return contents;
}

uint16_t ToOpenSslVersion(TlsVersion version) noexcept {
    switch (version) {
        case TlsVersion::V1_2:
            return TLS1_2_VERSION;
        case TlsVersion::V1_3:
            return TLS1_3_VERSION;
    }
    return 0;
}

[[nodiscard]] bssl::UniquePtr<BIO> PemReader(const std::string& pem) {
    return bssl::UniquePtr<BIO>(BIO_new_mem_buf(
        pem.data(), static_cast<ossl_ssize_t>(pem.size())));
}

int RejectEncryptedPemPassword(char*, int, int, void*) noexcept {
    return -1;
}

// PEM readers report the end of input as PEM_R_NO_START_LINE; anything else
// is a malformed block. Clears the queue so no stale error reaches later
// SSL_get_error calls on this thread.
[[nodiscard]] bool ConsumePemEndOfInput() noexcept {
    const uint32_t error = ERR_peek_last_error();
    ERR_clear_error();
    return ERR_GET_LIB(error) == ERR_LIB_PEM &&
        ERR_GET_REASON(error) == PEM_R_NO_START_LINE;
}

// In-memory SSL_CTX_load_verify_locations: like X509_load_cert_crl_file it
// reads every PEM_X509_INFO block (including TRUSTED CERTIFICATE and CRLs);
// a bundle without any certificate or CRL is rejected.
[[nodiscard]] bool ConfigureTlsTrustedCaPem(SSL_CTX* context, const std::string& pem) {
    ERR_clear_error();
    auto reader = PemReader(pem);
    X509_STORE* store = SSL_CTX_get_cert_store(context);
    if (!reader || !store) {
        ERR_clear_error();
        return false;
    }
    struct InfoStackFree {
        void operator()(STACK_OF(X509_INFO)* infos) const noexcept {
            sk_X509_INFO_pop_free(infos, X509_INFO_free);
        }
    };
    std::unique_ptr<STACK_OF(X509_INFO), InfoStackFree> infos(
        PEM_X509_INFO_read_bio(reader.get(), nullptr, &RejectEncryptedPemPassword, nullptr));
    if (!infos) {
        ERR_clear_error();
        return false;
    }
    size_t loaded = 0;
    for (size_t i = 0; i < sk_X509_INFO_num(infos.get()); ++i) {
        const X509_INFO* info = sk_X509_INFO_value(infos.get(), i);
        if (info->x509) {
            if (X509_STORE_add_cert(store, info->x509) != 1) {
                const uint32_t err = ERR_peek_last_error();
                if (ERR_GET_LIB(err) == ERR_LIB_X509 &&
                    ERR_GET_REASON(err) == X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                    ERR_clear_error();
                    ++loaded;
                } else {
                    ERR_clear_error();
                    return false;
                }
            } else {
                ++loaded;
            }
        }
        if (info->crl) {
            if (X509_STORE_add_crl(store, info->crl) != 1) {
                ERR_clear_error();
                return false;
            }
            ++loaded;
        }
    }
    ERR_clear_error();
    return loaded != 0;
}

}  // namespace

TlsPemMaterial::~TlsPemMaterial() {
    OPENSSL_cleanse(private_key.data(), private_key.size());
}

void LoadTlsPemMaterial(TlsConfig& config) {
    if (config.cert_file.empty() && config.key_file.empty() &&
        config.ca_file.empty()) {
        config.pem.reset();
        return;
    }
    auto material = std::make_shared<TlsPemMaterial>();
    if (!config.cert_file.empty()) {
        material->certificate_chain =
            ReadTlsPemFile(config.cert_file, "certificate");
    }
    if (!config.key_file.empty()) {
        material->private_key = ReadTlsPemFile(config.key_file, "private key");
    }
    if (!config.ca_file.empty()) {
        material->trusted_ca = ReadTlsPemFile(config.ca_file, "CA");
    }
    config.pem = std::move(material);
}

bool ConfigureTlsCertificatePem(SSL_CTX* context, const TlsPemMaterial& pem) {
    ERR_clear_error();
    auto chain = PemReader(pem.certificate_chain);
    if (!chain) {
        ERR_clear_error();
        return false;
    }
    bssl::UniquePtr<X509> leaf(
        PEM_read_bio_X509_AUX(chain.get(), nullptr, &RejectEncryptedPemPassword, nullptr));
    if (!leaf || SSL_CTX_use_certificate(context, leaf.get()) != 1) {
        ERR_clear_error();
        LOG_ERROR("TLS certificate file does not start with a valid PEM certificate");
        return false;
    }
    while (bssl::UniquePtr<X509> intermediate{
               PEM_read_bio_X509(chain.get(), nullptr, &RejectEncryptedPemPassword, nullptr)}) {
        if (SSL_CTX_add1_chain_cert(context, intermediate.get()) != 1) {
            ERR_clear_error();
            LOG_ERROR("failed to install TLS certificate chain");
            return false;
        }
    }
    if (!ConsumePemEndOfInput()) {
        LOG_ERROR("TLS certificate file contains a malformed PEM block");
        return false;
    }

    auto key_reader = PemReader(pem.private_key);
    bssl::UniquePtr<EVP_PKEY> key(key_reader
        ? PEM_read_bio_PrivateKey(key_reader.get(), nullptr, &RejectEncryptedPemPassword, nullptr)
        : nullptr);
    if (!key || SSL_CTX_use_PrivateKey(context, key.get()) != 1) {
        ERR_clear_error();
        LOG_ERROR("TLS private key file does not contain a valid PEM private key");
        return false;
    }
    if (SSL_CTX_check_private_key(context) != 1) {
        ERR_clear_error();
        LOG_ERROR("TLS private key does not match certificate");
        return false;
    }
    ERR_clear_error();
    return true;
}

bool ConfigureTlsProtocolVersions(
    SSL_CTX* context,
    TlsVersion min_version,
    TlsVersion max_version) noexcept {
    const uint16_t minimum = ToOpenSslVersion(min_version);
    const uint16_t maximum = ToOpenSslVersion(max_version);
    return context && minimum != 0 && maximum != 0 && minimum <= maximum &&
        SSL_CTX_set_min_proto_version(context, minimum) == 1 &&
        SSL_CTX_set_max_proto_version(context, maximum) == 1;
}

bool EncodeTlsAlpnProtocols(
    std::span<const std::string> protocols,
    std::vector<unsigned char>& wire) {
    wire.clear();
    if (!IsValidTlsAlpn(protocols)) return false;

    std::size_t wire_size = 0;
    for (const auto& protocol : protocols) {
        wire_size += 1 + protocol.size();
    }
    wire.reserve(wire_size);
    for (const auto& protocol : protocols) {
        wire.push_back(static_cast<unsigned char>(protocol.size()));
        wire.insert(wire.end(), protocol.begin(), protocol.end());
    }
    return true;
}

bool ConfigureTlsClientAlpn(
    SSL_CTX* context, std::span<const std::string> protocols) {
    std::vector<unsigned char> wire;
    // SSL_new copies the context list, so no handshake encodes it again.
    return EncodeTlsAlpnProtocols(protocols, wire) &&
        (wire.empty() || SSL_CTX_set_alpn_protos(context, wire.data(), wire.size()) == 0);
}

bool ConfigureTlsServerIdentity(
    SSL* ssl, std::string_view identity) {
    if (!ssl || identity.empty() || identity.find('\0') != std::string_view::npos) {
        return false;
    }

    if (const auto address = iputil::ParseLiteral(identity)) {
        X509_VERIFY_PARAM* parameters = SSL_get0_param(ssl);
        if (!parameters) return false;
        if (address->is_v4()) {
            const auto bytes = address->to_v4().to_bytes();
            return X509_VERIFY_PARAM_set1_ip(parameters, bytes.data(), bytes.size()) == 1;
        }
        const auto bytes = address->to_v6().to_bytes();
        return X509_VERIFY_PARAM_set1_ip(parameters, bytes.data(), bytes.size()) == 1;
    }
    if (!domain::IsValidDnsHostname(identity, domain::TrailingDotPolicy::Allow)) return false;
    identity = domain::WithoutTrailingRootDot(identity);
    std::array<char, 256> identity_text{};
    if (identity.size() >= identity_text.size()) return false;
    std::memcpy(identity_text.data(), identity.data(), identity.size());

    if (SSL_set_tlsext_host_name(ssl, identity_text.data()) != 1) {
        return false;
    }
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT);
    return SSL_set1_host(ssl, identity_text.data()) == 1;
}

std::unique_ptr<SslContext> SslContext::CreateClient(const TlsConfig& config) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        LOG_ERROR("failed to create TLS client context");
        return nullptr;
    }

    if (!ConfigureTlsProtocolVersions(
            ctx, config.min_version, config.max_version)) {
        LOG_ERROR("invalid TLS client protocol version policy");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (!ConfigureTlsClientAlpn(ctx, config.alpn)) {
        LOG_ERROR("invalid TLS client ALPN policy");
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (config.cert_file.empty() != config.key_file.empty()) {
        LOG_ERROR("TLS client certificate and private key must be configured together");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if ((config.HasCertificatePair() || !config.ca_file.empty()) && !config.pem) {
        LOG_ERROR("TLS client files were not loaded with the configuration");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (config.HasCertificatePair() &&
        !ConfigureTlsCertificatePem(ctx, *config.pem)) {
        LOG_ERROR("failed to load TLS client certificate from {}", config.cert_file);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (config.allow_insecure && !config.ca_file.empty()) {
        LOG_ERROR("TLS client CA cannot be used when certificate verification is disabled");
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (config.allow_insecure) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        const bool trust_loaded = config.ca_file.empty()
            ? SSL_CTX_set_default_verify_paths(ctx) == 1
            : ConfigureTlsTrustedCaPem(ctx, config.pem->trusted_ca);
        if (!trust_loaded) {
            LOG_ERROR("failed to load TLS client trust store from {}",
                      config.ca_file.empty() ? "system defaults"
                                             : config.ca_file);
            SSL_CTX_free(ctx);
            return nullptr;
        }
    }

    return std::unique_ptr<SslContext>(new SslContext(ctx));
}

SslContext::~SslContext() = default;
