#include "transport/tls_stream.hpp"
#include "transport/tcp_stream.hpp"
#include "transport/reality_tls.hpp"
#include "transport/tls_context.hpp"
#include "transport/async_write_gate.hpp"
#include "transport/stream_settings.hpp"
#include "infra/log.hpp"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <asio/ssl/error.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <string>
#include <vector>


// ============================================================================
// TlsStream 实现
// ============================================================================

namespace transport {

namespace {

// Populated explicitly before Worker startup; BIO_METHOD and SSL-owned memory
// use BoringSSL's allocator hooks (routed to mimalloc).
std::unique_ptr<BIO_METHOD, decltype(&BIO_meth_free)> tls_bio_method{nullptr, BIO_meth_free};

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

}  // namespace

struct TlsStream::Impl final : private transport::CancellationSubscription {
    using Gate = AsyncWriteGate;
    enum class Kind { Handshake, Read, Write, Shutdown };

    struct Invocation {
        // Only unsent ciphertext needs owned storage; bound handshake flights
        // and never retain a library buffer across another SSL call.
        static constexpr std::size_t kOutputLimit = 64 * 1024;
        std::optional<std::vector<uint8_t>> output;
        IoErrorCode transport_error;
        std::exception_ptr failure;
        std::uint64_t generation = 0;
        std::uint32_t library_error = 0;  // ERR_get_error() width
        int ssl_error = SSL_ERROR_NONE;
        int result = 0;
        // The direct BIO send hit EAGAIN and nothing was sent after it.
        bool write_blocked = false;
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
        std::optional<common::SignalChannel> wake;
    };

    // Registers the wait so BioRead can interrupt it when another SSL call has
    // already consumed this readiness.
    struct InputWait {
        InputWait(Impl& owner, net::cancellation_slot parent)
            : owner(owner), bridge(parent) {
            owner.input_wait = &bridge;
        }
        ~InputWait() { owner.input_wait = nullptr; }
        Impl& owner;
        transport::CancellationBridge bridge;
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
    struct PrependedPlaintext {
        common::MultiBuffer data;
    };

    Impl(std::unique_ptr<TcpStream> inner, const SslContext& context, bool server)
        : tcp(std::move(inner))
        , ssl(nullptr, SSL_free) {
        if (!tcp) throw std::invalid_argument("TlsStream requires TcpStream");
        if (!tls_bio_method)
            throw std::logic_error("TlsStream::InitializeIo must precede Worker startup");
        SSL_CTX* raw = context.AcquireNative();
        if (!raw) throw std::runtime_error("TLS certificate expired without a renewed snapshot");
        ssl.reset(SSL_new(raw));
        if (!ssl) throw std::bad_alloc();
        SSL_set_max_send_fragment(ssl.get(), common::Buffer::kSize);
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
            if (self.input_wait) self.input_wait->Interrupt();
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
            call.write_blocked = error == io_error::would_block || error == io_error::try_again;
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
        // BoringSSL ERR_clear_error frees and wipes every queue slot even when
        // empty; the queue is normally empty here, so only clear stale errors.
        if (ERR_peek_error() != 0) ERR_clear_error();
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
        if (call.library_error != 0) ERR_clear_error();
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
        const auto ec = co_await tcp->WaitReadable(waiting.bridge.Slot());
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
                            net::as_tuple(net::use_awaitable)));
                } else {
                    std::tie(ec) = co_await turn.wake->async_receive(
                        net::as_tuple(net::use_awaitable));
                }
                if (ec) throw IoSystemError(io_error::operation_aborted);
                CheckCancellation(epoch);
            }
            const net::const_buffer out_buf = net::buffer(*call.output);
            // Without a previous turn nothing suspended since the BIO send,
            // so its EAGAIN still holds: wait for writability before sending.
            co_await tcp->WriteBuffersFrom(std::span<const net::const_buffer>(&out_buf, 1), 0,
                                           !turn.previous && call.write_blocked);
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
                       net::const_buffer source, common::BufferGuard* allocated,
                       int& sync_result) {
        lease = engine_gate.TryAcquire();
        if (!lease) return false;
        CheckCancellation(epoch);
        if (kind == Kind::Read && !tcp->CanRead()) {
            sync_result = 0;
            return true;
        }
        if (allocated && !*allocated) {
            *allocated = common::BufferGuard{common::Buffer::New()};
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
        common::BufferGuard* allocated) {
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
                        *allocated = common::BufferGuard{common::Buffer::New()};
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

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() {
        if (!tcp->CanRead()) co_return common::MultiBuffer{};
        ActiveDirection active(read_active);
        try {
            if ((SSL_get_shutdown(ssl.get()) & SSL_RECEIVED_SHUTDOWN) != 0)
                co_return common::MultiBuffer{};
            // Socket wait has no payload allocation. Always retry SSL first when its
            // reusable read buffer contains a record/retained plaintext or when TCP
            // still holds bounded nonblocking drain budget from the last readiness.
            if (SSL_pending(ssl.get()) == 0 && SSL_has_pending(ssl.get()) == 0 &&
                !tcp->TryConsumeReadableBudget()) {
                co_await WaitForInput(cancel_epoch, input_generation);
            }
            const auto epoch = cancel_epoch;
            common::BufferGuard out;
            Gate::Lease lease;
            std::optional<Invocation> call;
            int n = 0;
            if (!TryInvokeOnce(Kind::Read, lease, call, epoch, {}, {}, &out, n)) {
                n = co_await FinishPerform(
                    Kind::Read, std::move(lease), std::move(call), epoch, false,
                    {}, {}, &out);
            }
            if (n == 0) co_return common::MultiBuffer{};
            out->Produce(static_cast<uint32_t>(n));
            co_return common::MultiBuffer{std::move(out)};
        } catch (const IoSystemError& error) {
            if (error.code() == io_error::eof && !tcp->CanRead())
                co_return common::MultiBuffer{};
            throw;
        }
    }

    net::awaitable<void> Write(
        std::span<const net::const_buffer> buffers,
        common::MultiBuffer owned = {}) {
        struct ClearOwned {
            common::MultiBuffer& mb;
            ~ClearOwned() noexcept { mb.clear(); }
        } clear_owned{owned};
        net::const_buffer owned_buffer;
        if (!owned.empty()) {
            const auto bytes = owned.FrontSpan();
            if (bytes.empty()) co_return;
            owned_buffer = net::buffer(bytes.data(), bytes.size());
            buffers = {&owned_buffer, 1};
        }
        ActiveDirection active(write_active);
        try {
            // Bound each application operation's output independently of the
            // caller's payload size and keep SSL retries stable. A fragment is
            // packed across caller buffers: one frame's header and payload
            // share a record and a TCP send, rather than leaving the payload
            // record behind the header under Nagle until the peer's delayed ACK.
            common::BufferGuard staging;
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
                if (current.size() >= common::Buffer::kSize || index + 1 == buffers.size()) {
                    fragment = net::buffer(
                        current, std::min<std::size_t>(current.size(), common::Buffer::kSize));
                } else {
                    if (!staging) {
                        staging = common::BufferGuard{common::Buffer::New()};
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
    transport::CancellationBridge* input_wait = nullptr;
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
    common::MultiBuffer plaintext_prefix) {
    if (!handshake_done_ || impl_->handshaking || impl_->read_active ||
        impl_->write_active || impl_->invocation || !impl_->tcp ||
        !impl_->tcp->IsOpen()) {
        return std::nullopt;
    }
    DetachedTlsState state;
    state.is_server = is_server_;
    if (impl_->prepended_plaintext) {
        if (plaintext_prefix.empty()) {
            plaintext_prefix = std::move(impl_->prepended_plaintext->data);
        } else {
            impl_->prepended_plaintext->data.MoveTo(plaintext_prefix);
        }
        impl_->prepended_plaintext.reset();
    }
    state.plaintext_prefix = std::move(plaintext_prefix);
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
        stream->PrependReadMultiBuffer(std::move(state.plaintext_prefix));
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
        std::string spider_x = std::move(reality_client_state_->spider_x);
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
                std::string{}.swap(spider_x);
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
        return std::string_view(reinterpret_cast<const char*>(data), len);
    }
    return {};
}

bool TlsStream::EnableRawRead() noexcept {
    if (!handshake_done_ || impl_->handshaking || impl_->read_active ||
        impl_->invocation || !impl_->tcp->CanRead()) return false;
    // BoringSSL reads only the bytes the current TLS record still needs, so a
    // completed SSL_read never fetches the next record. Refuse an outstanding
    // partial encrypted record rather than losing it or mistaking it for raw
    // Vision bytes.
    if (SSL_has_pending(NativeSsl()) && SSL_pending(NativeSsl()) == 0) return false;
    impl_->raw_read = true;
    return true;
}

void TlsStream::PrependReadBytes(std::span<const uint8_t> data) {
    if (data.empty()) return;
    if (!impl_->tcp->CanRead()) {
        throw IoSystemError(io_error::operation_aborted, "TLS read closed");
    }
    common::MultiBuffer prefix;
    if (!prefix.AppendSpan(data)) {
        throw std::bad_alloc();
    }
    PrependReadMultiBuffer(std::move(prefix));
}

void TlsStream::PrependReadMultiBuffer(common::MultiBuffer&& mb) {
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
        throw IoSystemError(io_error::connection_reset, "TLS handshake failed during read");
    if (impl_->raw_read && SSL_pending(NativeSsl()) == 0) {
        Impl::ActiveDirection active(impl_->read_active);
        co_return co_await impl_->tcp->AsyncRead(buffer);
    }
    co_return co_await impl_->AsyncRead(buffer);
}

net::awaitable<common::MultiBuffer> TlsStream::ReadMultiBuffer() {
    if (handshake_done_ && !impl_->prepended_plaintext &&
        (!impl_->raw_read || SSL_pending(NativeSsl()) != 0)) {
        return impl_->ReadMultiBuffer();
    }
    return ReadMultiBufferSlow();
}

net::awaitable<common::MultiBuffer> TlsStream::ReadMultiBufferSlow() {
    if (!impl_->tcp->CanRead()) co_return common::MultiBuffer{};
    if (impl_->prepended_plaintext) {
        auto data = std::move(impl_->prepended_plaintext->data);
        impl_->prepended_plaintext.reset();
        co_return data;
    }
    if (!handshake_done_ && !co_await Handshake())
        throw IoSystemError(io_error::connection_reset, "TLS handshake failed during read");
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

net::awaitable<void> TlsStream::WriteMultiBuffer(common::MultiBuffer mb) {
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
        throw IoSystemError(io_error::connection_reset, "TLS handshake failed during write");
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

}  // namespace transport
