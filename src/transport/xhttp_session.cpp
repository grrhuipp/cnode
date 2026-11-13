#include "transport/xhttp_session.hpp"

#include "transport/http1_handshake.hpp"
#include "app/group_coordinator.hpp"
#include "common/awaitable_task_group.hpp"
#include "common/const_buffer_span.hpp"
#include "infra/log.hpp"
#include "transport/http_headers.hpp"
#include "transport/tcp_stream.hpp"
#include "transport/tls_stream.hpp"
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/steady_timer.hpp>

#include <array>
#include <charconv>
#include <exception>
#include <optional>
#include <string>
#include <atomic>
#include <unordered_map>
#include <asio/this_coro.hpp>
#include <vector>

namespace transport {
namespace {

constexpr size_t kXHttpMaxPacketSessions = 1024;

constexpr std::string_view kXHttpRefererPadding =
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
static_assert(kXHttpRefererPadding.size() == 100);

// Strict 1*DIGIT; rejects signs, whitespace and overflow.
[[nodiscard]] std::optional<uint64_t> ParseU64Decimal(std::string_view value) {
    if (value.empty() || value.front() < '0' || value.front() > '9') {
        return std::nullopt;
    }
    uint64_t out = 0;
    const char* const end = value.data() + value.size();
    const auto [ptr, ec] = std::from_chars(value.data(), end, out);
    if (ec != std::errc{} || ptr != end) {
        return std::nullopt;
    }
    return out;
}

class XHttpPacketUpServerStream final : public AsyncStream {
    struct SessionCancellation final : transport::CancellationSubscription {
        explicit SessionCancellation(XHttpPacketUpServerStream& owner) noexcept : owner(owner) {}
        XHttpPacketUpServerStream& owner;
    private:
        void OnCancellation(transport::Cancellation cancellation) noexcept override {
            if (cancellation.terminal) {
                owner.NotifyClosed(cancellation.reason);
                owner.downlink_->Cancel();
            } else {
                Resubscribe(owner.session_->Cancellation());
                owner.NotifyCancellation(cancellation.reason);
            }
        }
    };
    struct DownlinkCancellation final : transport::CancellationSubscription {
        explicit DownlinkCancellation(XHttpPacketUpServerStream& owner) noexcept : owner(owner) {}
        XHttpPacketUpServerStream& owner;
    private:
        void OnCancellation(transport::Cancellation cancellation) noexcept override {
            if (cancellation.terminal) {
                owner.NotifyClosed(cancellation.reason);
                owner.session_->Close();
            } else {
                Resubscribe(owner.downlink_->Cancellation());
                owner.NotifyCancellation(cancellation.reason);
            }
        }
    };

public:
    transport::EofAction ReadEofAction() const noexcept override {
        return downlink_ ? downlink_->ReadEofAction() : AsyncStream::ReadEofAction();
    }

    XHttpPacketUpServerStream(std::shared_ptr<XHttpPacketUpSession> session,
                              std::unique_ptr<AsyncStream> downlink)
        : session_(std::move(session))
        , downlink_(std::move(downlink))
        , deadline_(session_->IoContext(), *this) {
        session_cancel_.Resubscribe(session_->Cancellation());
        downlink_cancel_.Resubscribe(downlink_->Cancellation());
        (void)session_->AttachDownlink();
    }

    ~XHttpPacketUpServerStream() noexcept override {
        Close();
    }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        const size_t n = co_await session_->AsyncRead(buffer);
        if (n != 0 && downlink_) {
            if (auto* tcp = BaseTcpStreamOf(*downlink_)) {
                tcp->TouchActivity();
            }
        }
        co_return n;
    }

    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        if (!downlink_) {
            throw IoSystemError(io_error::operation_aborted, "xhttp downlink closed");
        }
        return downlink_->AsyncWrite(buffer);
    }

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        auto mb = co_await session_->ReadMultiBuffer();
        if (!mb.empty() && downlink_) {
            if (auto* tcp = BaseTcpStreamOf(*downlink_)) {
                tcp->TouchActivity();
            }
        }
        co_return mb;
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer mb) override {
        if (!downlink_) {
            mb.clear();
            throw IoSystemError(io_error::operation_aborted, "xhttp downlink closed");
        }
        return downlink_->WriteMultiBuffer(std::move(mb));
    }

    net::awaitable<void> WriteBuffers(
        std::span<const net::const_buffer> buffers) override {
        if (!downlink_) {
            throw IoSystemError(io_error::operation_aborted, "xhttp downlink closed");
        }
        return downlink_->WriteBuffers(buffers);
    }

    void ShutdownRead() override {
        session_cancel_.Unsubscribe();
        if (session_) {
            session_->Close();
        }
    }

    void ShutdownWrite() override {
        if (downlink_) {
            downlink_->ShutdownWrite();
        }
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        if (downlink_) {
            return downlink_->AsyncShutdownWrite();
        }
        return []() -> net::awaitable<void> { co_return; }();
    }

    void Cancel() noexcept override {
        NotifyCancellation();
        if (session_) {
            session_->CancelPendingOperations();
        }
        if (downlink_) {
            downlink_->Cancel();
        }
    }

    void Close() override {
        deadline_.Clear();
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        session_cancel_.Unsubscribe();
        downlink_cancel_.Unsubscribe();
        if (session_) {
            session_->Close();
        }
        if (downlink_) {
            downlink_->Close();
        }
    }

    void CloseAbortive() override {
        deadline_.Clear();
        NotifyClosed();
        if (closed_) {
            return;
        }
        closed_ = true;
        session_cancel_.Unsubscribe();
        downlink_cancel_.Unsubscribe();
        if (session_) {
            session_->Close();
        }
        if (downlink_) {
            downlink_->CloseAbortive();
        }
    }

    int NativeHandle() const override {
        return downlink_ ? downlink_->NativeHandle() : -1;
    }

    bool IsOpen() const override {
        return !closed_ && downlink_ && downlink_->IsOpen();
    }

protected:
    StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &deadline_; }
    TcpStream* BaseTcpStream() override {
        return downlink_ ? BaseTcpStreamOf(*downlink_) : nullptr;
    }

    const TcpStream* BaseTcpStream() const override {
        return downlink_ ? BaseTcpStreamOf(*downlink_) : nullptr;
    }

private:
    std::shared_ptr<XHttpPacketUpSession> session_;
    std::unique_ptr<AsyncStream> downlink_;
    StreamPhaseDeadline deadline_;
    SessionCancellation session_cancel_{*this};
    DownlinkCancellation downlink_cancel_{*this};
    bool closed_ = false;
};

class XHttpClientTaskOwner final : public net::execution_context::service {
public:
    static net::execution_context::id id;
    explicit XHttpClientTaskOwner(net::execution_context& context)
        : net::execution_context::service(context) {}

    void Spawn(net::any_io_executor executor, net::awaitable<void> task,
               transport::CancellationSource& cancellation) {
        if (joining_) throw IoSystemError(io_error::operation_aborted);
        if (!tasks_) tasks_.emplace(std::move(executor));
        tasks_->Tasks().Spawn(std::move(task), &cancellation);
    }

    net::awaitable<void> Join() {
        joining_ = true;
        if (tasks_) {
            co_await tasks_->AsyncJoin();
            // Release the executor's domain reference before destroying its
            // Services, otherwise domain -> service -> executor forms a cycle.
            tasks_.reset();
        }
    }

private:
    void shutdown() override { tasks_.reset(); }
    std::optional<common::ResidentTaskGroup> tasks_;
    bool joining_ = false;
};

net::execution_context::id XHttpClientTaskOwner::id;

// Xray's upload response carries padding, not logical downlink data
// (splithttp/client.go OpenStream drains it with io.Copy(io.Discard)).
class XHttpUploadClientStream final : public AsyncStream {
public:
    XHttpUploadClientStream(net::any_io_executor executor,
                           net::execution_context& services,
                           std::unique_ptr<AsyncStream> stream)
        : state_(std::make_shared<SharedState>(std::move(stream))) {
        net::use_service<XHttpClientTaskOwner>(services).Spawn(
            std::move(executor), DrainOwned(state_), drain_cancellation_);
    }
    ~XHttpUploadClientStream() noexcept override { Close(); }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer) override { co_return 0; }
    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        co_return common::MultiBuffer{};
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        return state_->stream->AsyncWrite(buffer);
    }
    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer payload) override {
        return state_->stream->WriteMultiBuffer(std::move(payload));
    }
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return state_->stream->WriteBuffers(buffers);
    }
    void ShutdownWrite() override { state_->stream->ShutdownWrite(); }
    net::awaitable<void> AsyncShutdownWrite() override {
        return state_->stream->AsyncShutdownWrite();
    }
    void Cancel() noexcept override { state_->stream->Cancel(); }
    void Close() override {
        state_->closed = true;
        drain_cancellation_.Stop();
        state_->stream->Close();
    }
    void CloseAbortive() override {
        state_->closed = true;
        drain_cancellation_.Stop();
        state_->stream->CloseAbortive();
    }
    int NativeHandle() const override { return state_->stream->NativeHandle(); }
    bool IsOpen() const override { return state_->stream->IsOpen(); }
    transport::CancellationSource& Cancellation() noexcept override {
        return state_->stream->Cancellation();
    }

protected:
    TcpStream* BaseTcpStream() override { return BaseTcpStreamOf(*state_->stream); }
    const TcpStream* BaseTcpStream() const override { return BaseTcpStreamOf(*state_->stream); }

private:
    struct SharedState final {
        explicit SharedState(std::unique_ptr<AsyncStream> s) noexcept
            : stream(std::move(s)) {}
        std::unique_ptr<AsyncStream> stream;
        bool closed = false;
    };

    static net::awaitable<void> DrainOwned(std::shared_ptr<SharedState> state) {
        bool ok = false;
        try {
            ok = co_await DrainResponse(*state);
        } catch (...) {
            // This upload failure closes only its transport, not unrelated
            // resident tasks. The physical session still joins this callback.
        }
        if (ok) {
            state->stream->ShutdownRead();
        } else {
            state->stream->CloseAbortive();
        }
    }
    static net::awaitable<bool> DrainResponse(SharedState& state) {
        AsyncStream& stream = *state.stream;
        const auto should_retry = [&](const IoSystemError& e) noexcept {
            return e.code() == io_error::operation_aborted &&
                   !state.closed &&
                   stream.IsOpen();
        };
        Http1MessageHead head;
        while (true) {
            try {
                const auto res = co_await ReadHttp1MessageHead(stream, head);
                if (!res) {
                    co_return false;
                }
                const std::string_view status_line = ExtractStartLine(head.Text());
                if (HasStatusCode(status_line, "100") ||
                    HasStatusCode(status_line, "103")) {
                    continue;
                }
                if (!HasStatusCode(status_line, "200")) {
                    co_return false;
                }
                break;
            } catch (const IoSystemError& e) {
                if (!should_retry(e)) {
                    throw;
                }
            }
            if ((co_await net::this_coro::cancellation_state).cancelled() !=
                net::cancellation_type::none) {
                co_await net::this_coro::reset_cancellation_state();
            }
        }
        // Connection: close forbids a following response. Discard read-ahead
        // and subsequent wire bytes, including optional chunk framing.
        head.storage = common::BufferGuard{};
        while (true) {
            try {
                if ((co_await stream.ReadMultiBuffer()).empty()) {
                    break;
                }
            } catch (const IoSystemError& e) {
                if (!should_retry(e)) {
                    throw;
                }
            }
            if ((co_await net::this_coro::cancellation_state).cancelled() !=
                net::cancellation_type::none) {
                co_await net::this_coro::reset_cancellation_state();
            }
        }
        co_return true;
    }

    // Close cancels the reader; the registered task retains the transport
    // until the physical session's explicit resident-task join completes.
    std::shared_ptr<SharedState> state_;
    transport::CancellationSource drain_cancellation_;
};

// `close_connection` announces that the server ends the connection after this
// response (RFC 9112 9.6); otherwise an HTTP/1.1 connection persists.
net::awaitable<bool> SendXHttpResponseHeaders(
    AsyncStream& stream,
    const XHttpConfig& xhttp_cfg,
    bool chunked_body,
    bool close_connection) {
    const bool add_sse = !xhttp_cfg.no_sse_header &&
                         !FindHttpHeader(xhttp_cfg.headers, "Content-Type");
    Http1HeaderBuffer response;
    response.reserve(192 + (xhttp_cfg.headers.size() + (add_sse ? 1 : 0)) * 32);
    response.append("HTTP/1.1 200 OK\r\n"
                    "X-Accel-Buffering: no\r\n"
                    "Cache-Control: no-store\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Access-Control-Allow-Methods: GET, POST\r\n");
    if (chunked_body) {
        response.append("Transfer-Encoding: chunked\r\n");
    } else {
        response.append("Content-Length: 0\r\n");
    }
    if (close_connection) {
        response.append("Connection: close\r\n");
    }
    for (const auto& [key, value] : xhttp_cfg.headers) {
        if (key.empty() ||
            common::EqualsAsciiCI(key, "Transfer-Encoding") ||
            common::EqualsAsciiCI(key, "Content-Length") ||
            common::EqualsAsciiCI(key, "Connection")) {
            continue;
        }
        AppendHeaderLine(response, key, value);
    }
    if (add_sse) {
        AppendHeaderLine(response, "content-type", "text/event-stream");
    }
    response.append("\r\n");
    const auto view = response.View();
    const net::const_buffer buffer(view.data(), view.size());
    try {
        co_await stream.WriteBuffers(std::span<const net::const_buffer>{&buffer, 1});
    } catch (...) {
        co_return false;
    }
    co_return true;
}

net::awaitable<bool> SendEmptyHttp1Response(AsyncStream& stream,
                                            std::string_view status,
                                            bool close_connection) {
    Http1HeaderBuffer response;
    response.reserve(64 + status.size());
    response.append("HTTP/1.1 ");
    response.append(status);
    response.append("\r\nContent-Length: 0\r\n");
    if (close_connection) {
        response.append("Connection: close\r\n");
    }
    response.append("\r\n");
    const auto view = response.View();
    const net::const_buffer buffer(view.data(), view.size());
    try {
        co_await stream.WriteBuffers(std::span<const net::const_buffer>{&buffer, 1});
    } catch (...) {
        co_return false;
    }
    co_return true;
}

// Consumes a Content-Length body nobody will use, keeping the connection in
// step with its next request. Bodies above the packet budget are refused.
net::awaitable<bool> DiscardHttp1Body(AsyncStream& connection, uint64_t length) {
    if (length > XHttpPacketQueue::kMaxQueuedBytes) {
        co_return false;
    }
    while (length > 0) {
        common::MultiBuffer mb = co_await connection.ReadMultiBuffer();
        if (mb.empty()) {
            co_return false;
        }
        const size_t n = mb.DropPrefixBytes(
            static_cast<size_t>(std::min<uint64_t>(length, mb.byte_size())));
        if (n == 0) {
            co_return false;
        }
        length -= n;
        connection.PrependReadMultiBuffer(std::move(mb));
    }
    co_return true;
}

// Body size is bounded by the session payload budget, never by the declared
// Content-Length alone.
net::awaitable<std::optional<common::MultiBuffer>> ReadXHttpPacketBody(
    std::optional<uint64_t> content_length,
    XHttpPacketUpSession::Upload& upload) {
    common::MultiBuffer payload;

    if (content_length) {
        if (*content_length > XHttpPacketQueue::kMaxQueuedBytes) {
            co_return std::nullopt;
        }
        auto remaining = static_cast<size_t>(*content_length);
        while (remaining > 0) {
            const size_t n = co_await upload.Read(
                payload, std::min(static_cast<size_t>(common::Buffer::kSize), remaining));
            if (n == 0) {
                co_return std::nullopt;
            }
            remaining -= n;
        }
        co_return payload;
    }

    while (true) {
        const size_t n = co_await upload.Read(payload, common::Buffer::kSize);
        if (n == 0) {
            break;
        }
        if (payload.byte_size() > XHttpPacketQueue::kMaxQueuedBytes) {
            payload.clear();
            co_return std::nullopt;
        }
    }
    co_return payload;
}

// RFC 9112 9.3: an HTTP/1.1 request leaves its connection open unless it
// carries the "close" option in any Connection field line (9.6); earlier
// versions are not kept alive.
[[nodiscard]] bool RequestKeepsConnection(std::string_view request_line,
                                          std::string_view request) {
    return request_line.ends_with(" HTTP/1.1") &&
           !HeaderListContainsTokenCI(request, "Connection", "close");
}

// RFC 9112 6.1-6.3 framing of an XHTTP upload body. Exactly one is accepted:
// a single Content-Length field holding 1*DIGIT, or a single Transfer-Encoding
// field naming only "chunked". Both together (6.1), repeated or invalid
// lengths (6.3) and other codings are ambiguous or unsupported here; without
// either the body is empty (6.3) and carries no upload. All are refused.
[[nodiscard]] std::optional<Http1ReadFraming> XHttpUploadFraming(std::string_view request) {
    const size_t transfer_encodings = CountHeadersCI(request, "Transfer-Encoding");
    const size_t content_lengths = CountHeadersCI(request, "Content-Length");
    if (transfer_encodings == 1 && content_lengths == 0 &&
        common::EqualsAsciiCI(common::TrimAscii(ExtractHeaderValueCI(request, "Transfer-Encoding")), "chunked")) {
        return Http1BodyChunked{};
    }
    if (content_lengths == 1 && transfer_encodings == 0) {
        if (const auto length = ParseU64Decimal(
                common::TrimAscii(ExtractHeaderValueCI(request, "Content-Length")))) {
            return Http1BodyContentLength{.bytes = *length};
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool IsBodyFramingOrHostHeader(std::string_view key) {
    return common::EqualsAsciiCI(key, "Host") ||
           common::EqualsAsciiCI(key, "Content-Length") ||
           common::EqualsAsciiCI(key, "Transfer-Encoding");
}

void BuildXHttp1ClientRequest(
    Http1HeaderBuffer& request,
    const HttpClientRequestView& req,
    std::string_view host,
    std::string_view content_length,
    bool chunked_upload) {
    const std::string_view req_path = EffectiveHttpPath(req.path);
    const std::string_view method = req.method.empty()
        ? std::string_view("PUT") : req.method;
    const size_t header_count =
        (req.headers ? req.headers->size() : 0) +
        (!req.default_content_type.empty() ? 1 : 0) +
        (!req.default_referer.empty() ? 1 : 0);
    const size_t reserve_size = 224 + method.size() + req_path.size() + host.size() +
                                content_length.size() + header_count * 32;

    request.reserve(reserve_size);
    AppendRequestStart(request, method, req_path, host);
    if (chunked_upload) {
        request.append("Transfer-Encoding: chunked\r\n");
        // Match Xray's H1 DisableKeepAlives: Go's server otherwise drains the
        // request body on its first response flush, stealing live upload bytes.
        request.append("Connection: close\r\n");
    } else if (!content_length.empty()) {
        AppendHeaderLine(request, "Content-Length", content_length);
    }
    if (req.headers) {
        for (const auto& [key, value] : *req.headers) {
            if (key.empty() || IsBodyFramingOrHostHeader(key) ||
                (chunked_upload && common::EqualsAsciiCI(key, "Connection"))) {
                continue;
            }
            AppendHeaderLine(request, key, value);
        }
    }
    if (!req.default_content_type.empty()) {
        AppendHeaderLine(request, "content-type", req.default_content_type);
    }
    if (!req.default_referer.empty()) {
        AppendHeaderLine(request, "referer", req.default_referer);
    }
    request.append("\r\n");
}

net::awaitable<common::ErrorCode> SendXHttp1ClientRequest(
    AsyncStream& stream,
    const HttpClientRequestView& cfg,
    std::string_view host,
    std::string_view content_length,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload,
    size_t payload_len) {
    const bool chunked_upload = kind == XHttpClientRequestKind::StreamUp;
    Http1HeaderBuffer request;
    BuildXHttp1ClientRequest(
        request, cfg, host, content_length, chunked_upload);
    const std::string_view head_view = request.View();
    common::ConstBufferSpanBuilder<20> out;
    out.Append(net::buffer(head_view.data(), head_view.size()));
    Http1ChunkPrefixBuffer prefix{};
    if (chunked_upload) {
        if (payload_len > 0 &&
            !AppendHttp1Chunk(out, prefix, packet_payload, payload_len)) {
            co_return common::ErrorCode::PROTOCOL_ENCODE_FAILED;
        }
    } else if (kind == XHttpClientRequestKind::PacketUp && payload_len > 0) {
        out.AppendBuffers(packet_payload);
    }
    try {
        co_await stream.WriteBuffers(out.Span());
    } catch (...) {
        co_return common::ErrorCode::SOCKET_WRITE_FAILED;
    }
    co_return common::ErrorCode::OK;
}

// Coordinator-owned metadata only. Each admitted record reserves its own
// retirement node: noexcept close cannot lose an event to mailbox exhaustion.
class XHttpSessionDirectory final : public net::execution_context::service {
    using Key = BasicXHttpPacketSessionKey<std::string>;

public:
    static net::execution_context::id id;
    explicit XHttpSessionDirectory(net::execution_context& context)
        : net::execution_context::service(context) {}

    struct OwnerWaiter final : std::enable_shared_from_this<OwnerWaiter> {
        net::io_context& io;
        net::steady_timer timer;
        std::atomic<bool> notified{false};

        explicit OwnerWaiter(net::io_context& io_context)
            : io(io_context)
            , timer(io_context, net::steady_timer::time_point::max()) {}

        void Notify() noexcept {
            if (notified.exchange(true, std::memory_order_acq_rel)) return;
            try {
                net::post(io, [self = shared_from_this()] {
                    self->timer.cancel();
                });
            } catch (...) {}
        }

        void CancelOnOwner() noexcept {
            notified.store(true, std::memory_order_release);
            timer.cancel();
        }
    };

    struct Record {
        enum class State : uint8_t { Reserved, Live, Retired };
        XHttpSessionDirectory* directory;
        const Key* key = nullptr;
        net::io_context* owner = nullptr;
        std::atomic<State> state{State::Reserved};
        Record* incoming_next = nullptr;
        Record* previous = nullptr;
        Record* next = nullptr;
        bool processed = false;
        bool activated = false;
        std::vector<std::shared_ptr<OwnerWaiter>> owner_waiters;

        Record(XHttpSessionDirectory& directory, net::io_context* owner)
            : directory(&directory), owner(owner) {}
        void Retire(bool only_reserved = false) noexcept;
        bool MarkLive() noexcept {
            auto expected = State::Reserved;
            return state.compare_exchange_strong(expected, State::Live,
                       std::memory_order_acq_rel) || expected == State::Live;
        }
        bool Retired() const noexcept {
            return state.load(std::memory_order_acquire) == State::Retired;
        }
        void NotifyOwnerWaiters() noexcept {
            auto waiters = std::move(owner_waiters);
            owner_waiters.clear();
            for (auto& waiter : waiters) {
                if (waiter) waiter->Notify();
            }
        }
    };

    struct Claim {
        net::io_context* owner = nullptr;
        std::shared_ptr<Record> record;
        std::shared_ptr<OwnerWaiter> wait_owner;
        bool reservation = false;
        bool retry = false;
        Claim() = default;
        Claim(net::io_context* owner, std::shared_ptr<Record> record, bool reservation)
            : owner(owner), record(std::move(record)), reservation(reservation) {}
        Claim(Claim&& other) noexcept
            : owner(std::exchange(other.owner, nullptr)),
              record(std::move(other.record)),
              wait_owner(std::move(other.wait_owner)),
              reservation(std::exchange(other.reservation, false)),
              retry(other.retry) {}
        Claim(const Claim&) = delete;
        Claim& operator=(const Claim&) = delete;
        ~Claim() {
            if (reservation && record) record->Retire(true);
        }
    };

    Claim Acquire(std::string_view session_namespace, std::string_view session_id,
                  XHttpSessionAccess access, net::io_context* current,
                  bool bind_owner = true) {
        DrainRetirements();
        auto found = entries_.find(XHttpPacketSessionKeyRef{session_id, session_namespace});
        if (found != entries_.end() && !found->second->Retired()) {
            auto& record = found->second;
            if (!record->owner && bind_owner && current) {
                record->owner = current;
                record->NotifyOwnerWaiters();
                return {current, record, true};
            }
            if (record->owner) {
                return {record->owner, record, false};
            }
            Claim pending;
            pending.record = record;
            if (current) {
                pending.wait_owner = std::make_shared<OwnerWaiter>(*current);
                record->owner_waiters.push_back(pending.wait_owner);
            }
            return pending;
        }
        if (access == XHttpSessionAccess::Join ||
            (found != entries_.end() && access != XHttpSessionAccess::Open))
            return {};
        if (found != entries_.end() && !found->second->processed) {
            Claim claim;
            claim.retry = true;
            return claim;
        }
        if (active_ == kMaxActive) return {};
        auto record = std::make_shared<Record>(
            *this, bind_owner ? current : nullptr);
        if (found == entries_.end()) {
            found = entries_.try_emplace(
                Key{std::string(session_id), std::string(session_namespace)}, record).first;
        } else {
            Unlink(*found->second);
            --ended_;
            found->second = record;
        }
        record->key = &found->first;
        ++active_;
        if (!bind_owner) {
            Claim pending;
            pending.record = std::move(record);
            if (current) {
                pending.wait_owner = std::make_shared<OwnerWaiter>(*current);
                pending.record->owner_waiters.push_back(pending.wait_owner);
            }
            return pending;
        }
        return {current, std::move(record), true};
    }

private:
    void Enqueue(Record& record) noexcept {
        auto* previous = incoming_.load(std::memory_order_relaxed);
        do { record.incoming_next = previous; }
        while (!incoming_.compare_exchange_weak(previous, &record,
                   std::memory_order_release, std::memory_order_relaxed));
    }

    void DrainRetirements() noexcept {
        auto* batch = incoming_.exchange(nullptr, std::memory_order_acquire);
        Record* fifo = nullptr;
        while (batch) {
            auto* next = batch->incoming_next;
            batch->incoming_next = fifo;
            fifo = batch;
            batch = next;
        }
        while (fifo) {
            auto* record = fifo;
            fifo = record->incoming_next;
            record->processed = true;
            record->owner = nullptr;
            record->NotifyOwnerWaiters();
            --active_;
            if (!record->activated) {
                if (auto it = entries_.find(*record->key);
                    it != entries_.end() && it->second.get() == record) {
                    entries_.erase(it);
                }
                continue;
            }
            record->previous = last_;
            if (last_) last_->next = record;
            else first_ = record;
            last_ = record;
            if (++ended_ > kXHttpMaxPacketSessions) {
                auto* oldest = first_;
                Unlink(*oldest);
                entries_.erase(*oldest->key);
                --ended_;
            }
        }
    }

    void Unlink(Record& record) noexcept {
        if (record.previous) record.previous->next = record.next;
        else first_ = record.next;
        if (record.next) record.next->previous = record.previous;
        else last_ = record.previous;
        record.previous = record.next = nullptr;
    }

    void shutdown() override {
        // Domains retain their coordinator until session destructors finish.
        // Coordinator shutdown therefore has no concurrent producers.
        DrainRetirements();
        entries_.clear();
        first_ = last_ = nullptr;
        active_ = ended_ = 0;
    }

    static constexpr size_t kMaxActive = 64 * 1024;
    std::unordered_map<Key, std::shared_ptr<Record>, XHttpPacketSessionKeyHash, XHttpPacketSessionKeyEq> entries_;
    std::atomic<Record*> incoming_{nullptr};
    Record* first_ = nullptr;
    Record* last_ = nullptr;
    size_t active_ = 0;
    size_t ended_ = 0;
};

net::execution_context::id XHttpSessionDirectory::id;

void XHttpSessionDirectory::Record::Retire(bool only_reserved) noexcept {
    auto current = state.load(std::memory_order_acquire);
    do {
        if (current == State::Retired || (only_reserved && current != State::Reserved))
            return;
    } while (!state.compare_exchange_weak(current, State::Retired,
                 std::memory_order_acq_rel, std::memory_order_acquire));
    activated = (current == State::Live);
    directory->Enqueue(*this);
}

}  // namespace

net::awaitable<void> JoinXHttpClientTasks(net::execution_context& services) {
    if (net::has_service<XHttpClientTaskOwner>(services))
        co_await net::use_service<XHttpClientTaskOwner>(services).Join();
}

struct XHttpSessionTableEntry {
    XHttpSessionTable* table = nullptr;
    const XHttpPacketSessionKey* key = nullptr;
    std::weak_ptr<XHttpPacketUpSession> session;
    XHttpPacketUpSession* live = nullptr;
    XHttpSessionTableEntry* previous = nullptr;
    XHttpSessionTableEntry* next = nullptr;
    std::shared_ptr<XHttpSessionDirectory::Record> directory_record;
};

// Stable unordered-map nodes double as the bounded FIFO of ended ids. No
// insertion scans live/expired weak pointers, and retiring never allocates.
class XHttpSessionTable final : public net::execution_context::service {
public:
    static net::execution_context::id id;
    explicit XHttpSessionTable(net::execution_context& context)
        : net::execution_context::service(context) {}

    std::shared_ptr<XHttpPacketUpSession> Get(
        net::io_context& io, std::string_view session_namespace,
        std::string_view id, XHttpSessionAccess access,
        std::shared_ptr<XHttpSessionDirectory::Record> record = {}) {
        const XHttpPacketSessionKeyRef lookup{id, session_namespace};
        auto found = sessions_.find(lookup);
        if (found != sessions_.end() && found->second.live)
            return found->second.session.lock();
        if (access == XHttpSessionAccess::Join ||
            (found != sessions_.end() && access != XHttpSessionAccess::Open) ||
            active_ == kXHttpMaxPacketSessions)
            return nullptr;

        auto session = std::make_shared<XHttpPacketUpSession>(io);
        const bool inserting = found == sessions_.end();
        if (found == sessions_.end()) {
            XHttpPacketSessionKey key{
                .session_id = std::string(id),
                .session_namespace = std::string(session_namespace),
            };
            found = sessions_.try_emplace(std::move(key)).first;
        }
        if (record && !record->MarkLive()) {
            if (inserting) sessions_.erase(found);
            return nullptr;
        }
        if (!inserting) {
            Unlink(found->second);
            --ended_;
        }
        auto& entry = found->second;
        entry.table = this;
        entry.key = &found->first;
        entry.session = session;
        entry.live = session.get();
        entry.directory_record = std::move(record);
        session->table_entry_ = &entry;
        ++active_;
        return session;
    }

    void Retire(XHttpSessionTableEntry& entry) noexcept {
        if (entry.directory_record) {
            entry.directory_record->Retire();
            entry.directory_record.reset();
        }
        entry.live->table_entry_ = nullptr;
        entry.live = nullptr;
        entry.session.reset();
        --active_;
        entry.previous = last_;
        if (last_) last_->next = &entry;
        else first_ = &entry;
        last_ = &entry;
        if (++ended_ > kXHttpMaxPacketSessions) {
            auto* oldest = first_;
            Unlink(*oldest);
            sessions_.erase(*oldest->key);
            --ended_;
        }
    }

private:
    void shutdown() override {
        for (auto& [key, entry] : sessions_) {
            if (entry.live) {
                entry.live->table_entry_ = nullptr;
                if (entry.directory_record) entry.directory_record->Retire();
            }
        }
        sessions_.clear();
        first_ = last_ = nullptr;
        active_ = ended_ = 0;
    }

    void Unlink(XHttpSessionTableEntry& entry) noexcept {
        if (entry.previous) entry.previous->next = entry.next;
        else first_ = entry.next;
        if (entry.next) entry.next->previous = entry.previous;
        else last_ = entry.previous;
        entry.previous = entry.next = nullptr;
    }

    std::unordered_map<
        XHttpPacketSessionKey, XHttpSessionTableEntry,
        XHttpPacketSessionKeyHash,
        XHttpPacketSessionKeyEq> sessions_;
    XHttpSessionTableEntry* first_ = nullptr;
    XHttpSessionTableEntry* last_ = nullptr;
    size_t active_ = 0;
    size_t ended_ = 0;
};

net::execution_context::id XHttpSessionTable::id;

XHttpPacketUpSession::XHttpPacketUpSession(
    net::io_context& io_context)
    : io_context_(io_context)
    , input_signal_(net::any_io_executor(io_context.get_executor()), 1) {}
XHttpPacketUpSession::~XHttpPacketUpSession() noexcept {
    Unsubscribe();
    Retire();
}

net::io_context& XHttpPacketUpSession::IoContext() const noexcept {
    return io_context_;
}

void XHttpPacketUpSession::Retire() noexcept {
    if (table_entry_) table_entry_->table->Retire(*table_entry_);
}

XHttpPacketUpSession::Upload::Upload(XHttpPacketUpSession& session, AsyncStream& stream)
    : session_(session), stream_(stream) {
    if (!session.AcceptingInput() || !session.packet_queue_.AcquireUpload())
        throw IoSystemError(io_error::no_buffer_space, "xhttp upload admission exhausted");
    Resubscribe(session.Cancellation());
}

XHttpPacketUpSession::Upload::~Upload() noexcept {
    Unsubscribe();
    session_.Release(reserved_);
    session_.packet_queue_.ReleaseUpload();
}

net::awaitable<size_t> XHttpPacketUpSession::Upload::Read(
    common::MultiBuffer& payload, size_t limit) {
    if (payload.empty() || payload.FrontBuffer()->Available() == 0) {
        if (!session_.Reserve(common::Buffer::kSize)) {
            uint8_t excess;
            if (co_await stream_.AsyncRead(net::buffer(&excess, 1)) == 0) co_return 0;
            throw IoSystemError(io_error::no_buffer_space, "xhttp payload budget exhausted");
        }
        reserved_ += common::Buffer::kSize;
    }
    if (limit == 0) {
        co_return 0;
    }
    if (auto* tail = payload.FrontBuffer(); tail && tail->Available() != 0) {
        const size_t n = co_await stream_.AsyncRead(net::buffer(
            tail->Tail().data(), std::min(limit, size_t{tail->Available()})));
        tail->Produce(static_cast<uint32_t>(n));
        co_return n;
    }
    common::MultiBuffer chunk = co_await stream_.ReadMultiBuffer();
    common::BufferGuard first = chunk.pop_front();
    if (!first || first->IsEmpty()) {
        co_return 0;
    }
    const size_t n = std::min<size_t>(limit, first->Len());
    if (n < first->Len()) {
        stream_.PrependReadBytes(first->Bytes().subspan(n));
        first->end = first->start + static_cast<uint32_t>(n);
    }
    payload.push_back(std::move(first));
    co_return n;
}

bool XHttpPacketUpSession::Upload::Commit(uint64_t seq, common::MultiBuffer payload) {
    session_.Release(std::exchange(reserved_, 0));
    return session_.Push(seq, std::move(payload));
}

void XHttpPacketUpSession::Upload::OnCancellation(
    transport::Cancellation cancellation) noexcept {
    if (cancellation.terminal) {
        stream_.CloseAbortive();
    } else {
        Resubscribe(session_.Cancellation());
        stream_.Cancel();
    }
}

bool XHttpPacketUpSession::AttachStream(std::unique_ptr<AsyncStream> stream) {
    if (closed_ || input_closed_ || !stream) {
        return false;
    }
    if (!stream_input_.Attach(std::move(stream))) {
        return false;
    }
    auto upload = stream_input_.Snapshot();
    Resubscribe(upload->Cancellation());
    Wake();
    return true;
}

// The wake channel lives in this frame and stays published for the whole
// join, so a release signalled between two receives stays buffered. Nothing
// suspends between a condition check and its receive, and at most one join
// exists per session: only the first AttachStream succeeds.
net::awaitable<void> XHttpPacketUpSession::JoinAttachedUpload() {
    common::SignalChannel upload_signal(io_context_.get_executor(), 1);
    upload_signal_ = &upload_signal;
    struct Unpublish {
        common::SignalChannel*& published;
        ~Unpublish() noexcept { published = nullptr; }
    } unpublish{upload_signal_};
    std::exception_ptr failure;
    try {
        while (!stream_input_.Empty() || upload_reads_ != 0)
            co_await upload_signal.async_receive(net::use_awaitable);
    } catch (...) {
        failure = std::current_exception();
        Close();
    }
    if (failure) {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        while (!stream_input_.Empty() || upload_reads_ != 0)
            co_await upload_signal.async_receive(net::use_awaitable);
        std::rethrow_exception(failure);
    }
}

bool XHttpPacketUpSession::Push(uint64_t seq, common::MultiBuffer payload) {
    if (closed_ || input_closed_) {
        payload.clear();
        return false;
    }
    try {
        if (!packet_queue_.Push(seq, std::move(payload))) return false;
    } catch (...) {
        // Promotion may already have committed earlier complete packets.
        // Retire this logical session rather than expose a sequence gap.
        Close();
        throw;
    }
    Wake();
    return true;
}

void XHttpPacketUpSession::CloseInput() noexcept {
    if (input_closed_) {
        return;
    }
    input_closed_ = true;
    Retire();
    Wake();
}

void XHttpPacketUpSession::Close() noexcept {
    if (closed_) {
        return;
    }
    closed_ = true;
    input_closed_ = true;
    Retire();
    Unsubscribe();
    cancellation_.Stop();
    packet_queue_.Clear();
    if (auto stream = stream_input_.Take()) {
        stream->Close();
    }
    if (upload_signal_) (void)upload_signal_->try_send(IoErrorCode{});
    downlink_ready_.Stop();
    Wake();
}

bool XHttpPacketUpSession::AttachDownlink() noexcept {
    if (closed_ || downlink_attached_) {
        return false;
    }
    downlink_attached_ = true;
    downlink_ready_.Stop();
    return true;
}

net::awaitable<bool> XHttpPacketUpSession::AwaitDownlink(
    transport::CancellationSource& cancellation) {
    common::SignalChannel wake(io_context_.get_executor(), 1);
    struct ReadyWatch final : transport::CancellationSubscription {
        explicit ReadyWatch(common::SignalChannel& wake) noexcept : wake(wake) {}
        common::SignalChannel& wake;

    private:
        void OnCancellation(transport::Cancellation) noexcept override {
            (void)wake.try_send(IoErrorCode{});
        }
    } ready{wake};
    struct ConnectionCancellation final : transport::CancellationSubscription {
        explicit ConnectionCancellation(common::SignalChannel& wake) noexcept : wake(wake) {}
        common::SignalChannel& wake;
        bool cancelled = false;

    private:
        void OnCancellation(transport::Cancellation) noexcept override {
            cancelled = true;
            (void)wake.try_send(IoErrorCode{});
        }
    } watch{wake};
    ready.Resubscribe(downlink_ready_);
    watch.Resubscribe(cancellation);
    while (!downlink_attached_ && !closed_ && !watch.cancelled) {
        auto [ec] = co_await wake.async_receive(net::as_tuple(net::use_awaitable));
        (void)ec;
        if ((co_await net::this_coro::cancellation_state).cancelled() !=
            net::cancellation_type::none) {
            co_return false;
        }
        if (!downlink_attached_ && !closed_) {
            ready.Resubscribe(downlink_ready_);
        }
        if (!watch.cancelled) {
            watch.Resubscribe(cancellation);
        }
    }
    co_return downlink_attached_ && !closed_ && !watch.cancelled;
}

void XHttpPacketUpSession::CancelPendingOperations() noexcept {
    if (closed_) {
        return;
    }
    ++read_abort_epoch_;
    cancellation_.CancelPending();
    if (auto stream = stream_input_.Snapshot()) {
        stream->Cancel();
    }
    Wake();
}

net::awaitable<size_t> XHttpPacketUpSession::AsyncRead(net::mutable_buffer buffer) {
    auto* out = static_cast<uint8_t*>(buffer.data());
    const size_t capacity = buffer.size();
    if (capacity == 0) {
        co_return 0;
    }

    while (true) {
        if (packet_queue_.HasReady()) {
            co_return packet_queue_.ConsumePrefixTo(std::span<uint8_t>(out, capacity));
        }
        if (auto stream = stream_input_.Snapshot()) {
            UploadRead pending(*this, stream);
            const uint64_t epoch = read_abort_epoch_;
            size_t n = 0;
            try {
                n = co_await stream->AsyncRead(buffer);
            } catch (const IoSystemError& e) {
                if (e.code() != io_error::operation_aborted) {
                    ReleaseAttachedUpload(stream);
                    stream->CloseAbortive();
                }
                throw;
            }
            if (n > 0) {
                co_return n;
            }
            if (epoch != read_abort_epoch_) {
                throw IoSystemError(io_error::operation_aborted, "xhttp packet-up read cancelled");
            }
            ReleaseAttachedUpload(stream);
            co_return 0;
        }
        if (closed_ || input_closed_) {
            co_return 0;
        }
        const uint64_t epoch = read_abort_epoch_;
        auto [ec] = co_await input_signal_.async_receive(net::as_tuple(net::use_awaitable));
        if (ec || epoch != read_abort_epoch_) {
            throw IoSystemError(io_error::operation_aborted, "xhttp packet-up read cancelled");
        }
    }
}

net::awaitable<common::MultiBuffer> XHttpPacketUpSession::ReadMultiBuffer() {
    while (true) {
        if (packet_queue_.HasReady()) {
            co_return packet_queue_.Pop();
        }
        if (auto stream = stream_input_.Snapshot()) {
            UploadRead pending(*this, stream);
            const uint64_t epoch = read_abort_epoch_;
            common::MultiBuffer mb;
            try {
                mb = co_await stream->ReadMultiBuffer();
            } catch (const IoSystemError& e) {
                if (e.code() != io_error::operation_aborted) {
                    ReleaseAttachedUpload(stream);
                    stream->CloseAbortive();
                }
                throw;
            }
            if (mb.byte_size() != 0) {
                co_return mb;
            }
            if (epoch != read_abort_epoch_) {
                throw IoSystemError(io_error::operation_aborted, "xhttp packet-up read cancelled");
            }
            ReleaseAttachedUpload(stream);
            co_return common::MultiBuffer{};
        }
        if (closed_ || input_closed_) {
            co_return common::MultiBuffer{};
        }
        const uint64_t epoch = read_abort_epoch_;
        auto [ec] = co_await input_signal_.async_receive(net::as_tuple(net::use_awaitable));
        if (ec || epoch != read_abort_epoch_) {
            throw IoSystemError(io_error::operation_aborted, "xhttp packet-up read cancelled");
        }
    }
}

void XHttpPacketUpSession::OnCancellation(transport::Cancellation cancellation) noexcept {
    if (cancellation.terminal) {
        Close();
    } else {
        if (auto current = stream_input_.Snapshot())
            Resubscribe(current->Cancellation());
        cancellation_.CancelPending(cancellation.reason);
    }
}

// Stream-up EOF ends the logical upload direction.
void XHttpPacketUpSession::ReleaseAttachedUpload(
    const std::shared_ptr<AsyncStream>& stream) noexcept {
    Unsubscribe();
    (void)stream_input_.ReleaseIfCurrent(stream);
    CloseInput();
}

void XHttpPacketUpSession::Wake() noexcept {
    if (IoContext().stopped()) {
        return;
    }
    (void)input_signal_.try_send(IoErrorCode{});
}

XHttpRequestMeta ParseXHttpRequestMeta(std::string_view base_path,
                                       std::string_view request_path,
                                       std::string_view method) {
    XHttpRequestMeta meta;
    const std::string_view actual = PathWithoutQuery(request_path);
    const std::string_view expected = EffectiveHttpPath(base_path);
    if (actual == expected) {
        if (common::EqualsAsciiCI(method, "POST")) {
            meta.kind = XHttpRequestMeta::Kind::StreamOne;
        }
        return meta;
    }
    if (!PathPrefixMatchesSegment(expected, actual)) {
        return meta;
    }

    std::string_view rest = actual.substr(expected.size());
    while (!rest.empty() && rest.front() == '/') {
        rest.remove_prefix(1);
    }
    if (rest.empty()) {
        return meta;
    }

    const size_t slash = rest.find('/');
    if (slash == std::string_view::npos) {
        meta.session_id = rest;
        meta.kind = common::EqualsAsciiCI(method, "GET")
            ? XHttpRequestMeta::Kind::PacketDown
            : XHttpRequestMeta::Kind::StreamUp;
        return meta;
    }

    const std::string_view session = rest.substr(0, slash);
    if (session.empty()) {
        return meta;
    }
    const auto seq = ParseU64Decimal(rest.substr(slash + 1));
    if (!seq) {
        return meta;
    }
    meta.session_id = session;
    meta.seq = *seq;
    meta.kind = XHttpRequestMeta::Kind::PacketUp;
    return meta;
}

namespace {

struct DetachedXHttpStream {
    std::variant<DetachedTcpState, DetachedTlsState> state;
};

std::optional<DetachedXHttpStream> DetachXHttpStream(
    AsyncStream& stream, common::MultiBuffer head_bytes) {
    if (auto* tls = dynamic_cast<TlsStream*>(&stream)) {
        if (auto detached = tls->DetachForHandoff(std::move(head_bytes))) {
            return DetachedXHttpStream{std::move(*detached)};
        }
        return std::nullopt;
    }
    if (auto* tcp = dynamic_cast<TcpStream*>(&stream)) {
        if (auto detached = tcp->DetachForHandoff(std::move(head_bytes))) {
            return DetachedXHttpStream{std::move(*detached)};
        }
        return std::nullopt;
    }
    return std::nullopt;
}

std::unique_ptr<AsyncStream> RestoreXHttpStream(
    net::io_context& io_context, DetachedXHttpStream detached) {
    if (auto* tls = std::get_if<DetachedTlsState>(&detached.state)) {
        return TlsStream::RestoreFromHandoff(io_context, std::move(*tls));
    }
    if (auto* tcp = std::get_if<DetachedTcpState>(&detached.state)) {
        return TcpStream::RestoreFromHandoff(io_context, std::move(*tcp));
    }
    return nullptr;
}

struct XHttpUploadTimeouts {
    const std::shared_ptr<InboundTransportStreamHandler>* stream_handler = nullptr;
    std::chrono::seconds handshake_timeout{0};
    std::chrono::seconds idle_timeout{0};
    bool active = false;

    void OnRequest(AsyncStream& stream) const {
        if (stream_handler && *stream_handler) {
            (*stream_handler)->OnInboundTransportRequest(stream);
        } else if (active) {
            stream.SetIdleTimeout(handshake_timeout);
            (void)stream.StartPhaseDeadline(handshake_timeout);
        }
    }

    void OnReady(AsyncStream& stream) const {
        if (stream_handler && *stream_handler) {
            (*stream_handler)->OnInboundTransportReady(stream);
        } else if (active) {
            if (stream.ConsumePhaseDeadline()) {
                throw transport::LinkError(common::ErrorCode::TIMEOUT);
            }
            stream.ClearPhaseDeadline();
            stream.SetIdleTimeout(idle_timeout);
        }
    }
};

struct XHttpSessionOwnerResolution {
    net::io_context* owner = nullptr;
    std::shared_ptr<XHttpPacketUpSession> session;
};

net::awaitable<XHttpSessionOwnerResolution> ResolveXHttpSessionOwner(
    app::GroupCoordinator& coordinator,
    net::io_context& io_context,
    std::string_view session_namespace,
    std::string_view session_id,
    XHttpSessionAccess access,
    bool bind_owner,
    transport::CancellationSource* cancellation = nullptr) {
    auto& table = net::use_service<XHttpSessionTable>(io_context);
    if (access != XHttpSessionAccess::Open) {
        if (auto session = table.Get(
                io_context, session_namespace, session_id, XHttpSessionAccess::Join)) {
            co_return XHttpSessionOwnerResolution{
                .owner = &io_context,
                .session = std::move(session),
            };
        }
    }
    for (;;) {
        auto claim = co_await coordinator.PostCall(
            [&coordinator,
             session_namespace,
             session_id,
             access,
             &io_context,
             bind_owner] {
                return net::use_service<XHttpSessionDirectory>(coordinator.Services()).Acquire(
                    session_namespace, session_id, access, &io_context, bind_owner);
            });
        if (claim.retry) continue;
        if (claim.owner) {
            if (claim.owner != &io_context) {
                co_return XHttpSessionOwnerResolution{
                    .owner = claim.owner, .session = {}};
            }
            if (claim.record && claim.record->Retired()) continue;
            auto session = table.Get(
                io_context, session_namespace, session_id, access, claim.record);
            if (session) claim.reservation = false;
            co_return XHttpSessionOwnerResolution{
                .owner = claim.owner,
                .session = std::move(session),
            };
        }
        if (!claim.wait_owner) {
            // A rejected packet upload has no live owner to route to. Keep
            // it on this Worker so HTTP/1 can drain its body and send 404
            // without closing a persistent connection or creating a session.
            co_return XHttpSessionOwnerResolution{
                .owner = access == XHttpSessionAccess::Upload ? &io_context : nullptr,
                .session = {},
            };
        }
        struct CancelWait final : transport::CancellationSubscription {
            std::shared_ptr<XHttpSessionDirectory::OwnerWaiter> waiter;
            bool cancelled = false;
            explicit CancelWait(
                std::shared_ptr<XHttpSessionDirectory::OwnerWaiter> w) noexcept
                : waiter(std::move(w)) {}
            void OnCancellation(transport::Cancellation) noexcept override {
                cancelled = true;
                if (waiter) waiter->CancelOnOwner();
            }
        } cancel_wait{claim.wait_owner};
        if (cancellation) cancel_wait.Resubscribe(*cancellation);
        if (cancel_wait.cancelled) co_return XHttpSessionOwnerResolution{};
        if (!claim.wait_owner->notified.load(std::memory_order_acquire)) {
            IoErrorCode ec;
            std::tie(ec) = co_await claim.wait_owner->timer.async_wait(
                net::as_tuple(net::use_awaitable));
            (void)ec;
        }
        if (cancel_wait.cancelled ||
            (co_await net::this_coro::cancellation_state).cancelled() !=
                net::cancellation_type::none) {
            co_return XHttpSessionOwnerResolution{};
        }
    }
}

}  // namespace

net::awaitable<std::shared_ptr<XHttpPacketUpSession>> GetXHttpPacketSession(
    app::GroupCoordinator& coordinator,
    net::io_context& io_context,
    std::string_view session_namespace,
    std::string_view session_id,
    XHttpSessionAccess access) {
    co_return (co_await ResolveXHttpSessionOwner(coordinator, 
        io_context, session_namespace, session_id, access, true)).session;
}

std::unique_ptr<AsyncStream> MakeXHttpSplitStream(
    std::shared_ptr<XHttpPacketUpSession> session,
    std::unique_ptr<AsyncStream> downlink) {
    return std::make_unique<XHttpPacketUpServerStream>(
        std::move(session), std::move(downlink));
}

std::string_view XHttpRefererScratch::Format(
    std::string_view host,
    std::string_view path,
    bool tls) {
    const std::string_view scheme = tls ? "https://" : "http://";
    const std::string_view host_part = host.empty() ? "example.com" : host;
    const std::string_view req_path = EffectiveHttpPath(path);
    constexpr std::string_view kPaddingKey = "x_padding=";
    const char sep = req_path.find('?') == std::string_view::npos ? '?' : '&';
    const size_t total = scheme.size() + host_part.size() + req_path.size() + 1 +
                         kPaddingKey.size() + kXHttpRefererPadding.size();
    char* dst = nullptr;
    if (total <= inline_buf.size()) {
        dst = inline_buf.data();
    } else {
        overflow.resize(total);
        dst = overflow.data();
    }
    char* out = dst;
    auto put = [&out](std::string_view s) noexcept {
        std::memcpy(out, s.data(), s.size());
        out += s.size();
    };
    put(scheme);
    put(host_part);
    put(req_path);
    *out++ = sep;
    put(kPaddingKey);
    put(kXHttpRefererPadding);
    return std::string_view(dst, total);
}

HttpClientRequestView MakeXHttpClientRequestView(
    const XHttpConfig& cfg,
    std::string_view path,
    std::string_view method,
    bool tls,
    XHttpClientRequestKind kind,
    XHttpRefererScratch& referer_scratch) {
    HttpClientRequestView req{
        .path = path,
        .method = method,
        .host = cfg.host,
        .headers = &cfg.headers,
        .initial_window_size = std::nullopt,
        .default_content_type = {},
        .default_referer = {},
    };
    if (kind == XHttpClientRequestKind::StreamUp &&
        !cfg.no_grpc_header &&
        !FindHttpHeader(cfg.headers, "Content-Type")) {
        req.default_content_type = "application/grpc";
    }
    if (!FindHttpHeader(cfg.headers, "Referer")) {
        req.default_referer = referer_scratch.Format(cfg.host, path, tls);
    }
    return req;
}

namespace {

constexpr std::string_view kContinueResponse = "HTTP/1.1 100 Continue\r\n\r\n";

common::ErrorCode OwnerMissError(AsyncStream& stream, XHttpRequestMeta::Kind kind) {
    if (stream.ConsumePhaseDeadline() || stream.ConsumeIdleTimeout()) return common::ErrorCode::TIMEOUT;
    return kind == XHttpRequestMeta::Kind::StreamUp
        ? common::ErrorCode::RESOURCE_EXHAUSTED : common::ErrorCode::NOT_FOUND;
}

net::awaitable<tl::expected<bool, common::ErrorCode>> ExecuteXHttp1UploadRequest(
    std::unique_ptr<AsyncStream>& stream,
    const XHttpConfig& xhttp_cfg,
    uint64_t conn_id,
    XHttpRequestMeta::Kind kind,
    std::string_view session_id,
    uint64_t seq,
    const Http1ReadFraming& body_framing,
    bool expect_100_continue,
    bool keep_alive,
    common::MultiBuffer read_ahead,
    common::BufferGuard head_storage,
    std::string head_extended_storage,
    std::shared_ptr<XHttpPacketUpSession> session,
    const XHttpUploadTimeouts& timeouts) {
    if (kind == XHttpRequestMeta::Kind::PacketUp) {
        const auto* content_length = std::get_if<Http1BodyContentLength>(&body_framing);
        if (!content_length) {
            // The chunked decoder buffers past the body's last chunk, so
            // this upload ends its connection instead of persisting.
            if (!session) {
                co_return tl::unexpected(common::ErrorCode::NOT_FOUND);
            }
        }
        if (expect_100_continue &&
            (!content_length ||
             (session && session->AcceptingInput() &&
              content_length->bytes <= XHttpPacketQueue::kMaxQueuedBytes)) &&
            !co_await WriteFullToStream(*stream, kContinueResponse)) {
            co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
        }
        if (!content_length) {
            auto body = MakeHttp1BodyStream(
                std::move(stream), Http1BodyChunked{}, false, std::move(read_ahead));
            head_storage = common::BufferGuard{};
            try {
                XHttpPacketUpSession::Upload upload(*session, *body);
                auto payload = co_await ReadXHttpPacketBody(std::nullopt, upload);
                if (!payload) {
                    co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (!upload.Commit(seq, std::move(*payload))) {
                    co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
                }
            } catch (const IoSystemError& e) {
                co_return tl::unexpected(
                    e.code() == io_error::no_buffer_space
                        ? common::ErrorCode::RESOURCE_EXHAUSTED
                        : common::ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            if (!session->DownlinkAttached() && !co_await session->AwaitDownlink(*body)) {
                co_return tl::unexpected(common::ErrorCode::TIMEOUT);
            }
            if (!co_await SendXHttpResponseHeaders(*body, xhttp_cfg, false, true)) {
                co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
            }
            LOG_CONN_TRACE(conn_id, "XHTTP server packet-up payload accepted seq={}",
                          seq);
            co_return false;
        }

        // A Content-Length body is read from the connection itself, so the
        // bytes after it stay queued in order for the next request head.
        if (!read_ahead.empty()) {
            stream->PrependReadMultiBuffer(std::move(read_ahead));
        }
        const size_t body_bytes = content_length->bytes;
        head_storage = common::BufferGuard{};
        // A packet this server cannot take is answered and dropped without
        // closing: pipelined requests behind it may belong to other sessions.
        std::string_view rejection;
        if (!session || !session->AcceptingInput()) {
            if (!co_await DiscardHttp1Body(*stream, body_bytes)) {
                co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            rejection = "404 Not Found";
        } else {
            bool reading_body = false;
            bool discard_after_rejection = false;
            try {
                XHttpPacketUpSession::Upload upload(*session, *stream);
                reading_body = true;
                auto payload = co_await ReadXHttpPacketBody(body_bytes, upload);
                if (!payload) {
                    co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (!upload.Commit(seq, std::move(*payload))) {
                    rejection = "503 Service Unavailable";
                }
            } catch (const IoSystemError& e) {
                if (e.code() != io_error::no_buffer_space || !stream->IsOpen()) {
                    co_return tl::unexpected(
                        e.code() == io_error::no_buffer_space
                            ? common::ErrorCode::RESOURCE_EXHAUSTED
                            : common::ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (reading_body) {
                    co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
                }
                discard_after_rejection = true;
                rejection = "503 Service Unavailable";
            }
            if (discard_after_rejection &&
                !co_await DiscardHttp1Body(*stream, body_bytes)) {
                co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
            }
        }
        // An upload may reach the session before its downlink GET: hold
        // the session for that GET within this request's deadline.
        if (rejection.empty() && !session->DownlinkAttached() &&
            !co_await session->AwaitDownlink(*stream)) {
            co_return tl::unexpected(common::ErrorCode::TIMEOUT);
        }
        session.reset();
        const bool wrote_response = rejection.empty()
            ? co_await SendXHttpResponseHeaders(*stream, xhttp_cfg, false, !keep_alive)
            : co_await SendEmptyHttp1Response(*stream, rejection, !keep_alive);
        if (!wrote_response) {
            co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
        }
        LOG_CONN_TRACE(conn_id, "XHTTP server packet-up response seq={} status={}",
                      seq,
                      rejection.empty() ? std::string_view("200 OK") : rejection);
        if (!keep_alive) {
            co_return false;
        }
        // Between requests the connection idles under the transport idle
        // timeout; each request's handshake budget ends with its response.
        timeouts.OnReady(*stream);
        co_return true;
    }

    if (!session || !session->CanAttachStream()) {
        co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
    }
    bool accepting = true;
    struct StreamUpGuard {
        XHttpPacketUpSession* session;
        bool& active;
        ~StreamUpGuard() {
            if (active && session->CanAttachStream()) session->Close();
        }
    } guard{session.get(), accepting};
    if (expect_100_continue &&
        !co_await WriteFullToStream(*stream, kContinueResponse)) {
        co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }
    // Keep the upload response body open while the VLESS stream reads
    // request chunks.
    constexpr std::string_view kResponse =
        "HTTP/1.1 200 OK\r\n"
        "X-Accel-Buffering: no\r\n"
        "Cache-Control: no-store\r\n"
        "\r\n";
    if (!co_await WriteFullToStream(*stream, kResponse)) {
        co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
    }
    auto body = MakeHttp1BodyStream(
        std::move(stream), body_framing, false, std::move(read_ahead));
    timeouts.OnReady(*body);
    accepting = false;
    LOG_CONN_DEBUG(conn_id, "XHTTP server stream-up upload ready session={}",
                  PublicHttpTargetForLog(session_id));
    if (!session->AttachStream(std::move(body))) {
        co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
    }
    head_storage = common::BufferGuard{};
    std::string{}.swap(head_extended_storage);
    co_await session->JoinAttachedUpload();
    co_return false;
}

net::awaitable<tl::expected<void, common::ErrorCode>> HandOffXHttpUpload(
    app::GroupCoordinator& coordinator,
    net::io_context* owner, DetachedXHttpStream detached,
    const XHttpConfig& xhttp_cfg, uint64_t conn_id,
    XHttpUploadTimeouts timeouts, XHttpRequestMeta::Kind kind,
    std::string session_id, uint64_t seq, Http1ReadFraming framing,
    bool expect_100_continue, bool keep_alive);

net::awaitable<TransportBuildResult> RunXHttp1ServerHandshake(
    app::GroupCoordinator& coordinator,
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> stream,
    const XHttpConfig& xhttp_cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata,
    std::span<const uint8_t> initial,
    const std::shared_ptr<InboundTransportStreamHandler>& stream_handler,
    XHttpUploadTimeouts timeouts,
    bool start_persistent) {
    // RFC 9112 9.3: a packet-up upload leaves its HTTP/1.1 connection open for
    // the client's next, possibly pipelined, request. Every other request kind
    // turns the connection into a long-lived stream and ends the loop.
    std::array<uint8_t, 1> request_start{};
    for (bool persistent = start_persistent;; persistent = true) {
        if (transport_metadata) transport_metadata->real_ip.clear();
        std::span<const uint8_t> received = initial;
        if (persistent) {
            // Idle between requests until the next one begins; that request
            // then gets its own handshake budget, like the first one.
            size_t n = 0;
            try {
                n = co_await stream->AsyncRead(net::buffer(request_start));
            } catch (const IoSystemError& error) {
                LOG_CONN_DEBUG(conn_id, "XHTTP server idle H1 connection ended > {}", error.what());
            }
            if (n == 0) {
                co_return std::unique_ptr<AsyncStream>{};
            }
            timeouts.OnRequest(*stream);
            received = request_start;
        }
        auto received_request = co_await ReadHttp1Request(
            *stream, "XHTTP server H1", conn_id, received);
        if (!received_request) co_return tl::unexpected(received_request.error());
        auto* head = &received_request->head;
        const auto request = head->Text();
        const auto request_line = received_request->start_line;
        const auto method = received_request->line.method;
        const auto meta = ParseXHttpRequestMeta(
            xhttp_cfg.normalized_path, received_request->line.target, method);
        if (method.empty() || meta.kind == XHttpRequestMeta::Kind::Unknown)
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        if (RejectHostMismatch("XHTTP server", conn_id,
                ResolveConfiguredHttpHost(xhttp_cfg.host, &xhttp_cfg.headers), received_request->host))
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        if (!XHttpKindAllowed(meta.kind, xhttp_cfg))
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_UNSUPPORTED);
        if (meta.kind == XHttpRequestMeta::Kind::PacketDown) {
            if (!stream_handler) {
                co_return tl::unexpected(common::ErrorCode::INVALID_ARGUMENT);
            }
            auto session = co_await GetXHttpPacketSession(coordinator, 
                io_context, xhttp_cfg.session_namespace, meta.session_id, XHttpSessionAccess::Open);
            if (!session) {
                co_return tl::unexpected(common::ErrorCode::RESOURCE_EXHAUSTED);
            }
            XHttpDownlinkClaim claim(*session);
            if (!claim) co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
            if (!co_await SendXHttpResponseHeaders(*stream, xhttp_cfg, true, false)) {
                co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
            }
            // This physical GET becomes the dedicated downlink of a logical
            // request. End its transport budget before installing the split
            // stream's separate proxy-handshake deadline through the common
            // request sink.
            stream_handler->OnInboundTransportReady(*stream);

            auto downlink = MakeHttp1BodyStream(
                std::move(stream), Http1BodyUntilClose{}, true, head->TakeReadAheadMultiBuffer());
            LOG_CONN_DEBUG(conn_id, "XHTTP server split downlink ready session={} mode={}",
                          PublicHttpTargetForLog(meta.session_id),
                          xhttp_cfg.AcceptsStreamUp() ? "stream-up" : "packet-up");
            auto logical = MakeXHttpSplitStream(std::move(session), std::move(downlink));
            claim.Release();
            auto metadata = transport_metadata
                ? std::move(*transport_metadata) : InboundTransportMetadata{};
            head->storage = common::BufferGuard{};
            std::string{}.swap(head->extended_storage);
            co_await stream_handler->OnInboundTransportStream(
                std::move(logical), std::move(metadata));
            co_return std::unique_ptr<AsyncStream>{};
        }

        // Every other request kind carries an upload in its body.
        const auto body_framing = XHttpUploadFraming(request);
        if (!body_framing) {
            LOG_CONN_DEBUG(conn_id, "XHTTP server H1 upload requires exactly one valid body framing");
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
        }


        const bool expect_100_continue =
            HeaderListContainsTokenCI(request, "Expect", "100-continue");
        const bool keep_alive = RequestKeepsConnection(request_line, request);
        if (meta.kind == XHttpRequestMeta::Kind::PacketUp ||
            meta.kind == XHttpRequestMeta::Kind::StreamUp) {
            const auto access = meta.kind == XHttpRequestMeta::Kind::StreamUp
                ? XHttpSessionAccess::Open
                : XHttpSessionAccess::Upload;
            const bool bind_immediately = !timeouts.active;
            auto resolution = co_await ResolveXHttpSessionOwner(coordinator, 
                io_context, xhttp_cfg.session_namespace, meta.session_id,
                access, bind_immediately, &stream->Cancellation());
            auto* owner_reactor = resolution.owner;
            if (!owner_reactor)
                co_return tl::unexpected(OwnerMissError(*stream, meta.kind));
            if (owner_reactor != &io_context) {
                std::string session_id(meta.session_id);
                auto detached = DetachXHttpStream(*stream, head->TakeReadAheadMultiBuffer());
                head->storage = common::BufferGuard{};
                std::string{}.swap(head->extended_storage);
                stream.reset();
                if (!detached) {
                    co_return tl::unexpected(common::ErrorCode::SOCKET_READ_FAILED);
                }
                auto handed = co_await net::co_spawn(*owner_reactor,
                    HandOffXHttpUpload(coordinator, owner_reactor, std::move(*detached),
                        xhttp_cfg, conn_id,
                        XHttpUploadTimeouts{
                            .handshake_timeout = timeouts.handshake_timeout,
                            .idle_timeout = timeouts.idle_timeout,
                            .active = timeouts.active},
                        meta.kind, std::move(session_id), meta.seq,
                        *body_framing, expect_100_continue, keep_alive),
                    net::use_awaitable);
                if (!handed) co_return tl::unexpected(handed.error());
                co_return std::unique_ptr<AsyncStream>{};
            }
            common::MultiBuffer read_ahead = head->TakeReadAheadMultiBuffer();
            auto upload_result = co_await ExecuteXHttp1UploadRequest(
                stream, xhttp_cfg, conn_id, meta.kind, meta.session_id, meta.seq,
                *body_framing, expect_100_continue, keep_alive,
                std::move(read_ahead), std::move(head->storage),
                std::move(head->extended_storage),
                std::move(resolution.session), timeouts);
            if (!upload_result) {
                co_return tl::unexpected(upload_result.error());
            }
            if (!*upload_result) {
                co_return std::unique_ptr<AsyncStream>{};
            }
            continue;
        }

        // StreamOne: one request carries both directions, its body as the
        // uplink and the chunked response body as the downlink.
        if (expect_100_continue &&
            !co_await WriteFullToStream(*stream, kContinueResponse)) {
            co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
        }
        if (!co_await SendXHttpResponseHeaders(*stream, xhttp_cfg, true, false)) {
            co_return tl::unexpected(common::ErrorCode::SOCKET_WRITE_FAILED);
        }
        auto body = MakeHttp1BodyStream(
            std::move(stream), *body_framing, true, head->TakeReadAheadMultiBuffer());
        LOG_CONN_DEBUG(conn_id, "XHTTP server H1 stream-one ready");
        if (!stream_handler) {
            co_return body;
        }
        stream_handler->OnInboundTransportReady(*body);
        auto metadata = transport_metadata
            ? std::move(*transport_metadata) : InboundTransportMetadata{};
        head->storage = common::BufferGuard{};
        std::string{}.swap(head->extended_storage);
        co_await stream_handler->OnInboundTransportStream(std::move(body), std::move(metadata));
        co_return std::unique_ptr<AsyncStream>{};
    }
}

net::awaitable<tl::expected<void, common::ErrorCode>> HandOffXHttpUpload(
    app::GroupCoordinator& coordinator,
    net::io_context* owner, DetachedXHttpStream detached,
    const XHttpConfig& xhttp_cfg, uint64_t conn_id,
    XHttpUploadTimeouts timeouts, XHttpRequestMeta::Kind kind,
    std::string session_id, uint64_t seq, Http1ReadFraming framing,
    bool expect_100_continue, bool keep_alive) {
    auto restored = RestoreXHttpStream(*owner, std::move(detached));
    if (!restored) co_return tl::unexpected(common::ErrorCode::SOCKET_READ_FAILED);
    timeouts.OnRequest(*restored);
    const auto access = kind == XHttpRequestMeta::Kind::StreamUp
        ? XHttpSessionAccess::Open : XHttpSessionAccess::Upload;
    auto resolution = co_await ResolveXHttpSessionOwner(coordinator, 
        *owner, xhttp_cfg.session_namespace, session_id, access,
        !timeouts.active, &restored->Cancellation());
    if (!resolution.owner) co_return tl::unexpected(OwnerMissError(*restored, kind));
    auto first = co_await ExecuteXHttp1UploadRequest(
        restored, xhttp_cfg, conn_id, kind, session_id, seq, framing,
        expect_100_continue, keep_alive, {}, {}, {}, std::move(resolution.session), timeouts);
    if (!first) co_return tl::unexpected(first.error());
    if (!*first) co_return tl::expected<void, common::ErrorCode>{};
    const std::shared_ptr<InboundTransportStreamHandler> no_handler;
    auto result = co_await RunXHttp1ServerHandshake(coordinator, 
        *owner, std::move(restored), xhttp_cfg, conn_id, nullptr,
        {}, no_handler, timeouts, true);
    if (!result) co_return tl::unexpected(result.error());
    if (*result) co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    co_return tl::expected<void, common::ErrorCode>{};
}

}  // namespace

net::awaitable<TransportBuildResult> DoXHttp1ServerHandshake(
    app::GroupCoordinator& coordinator,
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> stream,
    const XHttpConfig& xhttp_cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata,
    std::span<const uint8_t> initial,
    const std::shared_ptr<InboundTransportStreamHandler>& stream_handler) {
    return RunXHttp1ServerHandshake(
        coordinator,
        io_context,
        std::move(stream),
        xhttp_cfg,
        conn_id,
        transport_metadata,
        initial,
        stream_handler,
        XHttpUploadTimeouts{
            .stream_handler = &stream_handler,
            .handshake_timeout = stream_handler
                ? stream_handler->TransportHandshakeTimeout()
                : std::chrono::seconds{0},
            .idle_timeout = stream_handler
                ? stream_handler->TransportIdleTimeout()
                : std::chrono::seconds{0},
            .active = (stream_handler != nullptr),
        },
        false);
}

net::awaitable<TransportBuildResult> DoXHttp1ClientRequest(
    std::unique_ptr<AsyncStream> stream,
    HttpClientRequestView cfg,
    std::string_view host,
    XHttpClientRequestKind kind,
    std::span<const net::const_buffer> packet_payload,
    uint64_t conn_id) {
    size_t payload_len = 0;
    for (const auto& buffer : packet_payload) {
        payload_len += buffer.size();
    }

    std::array<char, 32> content_length_buf{};
    std::string_view content_length;
    if (kind == XHttpClientRequestKind::PacketUp) {
        auto [ptr, ec] = std::to_chars(
            content_length_buf.data(),
            content_length_buf.data() + content_length_buf.size(),
            payload_len);
        if (ec != std::errc{}) {
            co_return tl::unexpected(common::ErrorCode::PROTOCOL_ENCODE_FAILED);
        }
        content_length = std::string_view(
            content_length_buf.data(),
            static_cast<size_t>(ptr - content_length_buf.data()));
    }

    if (const auto send_err = co_await SendXHttp1ClientRequest(
            *stream, cfg, host, content_length, kind, packet_payload, payload_len);
        send_err != common::ErrorCode::OK) {
        co_return tl::unexpected(send_err);
    }
    if (kind == XHttpClientRequestKind::StreamUp) {
        LOG_CONN_DEBUG(conn_id, "XHTTP client H1 stream-up ready path={} initial={}B",
                      PublicHttpTargetForLog(EffectiveHttpPath(cfg.path)),
                      payload_len);
        const auto executor = co_await net::this_coro::executor;
        auto& services = net::query(executor, net::execution::context);
        auto body = MakeHttp1BodyStream(std::move(stream), Http1BodyUntilClose{}, true);
        co_return std::make_unique<XHttpUploadClientStream>(
            executor, services, std::move(body));
    }

    Http1MessageHead head;
    if (auto read = co_await ReadHttp1MessageHead(*stream, head); !read) {
        co_return tl::unexpected(read.error());
    }
    const std::string_view response = head.Text();
    if (!HasStatusCode(ExtractStartLine(response), "200")) {
        co_return tl::unexpected(common::ErrorCode::PROTOCOL_DECODE_FAILED);
    }
    if (kind == XHttpClientRequestKind::PacketUp) {
        stream->Close();
        co_return std::unique_ptr<AsyncStream>{};
    }

    Http1ReadFraming read_framing = Http1BodyUntilClose{};
    if (HeaderContainsTokenCI(ExtractHeaderValueCI(response, "Transfer-Encoding"), "chunked")) {
        read_framing = Http1BodyChunked{};
    }
    LOG_CONN_DEBUG(conn_id, "XHTTP client H1 downlink ready path={}",
                  PublicHttpTargetForLog(EffectiveHttpPath(cfg.path)));
    co_return MakeHttp1BodyStream(
        std::move(stream), read_framing, false, head.TakeReadAheadMultiBuffer());
}

}  // namespace transport
