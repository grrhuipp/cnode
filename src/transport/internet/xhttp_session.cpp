#include "xhttp_session.hpp"

#include "http1_handshake.hpp"
#include "http_path_match.hpp"
#include "xhttp_packet_session_key.hpp"
#include "app/session_group_executor.hpp"
#include "../../common/awaitable_task_group.hpp"
#include "common/buffer_util.hpp"
#include "infra/log.hpp"
#include "transport/internet/http_headers.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "transport/phase_deadline.hpp"
#include "transport/internet/async_delay.hpp"

#include <array>
#include <charconv>
#include <exception>
#include <limits>
#include <optional>
#include <string>
#include <atomic>
#include <unordered_map>
#include <asio/this_coro.hpp>

namespace transport::internet {
namespace {

constexpr size_t kXHttpMaxPacketSessions = 1024;

constexpr std::string_view kXHttpRefererPadding =
    "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
static_assert(kXHttpRefererPadding.size() == 100);

net::awaitable<size_t> ReadToMultiBufferTail(AsyncStream& stream,
                                             buf::MultiBuffer& out,
                                             size_t max_read) {
    if (max_read == 0) {
        co_return 0;
    }
    if (!out.empty() && out.back()->Available() != 0) {
        auto* tail = out.back();
        const size_t n = co_await stream.AsyncRead(net::buffer(
            tail->Tail().data(), std::min(max_read, size_t{tail->Available()})));
        tail->Produce(static_cast<uint32_t>(n));
        out.RecordTailProduced(n);
        co_return n;
    }
    buf::MultiBuffer chunk = co_await stream.ReadMultiBuffer();
    buf::BufferGuard first;
    while (!chunk.empty()) {
        first = chunk.pop_front();
        if (first && !first->IsEmpty()) break;
        first.reset();
    }
    if (!first) {
        co_return 0;
    }
    for (size_t i = chunk.size(); i > 0; --i) {
        if (const buf::Buffer* b = *(chunk.begin() + (i - 1)); b && !b->IsEmpty()) {
            stream.PrependReadData(b->Bytes());
        }
    }
    chunk.clear();
    const size_t n = std::min<size_t>(max_read, first->Len());
    if (n < first->Len()) {
        stream.PrependReadData(first->Bytes().subspan(n));
        first->end = first->start + static_cast<uint32_t>(n);
    }
    out.push_back(std::move(first));
    co_return n;
}

// Strict 1*DIGIT; rejects signs, whitespace and overflow.
[[nodiscard]] std::optional<uint64_t> ParseU64Decimal(std::string_view value) {
    if (value.empty()) {
        return std::nullopt;
    }
    uint64_t out = 0;
    for (char ch : value) {
        if (ch < '0' || ch > '9') {
            return std::nullopt;
        }
        const uint64_t digit = static_cast<uint64_t>(ch - '0');
        if (out > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
            return std::nullopt;
        }
        out = out * 10 + digit;
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
                owner.cancellation_.Stop(cancellation.reason);
                owner.downlink_->Cancel();
            } else {
                Resubscribe(owner.session_->Cancellation());
                owner.cancellation_.CancelPending(cancellation.reason);
            }
        }
    };
    struct DownlinkCancellation final : transport::CancellationSubscription {
        explicit DownlinkCancellation(XHttpPacketUpServerStream& owner) noexcept : owner(owner) {}
        XHttpPacketUpServerStream& owner;
    private:
        void OnCancellation(transport::Cancellation cancellation) noexcept override {
            if (cancellation.terminal) {
                owner.cancellation_.Stop(cancellation.reason);
                owner.session_->Close();
            } else {
                Resubscribe(owner.downlink_->Cancellation());
                owner.cancellation_.CancelPending(cancellation.reason);
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

    transport::CancellationSource& Cancellation() noexcept override { return cancellation_; }

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

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        auto mb = co_await session_->ReadMultiBuffer();
        if (!mb.empty() && downlink_) {
            if (auto* tcp = BaseTcpStreamOf(*downlink_)) {
                tcp->TouchActivity();
            }
        }
        co_return mb;
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer mb) override {
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
        if (!downlink_) {
            co_return;
        }
        co_await downlink_->AsyncShutdownWrite();
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
    transport::CancellationSource cancellation_;
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
    std::optional<ResidentTaskGroup> tasks_;
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
        : state_(memory::AllocateShared<SharedState>(std::move(stream))) {
        net::use_service<XHttpClientTaskOwner>(services).Spawn(
            std::move(executor), DrainOwned(state_), drain_cancellation_);
    }
    ~XHttpUploadClientStream() noexcept override { Close(); }

    net::awaitable<size_t> AsyncRead(net::mutable_buffer) override { co_return 0; }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        co_return buf::MultiBuffer{};
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override {
        return state_->stream->AsyncWrite(buffer);
    }
    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
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
    struct SharedState final : memory::ThreadAllocated {
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
        head.storage = buf::BufferGuard{};
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
[[nodiscard]] memory::ThreadLocalString BuildXHttpResponseHeaders(
    const HttpConfig& cfg,
    bool chunked_body,
    bool close_connection) {
    memory::ThreadLocalString response;
    response.reserve(192 + cfg.headers.size() * 32);
    response.append("HTTP/1.1 200 OK\r\n");
    response.append("X-Accel-Buffering: no\r\n");
    response.append("Cache-Control: no-store\r\n");
    response.append("Access-Control-Allow-Origin: *\r\n");
    response.append("Access-Control-Allow-Methods: GET, POST\r\n");
    if (chunked_body) {
        response.append("Transfer-Encoding: chunked\r\n");
    } else {
        response.append("Content-Length: 0\r\n");
    }
    if (close_connection) {
        response.append("Connection: close\r\n");
    }
    for (const auto& [key, value] : cfg.headers) {
        if (key.empty() ||
            EqualsAsciiCI(key, "Transfer-Encoding") ||
            EqualsAsciiCI(key, "Content-Length") ||
            EqualsAsciiCI(key, "Connection")) {
            continue;
        }
        response.append(key);
        response.append(": ");
        response.append(value);
        response.append("\r\n");
    }
    response.append("\r\n");
    return response;
}

[[nodiscard]] memory::ThreadLocalString BuildEmptyHttp1Response(std::string_view status,
                                                                bool close_connection) {
    memory::ThreadLocalString response;
    response.reserve(64 + status.size());
    response.append("HTTP/1.1 ");
    response.append(status);
    response.append("\r\nContent-Length: 0\r\n");
    if (close_connection) {
        response.append("Connection: close\r\n");
    }
    response.append("\r\n");
    return response;
}

// Consumes a Content-Length body nobody will use, keeping the connection in
// step with its next request. Bodies above the packet budget are refused.
net::awaitable<bool> DiscardHttp1Body(AsyncStream& connection, uint64_t length) {
    if (length > ::detail::XHttpPacketQueue::kMaxQueuedBytes) {
        co_return false;
    }
    while (length > 0) {
        buf::MultiBuffer mb = co_await connection.ReadMultiBuffer();
        if (mb.empty()) {
            co_return false;
        }
        const size_t n = mb.DropPrefixBytes(
            static_cast<size_t>(std::min<uint64_t>(length, mb.byte_size())));
        if (n == 0) {
            co_return false;
        }
        length -= n;
        for (size_t i = mb.size(); i > 0; --i) {
            if (const buf::Buffer* b = *(mb.begin() + (i - 1)); b && !b->IsEmpty()) {
                connection.PrependReadData(b->Bytes());
            }
        }
        mb.clear();
    }
    co_return true;
}

// Body size is bounded by the session payload budget, never by the declared
// Content-Length alone.
net::awaitable<std::optional<buf::MultiBuffer>> ReadXHttpPacketBody(
    std::optional<uint64_t> content_length,
    XHttpPacketUpSession::Upload& upload) {
    buf::MultiBuffer payload;

    if (content_length) {
        if (*content_length > ::detail::XHttpPacketQueue::kMaxQueuedBytes) {
            co_return std::nullopt;
        }
        auto remaining = static_cast<size_t>(*content_length);
        while (remaining > 0) {
            const size_t n = co_await upload.Read(
                payload, std::min(static_cast<size_t>(buf::Buffer::kSize), remaining));
            if (n == 0) {
                co_return std::nullopt;
            }
            remaining -= n;
        }
        co_return payload;
    }

    while (true) {
        const size_t n = co_await upload.Read(payload, buf::Buffer::kSize);
        if (n == 0) {
            break;
        }
        if (payload.byte_size() > ::detail::XHttpPacketQueue::kMaxQueuedBytes) {
            payload.clear();
            co_return std::nullopt;
        }
    }
    co_return payload;
}

[[nodiscard]] std::string BuildXHttpReferer(std::string_view host,
                                            std::string_view path,
                                            bool tls) {
    const std::string_view scheme = tls ? "https://" : "http://";
    const std::string_view host_part = host.empty() ? "example.com" : host;
    const std::string_view req_path = detail::EffectiveHttpPath(path);
    constexpr std::string_view kPaddingKey = "x_padding=";

    std::string referer;
    referer.reserve(scheme.size() + host_part.size() + req_path.size() + 1 +
                    kPaddingKey.size() + kXHttpRefererPadding.size());
    referer.append(scheme);
    referer.append(host_part);
    referer.append(req_path);
    referer.push_back(req_path.find('?') == std::string_view::npos ? '?' : '&');
    referer.append(kPaddingKey);
    referer.append(kXHttpRefererPadding);
    return referer;
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
        EqualsAsciiCI(TrimAscii(ExtractHeaderValueCI(request, "Transfer-Encoding")), "chunked")) {
        return Http1BodyChunked{};
    }
    if (content_lengths == 1 && transfer_encodings == 0) {
        if (const auto length = ParseU64Decimal(
                TrimAscii(ExtractHeaderValueCI(request, "Content-Length")))) {
            return Http1BodyContentLength{.bytes = *length};
        }
    }
    return std::nullopt;
}

[[nodiscard]] bool IsBodyFramingOrHostHeader(std::string_view key) {
    return EqualsAsciiCI(key, "Host") ||
           EqualsAsciiCI(key, "Content-Length") ||
           EqualsAsciiCI(key, "Transfer-Encoding");
}

[[nodiscard]] memory::ThreadLocalString BuildXHttp1ClientRequest(
    const HttpConfig& cfg,
    std::string_view host,
    std::string_view content_length,
    bool chunked_upload) {
    const std::string_view req_path = detail::EffectiveHttpPath(cfg.path);
    const std::string_view method = cfg.method.empty()
        ? std::string_view("PUT") : std::string_view(cfg.method);
    const size_t reserve_size = 224 + method.size() + req_path.size() + host.size() +
                                content_length.size() + cfg.headers.size() * 32;

    memory::ThreadLocalString request;
    request.reserve(reserve_size);
    request.append(method);
    request.push_back(' ');
    request.append(req_path);
    request.append(" HTTP/1.1\r\n");
    request.append("Host: ");
    request.append(host);
    request.append("\r\n");
    if (chunked_upload) {
        request.append("Transfer-Encoding: chunked\r\n");
        // Match Xray's H1 DisableKeepAlives: Go's server otherwise drains the
        // request body on its first response flush, stealing live upload bytes.
        request.append("Connection: close\r\n");
    } else if (!content_length.empty()) {
        request.append("Content-Length: ");
        request.append(content_length);
        request.append("\r\n");
    }
    for (const auto& [key, value] : cfg.headers) {
        if (key.empty() || IsBodyFramingOrHostHeader(key) ||
            (chunked_upload && EqualsAsciiCI(key, "Connection"))) {
            continue;
        }
        request.append(key);
        request.append(": ");
        request.append(value);
        request.append("\r\n");
    }
    request.append("\r\n");
    return request;
}

// Coordinator-owned metadata only. Each admitted record reserves its own
// retirement node: noexcept close cannot lose an event to mailbox exhaustion.
class XHttpSessionDirectory final : public net::execution_context::service {
    struct KeyRef {
        std::string_view session_namespace;
        std::string_view id;
    };
    struct Key {
        std::string session_namespace;
        std::string id;
        operator KeyRef() const noexcept { return {session_namespace, id}; }
    };
    struct Hash {
        using is_transparent = void;
        size_t operator()(KeyRef key) const noexcept {
            const auto a = std::hash<std::string_view>{}(key.session_namespace);
            const auto b = std::hash<std::string_view>{}(key.id);
            return a ^ (b + size_t{0x9e3779b9} + (a << 6) + (a >> 2));
        }
    };
    struct Equal {
        using is_transparent = void;
        bool operator()(KeyRef a, KeyRef b) const noexcept {
            return a.session_namespace == b.session_namespace && a.id == b.id;
        }
    };

public:
    static net::execution_context::id id;
    explicit XHttpSessionDirectory(net::execution_context& context)
        : net::execution_context::service(context) {}

    struct Record {
        enum class State : uint8_t { Reserved, Live, Retired };
        XHttpSessionDirectory* directory;
        const Key* key = nullptr;
        std::weak_ptr<ExecutionDomain> owner;
        std::atomic<State> state{State::Reserved};
        Record* incoming_next = nullptr;
        Record* previous = nullptr;
        Record* next = nullptr;
        bool processed = false;
        bool activated = false;

        Record(XHttpSessionDirectory& directory, const std::shared_ptr<ExecutionDomain>& owner)
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
    };

    // Cancelled admission cannot strand capacity. Once any same-group caller
    // installs the session, an older admission token cannot retire it.
    struct Claim {
        std::shared_ptr<ExecutionDomain> owner;
        std::shared_ptr<Record> record;
        bool reservation = false;
        bool retry = false;
        Claim() = default;
        Claim(std::shared_ptr<ExecutionDomain> owner, std::shared_ptr<Record> record,
              bool reservation)
            : owner(std::move(owner)), record(std::move(record)), reservation(reservation) {}
        Claim(Claim&& other) noexcept
            : owner(std::move(other.owner)), record(std::move(other.record)),
              reservation(std::exchange(other.reservation, false)), retry(other.retry) {}
        Claim(const Claim&) = delete;
        Claim& operator=(const Claim&) = delete;
        ~Claim() {
            if (reservation && record) record->Retire(true);
        }
    };

    Claim Acquire(std::string_view session_namespace, std::string_view session_id,
                  XHttpSessionAccess access, const std::shared_ptr<ExecutionDomain>& current) {
        DrainRetirements();
        auto found = entries_.find(KeyRef{session_namespace, session_id});
        if (found != entries_.end() && !found->second->Retired()) {
            if (auto owner = found->second->owner.lock())
                return {std::move(owner), found->second, false};
            found->second->Retire();
            DrainRetirements();
            found = entries_.find(KeyRef{session_namespace, session_id});
        }
        if (access == XHttpSessionAccess::Join ||
            (found != entries_.end() && access != XHttpSessionAccess::Open))
            return {};
        if (found != entries_.end() && !found->second->processed) {
            // State was published just before the reserved queue node. Yield
            // through another bounded control call rather than spin here.
            Claim claim;
            claim.retry = true;
            return claim;
        }
        if (active_ == kMaxActive) return {};
        auto record = std::make_shared<Record>(*this, current);
        if (found == entries_.end()) {
            found = entries_.try_emplace(
                Key{std::string(session_namespace), std::string(session_id)}, record).first;
        } else {
            Unlink(*found->second);
            --ended_;
            found->second = record;
        }
        record->key = &found->first;
        ++active_;
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
            record->owner.reset();
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
    std::unordered_map<Key, std::shared_ptr<Record>, Hash, Equal> entries_;
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
    const ::detail::XHttpPacketSessionKey* key = nullptr;
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
        std::shared_ptr<ExecutionDomain> owner = {},
        std::shared_ptr<XHttpSessionDirectory::Record> record = {}) {
        const ::detail::XHttpPacketSessionKeyRef lookup{id, session_namespace};
        auto found = sessions_.find(lookup);
        if (found != sessions_.end() && found->second.live)
            return found->second.session.lock();
        if (access == XHttpSessionAccess::Join ||
            (found != sessions_.end() && access != XHttpSessionAccess::Open) ||
            active_ == kXHttpMaxPacketSessions)
            return nullptr;

        auto session = memory::AllocateShared<XHttpPacketUpSession>(io, owner);
        const bool inserting = found == sessions_.end();
        if (found == sessions_.end()) {
            ::detail::XHttpPacketSessionKey key{
                .session_id = memory::ThreadLocalString(id),
                .session_namespace = memory::ThreadLocalString(session_namespace),
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
        (void)owner;
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

    memory::ThreadLocalUnorderedMap<
        ::detail::XHttpPacketSessionKey, XHttpSessionTableEntry,
        ::detail::XHttpPacketSessionKeyHash,
        ::detail::XHttpPacketSessionKeyEq> sessions_;
    XHttpSessionTableEntry* first_ = nullptr;
    XHttpSessionTableEntry* last_ = nullptr;
    size_t active_ = 0;
    size_t ended_ = 0;
};

net::execution_context::id XHttpSessionTable::id;

XHttpPacketUpSession::XHttpPacketUpSession(
    net::io_context& io_context,
    std::shared_ptr<ExecutionDomain> owner)
    : owner_domain_(std::move(owner))
    , io_context_(io_context)
    , input_signal_(owner_domain_ ? owner_domain_->Executor()
                                  : net::any_io_executor(io_context.get_executor()), 1)
    , upload_signal_(owner_domain_ ? owner_domain_->Executor()
                                   : net::any_io_executor(io_context.get_executor()), 1) {}

XHttpPacketUpSession::~XHttpPacketUpSession() noexcept {
    Unsubscribe();
    Retire();
}

net::io_context& XHttpPacketUpSession::IoContext() const noexcept {
    return owner_domain_ ? owner_domain_->Reactor() : io_context_;
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
    buf::MultiBuffer& payload, size_t limit) {
    if (payload.empty() || payload.back()->Available() == 0) {
        if (!session_.Reserve(buf::Buffer::kSize)) {
            uint8_t excess;
            if (co_await stream_.AsyncRead(net::buffer(&excess, 1)) == 0) co_return 0;
            throw IoSystemError(io_error::no_buffer_space, "xhttp payload budget exhausted");
        }
        reserved_ += buf::Buffer::kSize;
    }
    co_return co_await ReadToMultiBufferTail(stream_, payload, limit);
}

bool XHttpPacketUpSession::Upload::Commit(uint64_t seq, buf::MultiBuffer payload) {
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

net::awaitable<void> XHttpPacketUpSession::JoinAttachedUpload() {
    std::exception_ptr failure;
    try {
        while (!stream_input_.Empty() || upload_reads_ != 0)
            co_await upload_signal_.async_receive(net::use_awaitable);
    } catch (...) {
        failure = std::current_exception();
        Close();
    }
    if (failure) {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        while (!stream_input_.Empty() || upload_reads_ != 0)
            co_await upload_signal_.async_receive(net::use_awaitable);
        std::rethrow_exception(failure);
    }
}

bool XHttpPacketUpSession::Push(uint64_t seq, buf::MultiBuffer payload) {
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
    (void)upload_signal_.try_send(IoErrorCode{});
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
    auto domain = ExecutionDomain::Current();
    AsyncDelay wait(domain ? domain->Reactor() : io_context_);
    struct ReadyWatch final : transport::CancellationSubscription {
        explicit ReadyWatch(AsyncDelay& wait) noexcept : wait(wait) {}
        AsyncDelay& wait;

    private:
        void OnCancellation(transport::Cancellation) noexcept override {
            wait.Cancel();
        }
    } ready{wait};
    struct ConnectionCancellation final : transport::CancellationSubscription {
        explicit ConnectionCancellation(AsyncDelay& wait) noexcept : wait(wait) {}
        AsyncDelay& wait;
        bool cancelled = false;

    private:
        void OnCancellation(transport::Cancellation) noexcept override {
            cancelled = true;
            wait.Cancel();
        }
    } watch{wait};
    ready.Resubscribe(downlink_ready_);
    watch.Resubscribe(cancellation);
    while (!downlink_attached_ && !closed_ && !watch.cancelled) {
        co_await wait.WaitFor(std::chrono::milliseconds::max());
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

net::awaitable<buf::MultiBuffer> XHttpPacketUpSession::ReadMultiBuffer() {
    while (true) {
        if (packet_queue_.HasReady()) {
            co_return packet_queue_.Pop();
        }
        if (auto stream = stream_input_.Snapshot()) {
            UploadRead pending(*this, stream);
            const uint64_t epoch = read_abort_epoch_;
            buf::MultiBuffer mb;
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
            co_return buf::MultiBuffer{};
        }
        if (closed_ || input_closed_) {
            co_return buf::MultiBuffer{};
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
    const std::string_view actual = detail::PathWithoutQuery(request_path);
    const std::string_view expected = detail::EffectiveHttpPath(base_path);
    if (actual == expected) {
        if (EqualsAsciiCI(method, "POST")) {
            meta.kind = XHttpRequestMeta::Kind::StreamOne;
        }
        return meta;
    }
    if (!detail::PathPrefixMatchesSegment(expected, actual)) {
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
        meta.kind = EqualsAsciiCI(method, "GET")
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

net::awaitable<std::shared_ptr<XHttpPacketUpSession>> GetXHttpPacketSession(
    net::io_context& io_context,
    std::string_view session_namespace,
    std::string_view session_id,
    XHttpSessionAccess access) {
    auto current = ExecutionDomain::Current();
    if (!current) {
        co_return net::use_service<XHttpSessionTable>(io_context).Get(
            io_context, session_namespace, session_id, access);
    }

    auto& coordinator = current->Coordinator();
    for (;;) {
        auto claim = co_await coordinator.PostCall(
            [&coordinator, session_namespace, session_id, access, current] {
                return net::use_service<XHttpSessionDirectory>(coordinator.Services()).Acquire(
                    session_namespace, session_id, access, current);
            });
        if (claim.retry) continue;
        if (!claim.owner) co_return nullptr;
        if (!current->SharesGroup(*claim.owner)) co_await current->Join(claim.owner);
        // The immutable record is the generation token. Join suspends, so
        // re-check retirement after both groups have become one serial owner.
        if (claim.record->Retired()) continue;
        co_return net::use_service<XHttpSessionTable>(claim.owner->Services()).Get(
            claim.owner->Reactor(), session_namespace, session_id, access,
            claim.owner, claim.record);
    }
}

std::unique_ptr<AsyncStream> MakeXHttpSplitStream(
    std::shared_ptr<XHttpPacketUpSession> session,
    std::unique_ptr<AsyncStream> downlink) {
    return std::make_unique<XHttpPacketUpServerStream>(
        std::move(session), std::move(downlink));
}

HttpConfig XHttpStreamOneHttpConfig(const XHttpConfig& cfg, bool outbound) {
    HttpConfig http;
    http.path = cfg.normalized_path;
    http.host = cfg.host;
    http.method = outbound ? "POST" : "";
    http.headers = cfg.headers;
    http.force_http2 = true;
    if (outbound && !cfg.no_grpc_header && !FindHttpHeader(http.headers, "Content-Type")) {
        http.headers.emplace("content-type", "application/grpc");
    }
    // normalized_path never carries a query, so the padding always opens one.
    if (outbound && !FindHttpHeader(http.headers, "Referer")) {
        http.headers.emplace("referer", BuildXHttpReferer(http.host, http.path, true));
    }
    if (!outbound && !cfg.no_sse_header && !FindHttpHeader(http.headers, "Content-Type")) {
        http.headers.emplace("content-type", "text/event-stream");
    }
    return http;
}

HttpConfig XHttpClientHttpConfig(const XHttpConfig& cfg,
                                 std::string_view path,
                                 std::string_view method,
                                 bool tls,
                                 XHttpClientRequestKind kind) {
    HttpConfig http;
    http.path.assign(path.data(), path.size());
    http.host = cfg.host;
    http.method.assign(method.data(), method.size());
    http.headers = cfg.headers;
    http.force_http2 = true;
    if (kind == XHttpClientRequestKind::StreamUp &&
        !cfg.no_grpc_header &&
        !FindHttpHeader(http.headers, "Content-Type")) {
        http.headers.emplace("content-type", "application/grpc");
    }
    if (!FindHttpHeader(http.headers, "Referer")) {
        http.headers.emplace("referer", BuildXHttpReferer(http.host, http.path, tls));
    }
    return http;
}

net::awaitable<TransportBuildResult> DoXHttp1ServerHandshake(
    net::io_context& io_context,
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
    const XHttpConfig& xhttp_cfg,
    uint64_t conn_id,
    InboundTransportMetadata* transport_metadata,
    std::span<const uint8_t> initial,
    const std::shared_ptr<InboundTransportStreamHandler>& stream_handler) {
    // RFC 9112 9.3: a packet-up upload leaves its HTTP/1.1 connection open for
    // the client's next, possibly pipelined, request. Every other request kind
    // turns the connection into a long-lived stream and ends the loop.
    std::array<uint8_t, 1> request_start{};
    for (bool persistent = false;; persistent = true) {
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
            if (stream_handler) stream_handler->OnInboundTransportRequest(*stream);
            received = request_start;
        }
        auto head = co_await ReadHttp1MessageHead(*stream, received);
        if (!head) {
            if (head.error() == ErrorCode::SOCKET_EOF) {
                LOG_CONN_DEBUG(conn_id, "XHTTP server peer closed during H1 request read");
            } else if (head.error() == ErrorCode::PROTOCOL_DECODE_FAILED) {
                LOG_CONN_DEBUG(conn_id, "XHTTP server H1 request too large or incomplete");
            }
            co_return tl::unexpected(head.error());
        }

        const std::string_view request = head->Text();
        const std::string_view request_line = ExtractStartLine(request);
        const auto parsed_line = ParseHttp1RequestLine(request_line);
        const auto method = parsed_line.method;
        const auto request_path = parsed_line.target;
        const std::string_view host = TrimAscii(ExtractHeaderValueCI(request, "Host"));
        const auto meta = ParseXHttpRequestMeta(cfg.path, request_path, method);

        LOG_CONN_TRACE(conn_id,
            "XHTTP server H1 request line='{}' method='{}' path='{}' host='{}' bytes={}",
            SanitizeHttpRequestLineForLog(parsed_line),
            PublicHttpMethodForLog(method),
            PublicHttpTargetForLog(request_path),
            PublicHttpTargetForLog(host),
            head->size);

        if (method.empty() || meta.kind == XHttpRequestMeta::Kind::Unknown) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }
        if (const std::string_view expected_host = TrimAscii(ExpectedHttpHost(cfg));
            !expected_host.empty() && !EqualsAsciiCI(host, expected_host)) {
            LOG_CONN_DEBUG(conn_id,
                "XHTTP server host mismatch expected='{}' actual='{}'",
                PublicHttpTargetForLog(expected_host),
                PublicHttpTargetForLog(host));
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }

        RecordExtractedRealIp(request, cfg.real_ip_header, transport_metadata);

        if (meta.kind == XHttpRequestMeta::Kind::PacketDown) {
            if (!xhttp_cfg.AcceptsPacketUp() && !xhttp_cfg.AcceptsStreamUp()) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
            }
            if (!stream_handler) {
                co_return tl::unexpected(ErrorCode::INVALID_ARGUMENT);
            }
            auto session = co_await GetXHttpPacketSession(
                io_context, xhttp_cfg.session_namespace, meta.session_id, XHttpSessionAccess::Open);
            if (!session) {
                co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
            }
            if (!session->AttachDownlink()) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
            }
            bool attached = true;
            struct DownlinkGuard {
                XHttpPacketUpSession* session;
                bool& active;
                ~DownlinkGuard() {
                    if (active) session->Close();
                }
            } guard{session.get(), attached};
            if (!co_await WriteFullToStream(
                    *stream, BuildXHttpResponseHeaders(cfg, true, false))) {
                co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
            }
            // This physical GET becomes the dedicated downlink of a logical
            // request. End its transport budget before installing the split
            // stream's separate proxy-handshake deadline through the common
            // request sink.
            stream_handler->OnInboundTransportReady(*stream);

            auto downlink = MakeHttp1BodyStream(
                std::move(stream), Http1BodyUntilClose{}, true, head->ReadAhead());
            LOG_CONN_DEBUG(conn_id, "XHTTP server split downlink ready session={} mode={}",
                          PublicHttpTargetForLog(meta.session_id),
                          xhttp_cfg.AcceptsStreamUp() ? "stream-up" : "packet-up");
            auto logical = MakeXHttpSplitStream(std::move(session), std::move(downlink));
            attached = false;
            auto metadata = transport_metadata
                ? std::move(*transport_metadata) : InboundTransportMetadata{};
            head->storage = buf::BufferGuard{};
            co_await stream_handler->OnInboundTransportStream(
                std::move(logical), std::move(metadata));
            co_return std::unique_ptr<AsyncStream>{};
        }

        // Every other request kind carries an upload in its body.
        const auto body_framing = XHttpUploadFraming(request);
        if (!body_framing) {
            LOG_CONN_DEBUG(conn_id, "XHTTP server H1 upload requires exactly one valid body framing");
            co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
        }

        if (meta.kind == XHttpRequestMeta::Kind::PacketUp) {
            if (!xhttp_cfg.AcceptsPacketUp()) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
            }
            auto session = co_await GetXHttpPacketSession(
                io_context, xhttp_cfg.session_namespace, meta.session_id, XHttpSessionAccess::Upload);
            const auto* content_length = std::get_if<Http1BodyContentLength>(&*body_framing);
            if (!content_length) {
                // The chunked decoder buffers past the body's last chunk, so
                // this upload ends its connection instead of persisting.
                if (!session) {
                    co_return tl::unexpected(ErrorCode::NOT_FOUND);
                }
            }
            if (HeaderListContainsTokenCI(request, "Expect", "100-continue") &&
                (!content_length ||
                 (session && session->AcceptingInput() &&
                  content_length->bytes <= ::detail::XHttpPacketQueue::kMaxQueuedBytes)) &&
                !co_await WriteFullToStream(*stream, "HTTP/1.1 100 Continue\r\n\r\n")) {
                co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
            }
            if (!content_length) {
                auto body = MakeHttp1BodyStream(
                    std::move(stream), Http1BodyChunked{}, false, head->ReadAhead());
                head->storage = buf::BufferGuard{};
                try {
                    XHttpPacketUpSession::Upload upload(*session, *body);
                    auto payload = co_await ReadXHttpPacketBody(std::nullopt, upload);
                    if (!payload) {
                        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
                    }
                    if (!upload.Commit(meta.seq, std::move(*payload))) {
                        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
                    }
                } catch (const IoSystemError& e) {
                    co_return tl::unexpected(
                        e.code() == io_error::no_buffer_space
                            ? ErrorCode::RESOURCE_EXHAUSTED
                            : ErrorCode::PROTOCOL_DECODE_FAILED);
                }
                if (!session->DownlinkAttached() && !co_await session->AwaitDownlink(*body)) {
                    co_return tl::unexpected(ErrorCode::TIMEOUT);
                }
                if (!co_await WriteFullToStream(
                        *body, BuildXHttpResponseHeaders(cfg, false, true))) {
                    co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
                }
                LOG_CONN_TRACE(conn_id, "XHTTP server packet-up payload accepted seq={}",
                              meta.seq);
                co_return std::unique_ptr<AsyncStream>{};
            }

            // A Content-Length body is read from the connection itself, so the
            // bytes after it stay queued in order for the next request head.
            stream->PrependReadData(head->ReadAhead());
            const bool keep_alive = RequestKeepsConnection(request_line, request);
            const size_t body_bytes = content_length->bytes;
            head->storage = buf::BufferGuard{};
            // A packet this server cannot take is answered and dropped without
            // closing: pipelined requests behind it may belong to other sessions.
            std::string_view rejection;
            if (!session || !session->AcceptingInput()) {
                if (!co_await DiscardHttp1Body(*stream, body_bytes)) {
                    co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
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
                        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
                    }
                    if (!upload.Commit(meta.seq, std::move(*payload))) {
                        rejection = "503 Service Unavailable";
                    }
                } catch (const IoSystemError& e) {
                    if (e.code() != io_error::no_buffer_space || !stream->IsOpen()) {
                        co_return tl::unexpected(
                            e.code() == io_error::no_buffer_space
                                ? ErrorCode::RESOURCE_EXHAUSTED
                                : ErrorCode::PROTOCOL_DECODE_FAILED);
                    }
                    if (reading_body) {
                        co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
                    }
                    discard_after_rejection = true;
                    rejection = "503 Service Unavailable";
                }
                if (discard_after_rejection &&
                    !co_await DiscardHttp1Body(*stream, body_bytes)) {
                    co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
                }
            }
            // An upload may reach the session before its downlink GET: hold
            // the session for that GET within this request's deadline.
            if (rejection.empty() && !session->DownlinkAttached() &&
                !co_await session->AwaitDownlink(*stream)) {
                co_return tl::unexpected(ErrorCode::TIMEOUT);
            }
            session.reset();
            const auto response = rejection.empty()
                ? BuildXHttpResponseHeaders(cfg, false, !keep_alive)
                : BuildEmptyHttp1Response(rejection, !keep_alive);
            if (!co_await WriteFullToStream(*stream, response)) {
                co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
            }
            LOG_CONN_TRACE(conn_id, "XHTTP server packet-up response seq={} status={}",
                          meta.seq,
                          rejection.empty() ? std::string_view("200 OK") : rejection);
            if (!keep_alive) {
                co_return std::unique_ptr<AsyncStream>{};
            }
            // Between requests the connection idles under the transport idle
            // timeout; each request's handshake budget ends with its response.
            if (stream_handler) {
                stream_handler->OnInboundTransportReady(*stream);
            }
            continue;
        }

        if (meta.kind == XHttpRequestMeta::Kind::StreamUp) {
            if (!xhttp_cfg.AcceptsStreamUp()) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
            }
            auto session = co_await GetXHttpPacketSession(
                io_context, xhttp_cfg.session_namespace, meta.session_id, XHttpSessionAccess::Open);
            if (!session || !session->CanAttachStream()) {
                co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
            }
            bool accepting = true;
            struct StreamUpGuard {
                XHttpPacketUpSession* session;
                bool& active;
                ~StreamUpGuard() {
                    if (active && session->CanAttachStream()) session->Close();
                }
            } guard{session.get(), accepting};
            if (HeaderListContainsTokenCI(request, "Expect", "100-continue") &&
                !co_await WriteFullToStream(*stream, "HTTP/1.1 100 Continue\r\n\r\n")) {
                co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
            }
            // Keep the upload response body open while the VLESS stream reads
            // request chunks.
            constexpr std::string_view kResponse =
                "HTTP/1.1 200 OK\r\n"
                "X-Accel-Buffering: no\r\n"
                "Cache-Control: no-store\r\n"
                "\r\n";
            if (!co_await WriteFullToStream(*stream, kResponse)) {
                co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
            }
            auto body = MakeHttp1BodyStream(
                std::move(stream), *body_framing, false, head->ReadAhead());
            if (stream_handler) stream_handler->OnInboundTransportReady(*body);
            accepting = false;
            LOG_CONN_DEBUG(conn_id, "XHTTP server stream-up upload ready session={}",
                          PublicHttpTargetForLog(meta.session_id));
            if (!session->AttachStream(std::move(body))) {
                co_return tl::unexpected(ErrorCode::RESOURCE_EXHAUSTED);
            }
            head->storage = buf::BufferGuard{};
            co_await session->JoinAttachedUpload();
            co_return std::unique_ptr<AsyncStream>{};
        }

        // StreamOne: one request carries both directions, its body as the
        // uplink and the chunked response body as the downlink.
        if (!xhttp_cfg.AcceptsStreamOne()) {
            co_return tl::unexpected(ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        if (HeaderListContainsTokenCI(request, "Expect", "100-continue") &&
            !co_await WriteFullToStream(*stream, "HTTP/1.1 100 Continue\r\n\r\n")) {
            co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
        if (!co_await WriteFullToStream(*stream, BuildXHttpResponseHeaders(cfg, true, false))) {
            co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
        auto body = MakeHttp1BodyStream(
            std::move(stream), *body_framing, true, head->ReadAhead());
        LOG_CONN_DEBUG(conn_id, "XHTTP server H1 stream-one ready");
        if (!stream_handler) {
            co_return body;
        }
        stream_handler->OnInboundTransportReady(*body);
        auto metadata = transport_metadata
            ? std::move(*transport_metadata) : InboundTransportMetadata{};
        head->storage = buf::BufferGuard{};
        co_await stream_handler->OnInboundTransportStream(std::move(body), std::move(metadata));
        co_return std::unique_ptr<AsyncStream>{};
    }
}

net::awaitable<TransportBuildResult> DoXHttp1ClientRequest(
    std::unique_ptr<AsyncStream> stream,
    const HttpConfig& cfg,
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
            co_return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
        }
        content_length = std::string_view(
            content_length_buf.data(),
            static_cast<size_t>(ptr - content_length_buf.data()));
    }

    const bool chunked_upload = kind == XHttpClientRequestKind::StreamUp;
    const memory::ThreadLocalString request = BuildXHttp1ClientRequest(
        cfg, host, content_length, chunked_upload);
    if (chunked_upload) {
        // Send the head and initial chunk together; an owned reader drains
        // this upload connection's response while the downlink joins.
        ConstBufferSpanBuilder<20> out;
        out.Append(net::buffer(request.data(), request.size()));
        std::array<char, sizeof(size_t) * 2 + 2> prefix{};
        constexpr std::array<char, 2> kChunkTail{'\r', '\n'};
        if (payload_len > 0) {
            auto [ptr, ec] = std::to_chars(
                prefix.data(),
                prefix.data() + prefix.size() - 2,
                payload_len,
                16);
            if (ec != std::errc{}) {
                co_return tl::unexpected(ErrorCode::PROTOCOL_ENCODE_FAILED);
            }
            *ptr++ = '\r';
            *ptr++ = '\n';
            out.Append(net::buffer(prefix.data(), static_cast<size_t>(ptr - prefix.data())));
            out.AppendBuffers(packet_payload);
            out.Append(net::buffer(kChunkTail.data(), kChunkTail.size()));
        }
        try {
            co_await stream->WriteBuffers(out.Span());
        } catch (...) {
            co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
        LOG_CONN_DEBUG(conn_id, "XHTTP client H1 stream-up ready path={} initial={}B",
                      PublicHttpTargetForLog(detail::EffectiveHttpPath(cfg.path)),
                      payload_len);
        const auto executor = co_await net::this_coro::executor;
        auto domain = ExecutionDomain::Current();
        auto& services = domain ? domain->Services()
                                : net::query(executor, net::execution::context);
        co_return std::make_unique<XHttpUploadClientStream>(
            executor, services,
            MakeHttp1BodyStream(std::move(stream), Http1BodyUntilClose{}, true));
    }
    if (!co_await WriteFullToStream(*stream, request)) {
        co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
    }
    if (kind == XHttpClientRequestKind::PacketUp && payload_len > 0) {
        try {
            co_await stream->WriteBuffers(packet_payload);
        } catch (...) {
            co_return tl::unexpected(ErrorCode::SOCKET_WRITE_FAILED);
        }
    }

    auto head = co_await ReadHttp1MessageHead(*stream);
    if (!head) {
        co_return tl::unexpected(head.error());
    }
    const std::string_view response = head->Text();
    if (!HasStatusCode(ExtractStartLine(response), "200")) {
        co_return tl::unexpected(ErrorCode::PROTOCOL_DECODE_FAILED);
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
                  PublicHttpTargetForLog(detail::EffectiveHttpPath(cfg.path)));
    co_return MakeHttp1BodyStream(
        std::move(stream), read_framing, false, head->ReadAhead());
}

}  // namespace transport::internet
