#include "transport/tcp_stream.hpp"
#include "common/allocator.hpp"
#include "common/const_buffer_span.hpp"
#include "transport/timeout_scheduler.hpp"
#include "transport/connection_timeouts.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/buffer.hpp>
#include <asio/use_awaitable.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <system_error>

#include <cerrno>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <vector>


namespace transport {

namespace {
constexpr size_t kProxyProbeBytes = 256;
template<class Timeouts, bool IsRead>
struct OperationTimeoutScope {
    explicit OperationTimeoutScope(Timeouts& timeouts, bool adopt_existing = false)
        : timeouts(timeouts)
        , owns(!adopt_existing || !timeouts.IsPending(IsRead)) {
        if (owns) {
            if constexpr (IsRead) timeouts.BeginRead();
            else timeouts.BeginWrite();
        }
    }
    OperationTimeoutScope(const OperationTimeoutScope&) = delete;
    OperationTimeoutScope& operator=(const OperationTimeoutScope&) = delete;
    ~OperationTimeoutScope() noexcept {
        if (owns) {
            if constexpr (IsRead) timeouts.EndRead();
            else timeouts.EndWrite();
        }
    }
    Timeouts& timeouts;
    bool owns = true;
};

// Explicit cancellation also covers a successful readiness notification that
// was queued before Cancel. Only the owning Worker touches payload.
class WriteCompletion final : private transport::CancellationSubscription {
public:
    explicit WriteCompletion(transport::CancellationSource& source) noexcept {
        Resubscribe(source);
    }


    bool Cancelled() const noexcept { return cancelled_; }

private:
    void OnCancellation(transport::Cancellation) noexcept override { cancelled_ = true; }
    bool cancelled_ = false;
};

struct ConnectTimeout final : TimeoutEvent {
    explicit ConnectTimeout(TcpStream& stream) : stream(stream) {}

    void OnTimeout() override {
        timed_out = true;
        stream.Cancel();
        stream.Close();
    }

    TcpStream& stream;
    bool timed_out = false;
};

net::io_context& SocketIoContext(tcp::socket& socket) {
    return static_cast<net::io_context&>(socket.get_executor().context());
}

ProxyProtocolReadResult ProxyReadResult(
    ProxyProtocolReadStatus status,
    ProxyProtocolResult result = {}) {
    ProxyProtocolReadResult out;
    out.status = status;
    out.result = std::move(result);
    return out;
}

// Gate before each nonblocking send attempt, including a skipped first attempt.
void ThrowIfWriteAborted(bool cancelled_or_stopped, bool deferred,
                         net::cancellation_type coro_cancelled) {
    if (cancelled_or_stopped ||
        (!deferred && coro_cancelled != net::cancellation_type::none)) {
        throw IoSystemError(io_error::operation_aborted);
    }
}

void SetupConnectedSocket(tcp::socket& sock);
}

enum Flag : uint8_t {
    kAbortiveClose          = 1u << 0,
    kReadShutdown           = 1u << 1,
    kWriteShutdown          = 1u << 2,
    kDeferWriteCancellation = 1u << 4,
};

struct TcpStream::Impl {
    static constexpr uint8_t kReadDrainBudget = 16;

    explicit Impl(tcp::socket sock, TcpStream& owner)
        : socket(std::move(sock))
        , owner(owner)
        , timeouts(SocketIoContext(this->socket), *this) {}

    void OnTimeout(common::ErrorCode reason) noexcept {
        // A deadline is terminal, not a graceful EOF. Select reset before
        // notifying subscribers: a subscriber can close the socket reentrantly,
        // and a normal close would leave queued writes draining without a bound.
        SetFlag(kAbortiveClose);
        if (reason != common::ErrorCode::CANCELLED) owner.Cancellation().Stop(reason);
        owner.Cancel();
        owner.Close();
    }

    void MarkCancelled() noexcept {
        ++cancellation_epoch_;
        read_drain_budget = 0;
    }

    tcp::socket::executor_type GetExecutor() noexcept {
        return socket.get_executor();
    }

    net::awaitable<IoErrorCode> Wait(
        tcp::socket::wait_type type, net::cancellation_slot cancellation) {
        return WaitSocket(
            socket, type, cancellation, cancellation_epoch_);
    }

    [[nodiscard]] bool HasFlag(Flag flag) const noexcept {
        return (flags & static_cast<uint8_t>(flag)) != 0;
    }

    void SetFlag(Flag flag, bool enabled = true) noexcept {
        if (enabled) {
            flags |= static_cast<uint8_t>(flag);
        } else {
            flags &= static_cast<uint8_t>(~static_cast<uint8_t>(flag));
        }
    }

    tcp::socket socket;
    TcpStream& owner;
    ConnectionTimeouts<Impl> timeouts;
    common::MultiBuffer pending_data;
    std::uint64_t cancellation_epoch_ = 0;
    uint8_t read_drain_budget = 0;
    uint8_t flags = 0;
};

DetachedTcpState::~DetachedTcpState() noexcept {
    if (fd >= 0) ::close(fd);
}

DetachedTcpState::DetachedTcpState(DetachedTcpState&& other) noexcept
    : fd(std::exchange(other.fd, -1))
    , protocol(other.protocol)
    , pending_bytes(std::move(other.pending_bytes)) {}

DetachedTcpState& DetachedTcpState::operator=(DetachedTcpState&& other) noexcept {
    if (this != &other) {
        if (fd >= 0) ::close(fd);
        fd = std::exchange(other.fd, -1);
        protocol = other.protocol;
        pending_bytes = std::move(other.pending_bytes);
    }
    return *this;
}

// ============================================================================
// TcpStream 实现
// ============================================================================

TcpStream::TcpStream(tcp::socket socket)
    : impl_(std::make_unique<Impl>(std::move(socket), *this)) {
    if (impl_->socket.is_open()) {
        SetupConnectedSocket(impl_->socket);
        impl_->socket.non_blocking(true);
    }
}

TcpStream::~TcpStream() {
    // Close() 内部已包含所有 Cancel 调用与 pending 释放，不重复
    Close();
}

net::awaitable<std::size_t> TcpStream::AsyncRead(net::mutable_buffer buf) {
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        impl_->read_drain_budget = 0;
        co_return 0;
    }

    // 先返回 pending 数据；Buffer 游标推进后，消费完立即归还。
    if (!impl_->pending_data.empty()) {
        const size_t copy = ConsumePendingData(buf);
        TouchActivity();
        co_return copy;
    }

    auto [ec, n] = co_await AsyncReceiveSome(buf);

    if (ec) {
        if (ec == io_error::eof) {
            co_return 0;
        }
        // A reset is a truncation, not the peer's orderly end of stream.
        throw IoSystemError(ec);
    }
    // AsyncReceiveSome already refreshed idle activity on every successful
    // non-peek return.
    co_return n;
}

// ============================================================================
// TcpStream::ReadMultiBuffer
//
// Readiness is delivered without payload. The owning Worker then performs
// nonblocking recv directly into its single Buffer within a bounded drain
// budget until EAGAIN or a short read requires re-arming readiness.
// pending_data remains ordered before unread socket bytes.
// ============================================================================
net::awaitable<common::MultiBuffer> TcpStream::ReadMultiBuffer() {
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        impl_->read_drain_budget = 0;
        co_return common::MultiBuffer{};
    }

    // 先消费 pending_data；MultiBuffer move 即转移剩余 Buffer 所有权。
    if (!impl_->pending_data.empty()) {
        common::MultiBuffer pending = std::move(impl_->pending_data);
        TouchActivity();
        co_return pending;
    }

    impl_->timeouts.CheckCanBeginRead();
    const auto cancellation = co_await net::this_coro::cancellation_state;
    std::optional<WriteCompletion> completion;
    std::optional<OperationTimeoutScope<decltype(impl_->timeouts), true>> timeout_scope;

    for (;;) {
        if ((completion ? completion->Cancelled() : Cancellation().Stopped()) ||
            cancellation.cancelled() != net::cancellation_type::none) {
            impl_->read_drain_budget = 0;
            throw IoSystemError(io_error::operation_aborted);
        }

        bool fresh_wait = false;
        if (impl_->read_drain_budget != 0) {
            --impl_->read_drain_budget;
        } else {
            if (!completion) completion.emplace(Cancellation());
            if (!timeout_scope) timeout_scope.emplace(impl_->timeouts);
            if (completion->Cancelled() ||
                cancellation.cancelled() != net::cancellation_type::none) {
                impl_->read_drain_budget = 0;
                throw IoSystemError(io_error::operation_aborted);
            }
            const IoErrorCode wait_ec = co_await impl_->Wait(
                tcp::socket::wait_read, cancellation.slot());
            if (completion->Cancelled() && !wait_ec) {
                impl_->read_drain_budget = 0;
                throw IoSystemError(io_error::operation_aborted);
            }
            if (wait_ec) {
                impl_->read_drain_budget = 0;
                if (wait_ec == io_error::eof) {
                    co_return common::MultiBuffer{};
                }
                throw IoSystemError(wait_ec);
            }
            fresh_wait = true;
        }

        if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
            impl_->read_drain_budget = 0;
            co_return common::MultiBuffer{};
        }
        if (!impl_->pending_data.empty()) {
            common::MultiBuffer pending = std::move(impl_->pending_data);
            TouchActivity();
            co_return pending;
        }

        common::BufferGuard buffer{common::Buffer::New()};
        if (!buffer) {
            throw std::bad_alloc();
        }
        const auto avail = buffer->Available();
        const auto received = ::recv(
            impl_->socket.native_handle(),
            buffer->Tail().data(),
            avail,
            MSG_DONTWAIT);
        if (received > 0) {
            if (static_cast<size_t>(received) < avail) {
                impl_->read_drain_budget = 0;
            } else if (fresh_wait) {
                impl_->read_drain_budget = Impl::kReadDrainBudget - 1;
            }
            buffer->Produce(static_cast<uint32_t>(received));
            TouchActivity();
            co_return common::MultiBuffer{std::move(buffer)};
        }
        if (received == 0) {
            impl_->read_drain_budget = 0;
            co_return common::MultiBuffer{};
        }
        if (errno == EINTR) {
            if (fresh_wait) impl_->read_drain_budget = 1;
            continue;
        }
        impl_->read_drain_budget = 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        }
        throw IoSystemError(IoErrorCode(errno, io_error::get_system_category()));
    }
}

// ============================================================================
// TcpStream 写路径
//
// Scatter-send executes only on the owning Worker; native asynchronous work
// consists solely of readiness notifications and never retains payload spans.
// ============================================================================
bool TcpStream::DrainWriteAvailable(
    std::span<const net::const_buffer>& buffers,
    std::size_t& offset,
    bool cancelled_or_stopped,
    bool deferred,
    net::cancellation_type coro_cancelled) {
    while (!buffers.empty()) {
        ThrowIfWriteAborted(cancelled_or_stopped, deferred, coro_cancelled);
        IoErrorCode error;
        const auto sent = WriteAvailable(buffers, offset, error);
        if (error) {
            if (error == io_error::interrupted) continue;
            if (error != io_error::would_block && error != io_error::try_again) {
                throw IoSystemError(error);
            }
            return false;
        }
        auto remaining = sent;
        while (!buffers.empty() && remaining >= buffers.front().size() - offset) {
            remaining -= buffers.front().size() - offset;
            buffers = buffers.subspan(1);
            offset = 0;
        }
        offset += remaining;
        while (!buffers.empty() && buffers.front().size() == 0) {
            buffers = buffers.subspan(1);
        }
    }
    return true;
}

net::awaitable<void> TcpStream::WriteMultiBuffer(common::MultiBuffer mb) {
    if (mb.byte_size() == 0) {
        mb.clear();
        co_return;
    }
    if (!impl_->socket.is_open() || impl_->HasFlag(kWriteShutdown)) {
        mb.clear();
        throw IoSystemError(io_error::broken_pipe);
    }
    common::ConstBufferSpanBuilder<common::MultiBuffer::kInlineCapacity> builder;
    try {
        builder.AppendMultiBuffer(mb);
        auto buffers = builder.Span();
        while (!buffers.empty() && buffers.front().size() == 0) buffers = buffers.subspan(1);
        if (buffers.empty()) {
            mb.clear();
            co_return;
        }
        impl_->timeouts.CheckCanBeginWrite();
        const auto cancellation = co_await net::this_coro::cancellation_state;
        const bool deferred = IsWriteCancellationDeferred();
        size_t offset = 0;
        if (DrainWriteAvailable(
                buffers, offset, Cancellation().Stopped(), deferred, cancellation.cancelled())) {
            mb.clear();
            co_return;
        }
        co_await WriteBuffersFrom(buffers, offset, true);
    } catch (...) {
        mb.clear();
        throw;
    }
    mb.clear();
}

net::awaitable<void> TcpStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    return WriteBuffersFrom(buffers, 0, false);
}

// `blocked`: the caller's nonblocking attempt just hit EAGAIN without
// suspending since, so go straight to the writable wait.
net::awaitable<void> TcpStream::WriteBuffersFrom(
    std::span<const net::const_buffer> buffers, std::size_t offset, bool blocked) {
    if (!impl_->socket.is_open() || impl_->HasFlag(kWriteShutdown)) {
        throw IoSystemError(io_error::broken_pipe);
    }

    while (!buffers.empty() && buffers.front().size() == 0) buffers = buffers.subspan(1);
    if (buffers.empty()) co_return;
    impl_->timeouts.CheckCanBeginWrite();
    const auto cancellation = co_await net::this_coro::cancellation_state;
    const bool deferred = IsWriteCancellationDeferred();
    if (blocked) {
        ThrowIfWriteAborted(Cancellation().Stopped(), deferred, cancellation.cancelled());
    } else if (DrainWriteAvailable(
            buffers, offset, Cancellation().Stopped(), deferred, cancellation.cancelled())) {
        co_return;
    }

    WriteCompletion completion(Cancellation());
    OperationTimeoutScope<decltype(impl_->timeouts), false> timeout_scope{impl_->timeouts};
    const auto slot = deferred ? net::cancellation_slot{} : cancellation.slot();
    const bool previous_throw = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    try {
        for (;;) {
            const auto ec = co_await impl_->Wait(tcp::socket::wait_write, slot);
            if (ec) throw IoSystemError(ec);
            if (DrainWriteAvailable(
                    buffers, offset, completion.Cancelled(), deferred, cancellation.cancelled())) {
                break;
            }
        }
    } catch (...) { failure = std::current_exception(); }
    co_await net::this_coro::throw_if_cancelled(previous_throw);
    if (failure) std::rethrow_exception(failure);
}
net::awaitable<std::size_t> TcpStream::AsyncWrite(net::const_buffer buf) {
    const size_t size = buf.size();
    co_await WriteBuffers(std::span<const net::const_buffer>(&buf, 1));
    co_return size;
}

void TcpStream::ShutdownRead() {
    ReleasePendingData();
    impl_->read_drain_budget = 0;
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        return;
    }

    IoErrorCode ec;
    impl_->socket.shutdown(tcp::socket::shutdown_receive, ec);
    impl_->SetFlag(kReadShutdown);
}

void TcpStream::ShutdownWrite() {
    if (!impl_->socket.is_open() || impl_->HasFlag(kWriteShutdown)) {
        return;
    }

    IoErrorCode ec;
    impl_->socket.shutdown(tcp::socket::shutdown_send, ec);
    impl_->SetFlag(kWriteShutdown);
}

void TcpStream::Close() {
    ReleasePendingData();
    impl_->MarkCancelled();
    impl_->timeouts.Stop();
    NotifyClosed();
    if (impl_->socket.is_open()) {
        IoErrorCode ec;
        // 仅错误路径使用 abortive close；正常关闭保持 FIN 语义，
        // 避免高并发下统一 RST 导致对端看到 connection reset。
        if (impl_->HasFlag(kAbortiveClose)) {
            struct linger lg = {1, 0};
            ::setsockopt(impl_->socket.native_handle(), SOL_SOCKET, SO_LINGER,
                         reinterpret_cast<const char*>(&lg), sizeof(lg));
        }
        impl_->socket.shutdown(tcp::socket::shutdown_both, ec);
        impl_->socket.close(ec);
    }
    impl_->SetFlag(kReadShutdown);
    impl_->SetFlag(kWriteShutdown);
}

void TcpStream::Cancel() noexcept {
    impl_->MarkCancelled();
    NotifyCancellation();
    if (impl_->socket.is_open()) {
        IoErrorCode ec;
        impl_->socket.cancel(ec);
    }
}

int TcpStream::NativeHandle() const {
    if (!impl_->socket.is_open()) {
        return -1;
    }
    return static_cast<int>(const_cast<tcp::socket&>(impl_->socket).native_handle());
}

bool TcpStream::IsOpen() const {
    return impl_->socket.is_open();
}

net::awaitable<std::pair<IoErrorCode, std::size_t>> TcpStream::AsyncReceiveSome(
    net::mutable_buffer buffer,
    bool peek) {
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        impl_->read_drain_budget = 0;
        co_return std::make_pair(io_error::not_connected, std::size_t{0});
    }

    if (buffer.size() == 0) {
        if (!peek) TouchActivity();
        co_return std::make_pair(IoErrorCode{}, size_t{0});
    }
    impl_->timeouts.CheckCanBeginRead();
    const auto cancellation = co_await net::this_coro::cancellation_state;
    std::optional<WriteCompletion> completion;
    std::optional<OperationTimeoutScope<decltype(impl_->timeouts), true>> timeout_scope;
    for (;;) {
        if ((completion ? completion->Cancelled() : Cancellation().Stopped()) ||
            cancellation.cancelled() != net::cancellation_type::none) {
            impl_->read_drain_budget = 0;
            co_return std::make_pair(IoErrorCode(io_error::operation_aborted), size_t{0});
        }
        const auto received = ::recv(impl_->socket.native_handle(), buffer.data(), buffer.size(),
                                    MSG_DONTWAIT | (peek ? MSG_PEEK : 0));
        if (received > 0) {
            if (peek || static_cast<size_t>(received) < buffer.size()) {
                impl_->read_drain_budget = 0;
            }
            if (!peek) TouchActivity();
            co_return std::make_pair(IoErrorCode{}, static_cast<size_t>(received));
        }
        impl_->read_drain_budget = 0;
        if (received == 0) co_return std::make_pair(IoErrorCode(io_error::eof), size_t{0});
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            co_return std::make_pair(IoErrorCode(errno, std::system_category()), size_t{0});
        if (!completion) completion.emplace(Cancellation());
        if (!timeout_scope) timeout_scope.emplace(impl_->timeouts, true);
        if (completion->Cancelled() || cancellation.cancelled() != net::cancellation_type::none)
            co_return std::make_pair(IoErrorCode(io_error::operation_aborted), size_t{0});
        const auto ec = co_await impl_->Wait(tcp::socket::wait_read, cancellation.slot());
        if (ec) co_return std::make_pair(ec, size_t{0});
    }
}

net::awaitable<ProxyProtocolReadResult> TcpStream::ReadProxyProtocolHeader(
    std::chrono::seconds timeout) {
    SetIdleTimeout(timeout);
    auto deadline = StartPhaseDeadline(timeout);
    // 每个出口（含异常）都结束本阶段截止时间；返回值在析构前已求值。
    struct PhaseDeadlineScope {
        TcpStream& stream;
        ~PhaseDeadlineScope() { stream.ClearPhaseDeadline(); }
    } phase_scope{*this};

    // 读失败或 EOF：区分截止时间到期与对端截断。
    auto read_failed = [&](ProxyProtocolResult result) {
        const bool expired = deadline.Expired();
        const bool phase = ConsumePhaseDeadline();
        const bool idle = ConsumeIdleTimeout();
        return ProxyReadResult(expired || phase || idle
            ? ProxyProtocolReadStatus::TimedOut
            : ProxyProtocolReadStatus::Truncated, std::move(result));
    };

    std::array<uint8_t, kProxyProbeBytes> probe;
    auto [peek_ec, probe_len] = co_await AsyncReceiveSome(
        net::buffer(probe), true);
    if (peek_ec || probe_len == 0) co_return read_failed({});

    auto result = ParseProxyProtocolHeader(
        std::span<const uint8_t>(probe.data(), probe_len));

    if (!result.incomplete()) {
        if (result.status == ProxyProtocolParseStatus::Invalid) {
            co_return ProxyReadResult(ProxyProtocolReadStatus::Invalid, std::move(result));
        }

        size_t remaining = result.consumed;
        while (remaining > 0) {
            const size_t want = std::min(remaining, probe.size());
            auto [read_ec, n] = co_await AsyncReceiveSome(
                net::buffer(probe.data(), want));
            if (read_ec || n == 0) co_return read_failed(std::move(result));
            remaining -= n;
        }
        co_return ProxyReadResult(ProxyProtocolReadStatus::Ok, std::move(result));
    }

    std::vector<uint8_t> buf;

    while (buf.size() < kProxyHeaderMaxBytes) {
        auto [read_ec, n] = co_await AsyncReceiveSome(net::buffer(probe));
        // Only an incomplete header reaches this loop: whatever arrived so far
        // cannot complete it any more.
        if (read_ec || n == 0) co_return read_failed(std::move(result));
        const size_t required = buf.size() + n;
        if (required > buf.capacity()) {
            buf.reserve(std::min<size_t>(
                kProxyHeaderMaxBytes + kProxyProbeBytes,
                std::max(required, std::max<size_t>(kProxyProbeBytes, buf.capacity() * 2))));
        }
        buf.insert(buf.end(), probe.begin(),
                   probe.begin() + static_cast<ptrdiff_t>(n));
        result = ParseProxyProtocolHeader(buf);
        if (result.incomplete()) {
            continue;
        }

        if (result.status == ProxyProtocolParseStatus::Invalid) {
            co_return ProxyReadResult(ProxyProtocolReadStatus::Invalid, std::move(result));
        }
        // The limit bounds the header itself, not payload read along with it.
        if (result.consumed > kProxyHeaderMaxBytes) {
            co_return ProxyReadResult(ProxyProtocolReadStatus::TooLarge, std::move(result));
        }
        if (result.consumed < buf.size()) {
            ReleasePendingData();
            if (!common::AppendSpanToMultiBuffer(
                    std::span<const uint8_t>(buf).subspan(result.consumed),
                    impl_->pending_data)) {
                throw std::bad_alloc();
            }
        }
        co_return ProxyReadResult(ProxyProtocolReadStatus::Ok, std::move(result));
    }

    co_return ProxyReadResult(ProxyProtocolReadStatus::TooLarge, std::move(result));
}

void TcpStream::PrependReadData(std::span<const uint8_t> data) {
    if (data.empty()) return;
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        throw IoSystemError(io_error::operation_aborted, "TCP read closed");
    }
    common::MultiBuffer prefix;
    if (!common::AppendSpanToMultiBuffer(data, prefix)) {
        throw std::bad_alloc();
    }
    PrependReadMultiBuffer(std::move(prefix));
}

void TcpStream::PrependReadMultiBuffer(common::MultiBuffer&& mb) {
    if (mb.byte_size() == 0) {
        mb.clear();
        return;
    }
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        mb.clear();
        throw IoSystemError(io_error::operation_aborted, "TCP read closed");
    }
    // MoveTo reserves before transferring; allocation failure preserves old data.
    impl_->pending_data.MoveTo(mb);
    impl_->pending_data = std::move(mb);
}

std::optional<DetachedTcpState> TcpStream::DetachForHandoff(
    common::MultiBuffer prefix) {
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        return std::nullopt;
    }
    DetachedTcpState state;
    if (!impl_->pending_data.empty()) {
        if (prefix.empty()) {
            prefix = std::move(impl_->pending_data);
        } else {
            impl_->pending_data.MoveTo(prefix);
        }
    }
    ReleasePendingData();
    state.pending_bytes = std::move(prefix);
    IoErrorCode ec;
    const auto local_ep = impl_->socket.local_endpoint(ec);
    if (ec) return std::nullopt;
    state.protocol = local_ep.protocol();
    impl_->MarkCancelled();
    impl_->timeouts.Stop();
    state.fd = impl_->socket.release(ec);
    if (ec || state.fd < 0) return std::nullopt;
    NotifyClosed();
    impl_->SetFlag(kReadShutdown);
    impl_->SetFlag(kWriteShutdown);
    return state;
}

std::optional<DetachedTcpState> TcpStream::DetachForHandoff(
    std::span<const uint8_t> prefix) {
    common::MultiBuffer mb;
    if (!prefix.empty() && !common::AppendSpanToMultiBuffer(prefix, mb)) {
        throw std::bad_alloc();
    }
    return DetachForHandoff(std::move(mb));
}

std::unique_ptr<TcpStream> TcpStream::RestoreFromHandoff(
    net::io_context& io_context, DetachedTcpState state) {
    if (state.fd < 0) return nullptr;
    tcp::socket socket(io_context);
    IoErrorCode ec;
    socket.assign(state.protocol, state.fd, ec);
    if (ec) return nullptr;
    state.fd = -1;
    auto stream = std::make_unique<TcpStream>(std::move(socket));
    if (!state.pending_bytes.empty()) {
        stream->PrependReadMultiBuffer(std::move(state.pending_bytes));
    }
    return stream;
}

void TcpStream::SetAbortiveClose(bool enable) noexcept {
    impl_->SetFlag(kAbortiveClose, enable);
}

void TcpStream::SetWriteCancellationDeferred() noexcept {
    impl_->SetFlag(kDeferWriteCancellation);
}

bool TcpStream::IsWriteCancellationDeferred() const noexcept {
    return impl_->HasFlag(kDeferWriteCancellation);
}

tcp::socket::executor_type TcpStream::GetExecutor() noexcept {
    return impl_->GetExecutor();
}

net::awaitable<IoErrorCode> TcpStream::WaitReadable(net::cancellation_slot cancellation) {
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        impl_->read_drain_budget = 0;
        co_return io_error::eof;
    }
    if (impl_->pending_data.byte_size() != 0) {
        co_return IoErrorCode{};
    }

    WriteCompletion completion(Cancellation());
    OperationTimeoutScope<decltype(impl_->timeouts), true> timeout_scope{impl_->timeouts, true};
    const auto coro_cancellation = co_await net::this_coro::cancellation_state;
    if (!cancellation.is_connected())
        cancellation = coro_cancellation.slot();
    if (completion.Cancelled() ||
        coro_cancellation.cancelled() != net::cancellation_type::none) {
        impl_->read_drain_budget = 0;
        co_return IoErrorCode(io_error::operation_aborted);
    }
    const auto ec = co_await impl_->Wait(tcp::socket::wait_read, cancellation);
    if (completion.Cancelled() && !ec) {
        impl_->read_drain_budget = 0;
        co_return IoErrorCode(io_error::operation_aborted);
    }
    impl_->read_drain_budget = ec ? 0 : static_cast<uint8_t>(Impl::kReadDrainBudget - 1);
    co_return ec;
}

bool TcpStream::CanRead() const noexcept {
    return impl_->socket.is_open() && !impl_->HasFlag(kReadShutdown);
}

bool TcpStream::CanWrite() const noexcept {
    return impl_->socket.is_open() && !impl_->HasFlag(kWriteShutdown);
}

bool TcpStream::TryConsumeReadableBudget() noexcept {
    if (!CanRead()) {
        impl_->read_drain_budget = 0;
        return false;
    }
    if (!impl_->pending_data.empty()) {
        return true;
    }
    if (impl_->read_drain_budget != 0) {
        --impl_->read_drain_budget;
        return true;
    }
    return false;
}

void TcpStream::ResetReadableBudget() noexcept {
    impl_->read_drain_budget = 0;
}

std::size_t TcpStream::ReadAvailable(
    net::mutable_buffer target, IoErrorCode& error) noexcept {
    error.clear();
    if (!CanRead()) {
        impl_->read_drain_budget = 0;
        error = io_error::eof;
        return 0;
    }
    if (target.size() == 0) return 0;
    std::size_t n = ConsumePendingData(target);
    if (n == 0) {
        ssize_t received = 0;
        do {
            received = ::recv(
                impl_->socket.native_handle(),
                target.data(),
                target.size(),
                MSG_DONTWAIT);
        } while (received < 0 && errno == EINTR);
        if (received > 0) {
            n = static_cast<std::size_t>(received);
            if (n < target.size()) {
                impl_->read_drain_budget = 0;
            }
        } else {
            impl_->read_drain_budget = 0;
            error = received == 0
                ? IoErrorCode(io_error::eof)
                : IoErrorCode(errno, io_error::get_system_category());
            return 0;
        }
    }
    TouchActivity();
    return n;
}

std::size_t TcpStream::WriteAvailable(
    std::span<const net::const_buffer> buffers, std::size_t offset,
    IoErrorCode& error) noexcept {
    error.clear();
    if (!CanWrite()) {
        error = io_error::broken_pipe;
        return 0;
    }
    ssize_t sent;
    if (buffers.size() == 1) {
        const auto buffer = buffers.front() + offset;
        if (buffer.size() == 0) return 0;
        sent = ::send(impl_->socket.native_handle(), buffer.data(),
                      buffer.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
    } else {
        std::array<iovec, 16> vectors;
        size_t count = 0;
        for (size_t i = 0; i < buffers.size() && count < vectors.size(); ++i) {
            const auto buffer = buffers[i] + (i == 0 ? offset : 0);
            if (!buffer.size()) continue;
            vectors[count++] = {const_cast<void*>(buffer.data()), buffer.size()};
        }
        if (count == 0) return 0;
        msghdr message{};
        message.msg_iov = vectors.data();
        message.msg_iovlen = count;
        sent = ::sendmsg(impl_->socket.native_handle(), &message,
                         MSG_DONTWAIT | MSG_NOSIGNAL);
    }
    if (sent < 0) {
        error = IoErrorCode(errno, io_error::get_system_category());
        return 0;
    }
    if (sent == 0) {
        error = io_error::broken_pipe;
        return 0;
    }
    TouchActivity();
    return static_cast<std::size_t>(sent);
}

tcp::endpoint TcpStream::LocalEndpoint() const {
    if (!impl_->socket.is_open()) {
        return tcp::endpoint();
    }
    IoErrorCode ec;
    auto ep = impl_->socket.local_endpoint(ec);
    return ec ? tcp::endpoint() : ep;
}

tcp::endpoint TcpStream::RemoteEndpoint() const {
    if (!impl_->socket.is_open()) {
        return tcp::endpoint();
    }
    IoErrorCode ec;
    auto ep = impl_->socket.remote_endpoint(ec);
    return ec ? tcp::endpoint() : ep;
}

// ============================================================================
// 静态连接方法
// ============================================================================

// Register the stable stream before connect suspends. A pending dial then
// transfers its existing in-progress fd just like an established connection.
net::awaitable<DialResult> TcpStream::Connect(
    net::io_context& io_context,
    const tcp::endpoint& endpoint,
    const net::ip::address* bind_local,
    std::chrono::seconds timeout) {

    if (timeout.count() <= 0) {
        co_return DialResult::Fail(common::ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }
    IoErrorCode ec;
    tcp::socket socket(io_context);
    socket.open(endpoint.protocol(), ec);
    if (ec)
        co_return DialResult::Fail(common::ErrorCode::SOCKET_CREATE_FAILED, ec.message());
    if (bind_local) {
        socket.bind(tcp::endpoint(*bind_local, 0), ec);
        if (ec)
            co_return DialResult::Fail(common::ErrorCode::SOCKET_BIND_FAILED, ec.message());
    }

    auto stream = std::make_unique<TcpStream>(std::move(socket));
    ConnectTimeout deadline(*stream);
    auto& scheduler = TimeoutScheduler::ForIoContext(SocketIoContext(stream->impl_->socket));
    if (!scheduler.ScheduleAfter(
            std::chrono::duration_cast<std::chrono::milliseconds>(timeout), deadline))
        co_return DialResult::Fail(common::ErrorCode::CANCELLED, "connection cancelled");

    IoErrorCode connect_ec;
    const auto result = ::connect(stream->NativeHandle(), endpoint.data(), endpoint.size());
    if (result != 0 && errno != EISCONN) {
        if (errno == EINPROGRESS || errno == EALREADY || errno == EINTR) {
            const auto cancellation = co_await net::this_coro::cancellation_state;
            connect_ec = co_await stream->impl_->Wait(tcp::socket::wait_write, cancellation.slot());
            if (!connect_ec) {
                int error = 0;
                socklen_t size = sizeof(error);
                if (::getsockopt(stream->NativeHandle(), SOL_SOCKET, SO_ERROR, &error, &size) != 0)
                    error = errno;
                if (error != 0) connect_ec = IoErrorCode(error, std::system_category());
            }
        } else {
            connect_ec = IoErrorCode(errno, std::system_category());
        }
    }
    deadline.Cancel();
    if (deadline.timed_out)
        co_return DialResult::Fail(common::ErrorCode::DIAL_TIMEOUT, "connection timed out");
    if (connect_ec)
        co_return DialResult::Fail(common::MapAsioError(connect_ec), connect_ec.message());
    co_return DialResult::Success(std::move(stream));
}

// ============================================================================
// Idle Timeout
// ============================================================================

void TcpStream::SetIdleTimeout(std::chrono::seconds timeout) {
    impl_->timeouts.SetIdleTimeout(timeout);
}

bool TcpStream::ConsumeIdleTimeout() noexcept {
    return impl_->timeouts.ConsumeIdleTimeout();
}

void TcpStream::SetReadTimeout(std::chrono::seconds timeout) {
    impl_->timeouts.SetReadTimeout(timeout);
}

void TcpStream::SetWriteTimeout(std::chrono::seconds timeout) {
    impl_->timeouts.SetWriteTimeout(timeout);
}

bool TcpStream::ConsumeReadTimeout() noexcept {
    return impl_->timeouts.ConsumeReadTimeout();
}

bool TcpStream::ConsumeWriteTimeout() noexcept {
    return impl_->timeouts.ConsumeWriteTimeout();
}

PhaseDeadlineHandle TcpStream::StartPhaseDeadline(std::chrono::seconds timeout) {
    if (!impl_->socket.is_open()) return {};
    return impl_->timeouts.StartPhaseDeadline(timeout);
}

void TcpStream::ClearPhaseDeadline() {
    impl_->timeouts.ClearPhaseDeadline();
}

bool TcpStream::ConsumePhaseDeadline() noexcept {
    return impl_->timeouts.ConsumePhaseDeadline();
}

size_t TcpStream::ConsumePendingData(net::mutable_buffer target) noexcept {
    auto& pending = impl_->pending_data;
    const auto consumed = pending.ConsumePrefixTo(
        std::span<uint8_t>(
            static_cast<uint8_t*>(target.data()),
            target.size()));
    pending.ReleaseIfIdle();
    return consumed;
}

void TcpStream::ReleasePendingData() noexcept {
    impl_->pending_data.clear();
}

// Successful I/O refreshes the authoritative connection idle deadline.
void TcpStream::TouchActivity() noexcept {
    impl_->timeouts.TouchActivity();
}


// ============================================================================
// Socket 设置函数
// ============================================================================

namespace {
void SetupConnectedSocket(tcp::socket& sock) {
    if (!sock.is_open()) {
        return;
    }

    IoErrorCode ec;
    auto fd = sock.native_handle();

    sock.set_option(net::socket_base::keep_alive(true), ec);

    // 60 seconds idle, then six probes 10 seconds apart.
    int keepidle = 60;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE,
               reinterpret_cast<const char*>(&keepidle), sizeof(keepidle));

    int keepintvl = 10;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL,
               reinterpret_cast<const char*>(&keepintvl), sizeof(keepintvl));

    int keepcnt = 6;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT,
               reinterpret_cast<const char*>(&keepcnt), sizeof(keepcnt));
}
}  // namespace

}  // namespace transport

