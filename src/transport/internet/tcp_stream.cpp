#include "transport/internet/tcp_stream.hpp"
#include "app/session_group_executor.hpp"
#include "common/allocator.hpp"
#include "common/buffer_util.hpp"
#include "transport/internet/timeout_scheduler.hpp"
#include "connection_timeouts.hpp"
#include "native_socket_handoff.hpp"

#include <asio/buffer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <system_error>

#include <cerrno>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/tcp.h>


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
// was queued before Cancel. Only the owning execution domain touches payload.
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

void SetupConnectedSocket(tcp::socket& sock);
}

enum Flag : uint8_t {
    kAbortiveClose          = 1u << 0,
    kReadShutdown           = 1u << 1,
    kWriteShutdown          = 1u << 2,
    kDeferWriteCancellation = 1u << 4,
};

struct TcpStream::Impl : memory::ThreadAllocated,
                         transport::internet::detail::NativeSocketHandoff<tcp> {
    explicit Impl(tcp::socket socket, TcpStream& owner)
        : NativeSocketHandoff(std::move(socket))
        , owner(owner)
        , timeouts(SocketIoContext(this->socket), *this)
        , executor(ExecutionDomain::Current() ? ExecutionDomain::Current()->Executor()
                                             : this->socket.get_executor()) {}

    void OnTimeout(ErrorCode reason) noexcept {
        // A deadline is terminal, not a graceful EOF. Select reset before
        // notifying subscribers: a subscriber can close the socket reentrantly,
        // and a normal close would leave queued writes draining without a bound.
        SetFlag(kAbortiveClose);
        if (reason != ErrorCode::CANCELLED) owner.Cancellation().Stop(reason);
        owner.Cancel();
        owner.Close();
    }

    void HandoffFailed() noexcept override { owner.Cancel(); owner.Close(); }

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

    TcpStream& owner;
    transport::internet::detail::ConnectionTimeouts<Impl> timeouts;
    net::any_io_executor executor;
    buf::MultiBuffer pending_data;
    uint8_t flags = 0;
};

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

    TouchActivity();
    co_return n;
}

// ============================================================================
// TcpStream::ReadMultiBuffer
//
// Readiness is delivered without payload. The execution domain then performs
// nonblocking recv directly into its single pool Buffer.
// pending_data remains ordered before unread socket bytes.
// ============================================================================
net::awaitable<buf::MultiBuffer> TcpStream::ReadMultiBuffer() {
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) co_return buf::MultiBuffer{};

    // 先消费 pending_data；MultiBuffer move 即转移剩余 Buffer 所有权。
    if (!impl_->pending_data.empty()) {
        buf::MultiBuffer pending = std::move(impl_->pending_data);
        TouchActivity();
        co_return pending;
    }

    OperationTimeoutScope<decltype(impl_->timeouts), true> timeout_scope{impl_->timeouts};
    for (;;) {
        const IoErrorCode wait_ec = co_await WaitReadable();
        if (wait_ec) {
            if (wait_ec == io_error::eof) {
                co_return buf::MultiBuffer{};
            }
            throw IoSystemError(wait_ec);
        }

        if (!impl_->pending_data.empty()) {
            buf::MultiBuffer pending = std::move(impl_->pending_data);
            TouchActivity();
            co_return pending;
        }

        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            throw std::bad_alloc();
        }
        const auto received = ::recv(
            impl_->socket.native_handle(),
            buffer->Tail().data(),
            buffer->Available(),
            MSG_DONTWAIT);
        if (received > 0) {
            buffer->Produce(static_cast<uint32_t>(received));
            TouchActivity();
            co_return buf::MultiBuffer{std::move(buffer)};
        }
        if (received == 0) {
            co_return buf::MultiBuffer{};
        }
        if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
            continue;
        }
        throw IoSystemError(IoErrorCode(errno, std::system_category()));
    }
}

// ============================================================================
// TcpStream 写路径
//
// Scatter-send executes only on the domain owner; native asynchronous work
// consists solely of readiness notifications and never retains payload spans.
// ============================================================================
net::awaitable<void> TcpStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {
    if (!impl_->socket.is_open() || impl_->HasFlag(kWriteShutdown)) {
        throw IoSystemError(io_error::broken_pipe);
    }

    while (!buffers.empty() && buffers.front().size() == 0) buffers = buffers.subspan(1);
    if (buffers.empty()) co_return;
    WriteCompletion completion(Cancellation());
    OperationTimeoutScope<decltype(impl_->timeouts), false> timeout_scope{impl_->timeouts};
    const auto cancellation = co_await net::this_coro::cancellation_state;
    const bool deferred = IsWriteCancellationDeferred();
    const auto slot = deferred ? net::cancellation_slot{} : cancellation.slot();
    const bool previous_throw = co_await net::this_coro::throw_if_cancelled();
    co_await net::this_coro::throw_if_cancelled(false);
    std::exception_ptr failure;
    try {
        size_t offset = 0;
        while (!buffers.empty()) {
            if (completion.Cancelled() ||
                (!deferred && cancellation.cancelled() != net::cancellation_type::none))
                throw IoSystemError(io_error::operation_aborted);
            std::array<iovec, 16> vectors;
            size_t count = 0;
            for (size_t i = 0; i < buffers.size() && count < vectors.size(); ++i) {
                const auto buffer = buffers[i] + (i == 0 ? offset : 0);
                if (!buffer.size()) continue;
                vectors[count++] = {const_cast<void*>(buffer.data()), buffer.size()};
            }
            msghdr message{};
            message.msg_iov = vectors.data();
            message.msg_iovlen = count;
            const auto sent = ::sendmsg(impl_->socket.native_handle(), &message,
                                        MSG_DONTWAIT | MSG_NOSIGNAL);
            if (sent < 0) {
                if (errno == EINTR) continue;
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    throw IoSystemError(IoErrorCode(errno, std::system_category()));
                const auto ec = co_await impl_->Wait(tcp::socket::wait_write, slot);
                if (ec) throw IoSystemError(ec);
                continue;
            }
            if (!sent) throw IoSystemError(io_error::broken_pipe);
            auto remaining = static_cast<size_t>(sent);
            while (!buffers.empty() && remaining >= buffers.front().size() - offset) {
                remaining -= buffers.front().size() - offset;
                buffers = buffers.subspan(1);
                offset = 0;
            }
            offset += remaining;
            TouchActivity();
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
        co_return std::make_pair(io_error::not_connected, std::size_t{0});
    }

    if (buffer.size() == 0) co_return std::make_pair(IoErrorCode{}, size_t{0});
    WriteCompletion completion(Cancellation());
    const auto cancellation = co_await net::this_coro::cancellation_state;
    OperationTimeoutScope<decltype(impl_->timeouts), true> timeout_scope{impl_->timeouts, true};
    for (;;) {
        if (completion.Cancelled() || cancellation.cancelled() != net::cancellation_type::none)
            co_return std::make_pair(IoErrorCode(io_error::operation_aborted), size_t{0});
        const auto received = ::recv(impl_->socket.native_handle(), buffer.data(), buffer.size(),
                                    MSG_DONTWAIT | (peek ? MSG_PEEK : 0));
        if (received > 0) {
            if (!peek) TouchActivity();
            co_return std::make_pair(IoErrorCode{}, static_cast<size_t>(received));
        }
        if (received == 0) co_return std::make_pair(IoErrorCode(io_error::eof), size_t{0});
        if (errno == EINTR) continue;
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            co_return std::make_pair(IoErrorCode(errno, std::system_category()), size_t{0});
        const auto ec = co_await impl_->Wait(tcp::socket::wait_read, cancellation.slot());
        if (ec) co_return std::make_pair(ec, size_t{0});
    }
}

net::awaitable<ProxyProtocolReadResult> TcpStream::ReadProxyProtocolHeader(
    std::chrono::seconds timeout) {
    SetIdleTimeout(timeout);
    auto deadline = StartPhaseDeadline(timeout);

    auto timed_out = [&]() noexcept {
        const bool expired = deadline.Expired();
        const bool phase = ConsumePhaseDeadline();
        const bool idle = ConsumeIdleTimeout();
        return expired || phase || idle;
    };

    std::array<uint8_t, kProxyProbeBytes> probe;
    auto [peek_ec, probe_len] = co_await AsyncReceiveSome(
        net::buffer(probe), true);

    if (peek_ec || probe_len == 0) {
        auto out = timed_out()
            ? ProxyReadResult(ProxyProtocolReadStatus::TimedOut)
            : ProxyReadResult(ProxyProtocolReadStatus::Truncated);
        ClearPhaseDeadline();
        co_return out;
    }

    auto result = ParseProxyProtocolHeader(
        std::span<const uint8_t>(probe.data(), probe_len));

    if (!result.incomplete()) {
        if (result.status == ProxyProtocolParseStatus::Invalid) {
            ClearPhaseDeadline();
            co_return ProxyReadResult(ProxyProtocolReadStatus::Invalid, std::move(result));
        }

        size_t remaining = result.consumed;
        while (remaining > 0) {
            const size_t want = std::min(remaining, probe.size());
            auto [read_ec, n] = co_await AsyncReceiveSome(
                net::buffer(probe.data(), want));
            if (read_ec || n == 0) {
                auto out = timed_out()
                    ? ProxyReadResult(ProxyProtocolReadStatus::TimedOut, std::move(result))
                    : ProxyReadResult(ProxyProtocolReadStatus::Truncated, std::move(result));
                ClearPhaseDeadline();
                co_return out;
            }
            remaining -= n;
        }

        ClearPhaseDeadline();
        co_return ProxyReadResult(ProxyProtocolReadStatus::Ok, std::move(result));
    }

    memory::ByteVector buf;

    while (buf.size() < kProxyHeaderMaxBytes) {
        auto [read_ec, n] = co_await AsyncReceiveSome(net::buffer(probe));
        if (read_ec || n == 0) {
            // Only an incomplete header reaches this loop: whatever arrived
            // so far cannot complete it any more.
            auto out = timed_out()
                ? ProxyReadResult(ProxyProtocolReadStatus::TimedOut, std::move(result))
                : ProxyReadResult(ProxyProtocolReadStatus::Truncated, std::move(result));
            ClearPhaseDeadline();
            co_return out;
        }
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
            ClearPhaseDeadline();
            co_return ProxyReadResult(ProxyProtocolReadStatus::Invalid, std::move(result));
        }
        // The limit bounds the header itself, not payload read along with it.
        if (result.consumed > kProxyHeaderMaxBytes) {
            ClearPhaseDeadline();
            co_return ProxyReadResult(ProxyProtocolReadStatus::TooLarge, std::move(result));
        }
        if (result.consumed < buf.size()) {
            ReleasePendingData();
            if (!buf::AppendSpanToMultiBuffer(
                    std::span<const uint8_t>(buf).subspan(result.consumed),
                    impl_->pending_data)) {
                throw std::bad_alloc();
            }
        }

        ClearPhaseDeadline();
        co_return ProxyReadResult(ProxyProtocolReadStatus::Ok, std::move(result));
    }

    ClearPhaseDeadline();
    co_return ProxyReadResult(ProxyProtocolReadStatus::TooLarge, std::move(result));
}

void TcpStream::PrependReadData(std::span<const uint8_t> data) {
    if (data.empty()) return;
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        throw IoSystemError(io_error::operation_aborted, "TCP read closed");
    }
    buf::MultiBuffer prefix;
    if (!buf::AppendSpanToMultiBuffer(data, prefix)) {
        throw std::bad_alloc();
    }
    // MoveTo reserves before transferring; allocation failure preserves old data.
    impl_->pending_data.MoveTo(prefix);
    impl_->pending_data = std::move(prefix);
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
    return impl_->executor;
}

net::awaitable<IoErrorCode> TcpStream::WaitReadable(net::cancellation_slot cancellation) {
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        co_return io_error::eof;
    }
    if (impl_->pending_data.byte_size() != 0) {
        co_return IoErrorCode{};
    }

    WriteCompletion completion(Cancellation());
    OperationTimeoutScope<decltype(impl_->timeouts), true> timeout_scope{impl_->timeouts, true};
    if (!cancellation.is_connected())
        cancellation = (co_await net::this_coro::cancellation_state).slot();
    if (completion.Cancelled() ||
        (co_await net::this_coro::cancellation_state).cancelled() != net::cancellation_type::none) {
        co_return IoErrorCode(io_error::operation_aborted);
    }
    const auto ec = co_await impl_->Wait(tcp::socket::wait_read, cancellation);
    if (completion.Cancelled() && !ec) {
        co_return IoErrorCode(io_error::operation_aborted);
    }
    co_return ec;
}

void TcpStream::PrepareTlsIo() {
    // Asio's synchronous read_some otherwise waits internally even if an earlier
    // asynchronous operation has made the native descriptor nonblocking.
    impl_->socket.non_blocking(true);
}

bool TcpStream::CanRead() const noexcept {
    return impl_->socket.is_open() && !impl_->HasFlag(kReadShutdown);
}

bool TcpStream::CanWrite() const noexcept {
    return impl_->socket.is_open() && !impl_->HasFlag(kWriteShutdown);
}

std::size_t TcpStream::ReadAvailable(
    net::mutable_buffer target, IoErrorCode& error) noexcept {
    error.clear();
    if (!CanRead()) {
        error = io_error::eof;
        return 0;
    }
    std::size_t n = ConsumePendingData(target);
    if (n == 0) n = impl_->socket.read_some(target, error);
    if (n != 0) TouchActivity();
    return n;
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
net::awaitable<DialResult> TcpStream::ConnectSocket(
    tcp::socket socket,
    const tcp::endpoint& endpoint,
    std::chrono::seconds timeout) {
    auto stream = std::make_unique<TcpStream>(std::move(socket));
    ConnectTimeout deadline(*stream);
    auto& scheduler = TimeoutScheduler::ForIoContext(SocketIoContext(stream->impl_->socket));
    if (!scheduler.ScheduleAfter(
            std::chrono::duration_cast<std::chrono::milliseconds>(timeout), deadline))
        co_return DialResult::Fail(ErrorCode::CANCELLED, "connection cancelled");

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
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    if (connect_ec)
        co_return DialResult::Fail(MapAsioError(connect_ec), connect_ec.message(), connect_ec.value());
    co_return DialResult::Success(std::move(stream));
}

net::awaitable<DialResult> TcpStream::Connect(
    net::io_context& io_context,
    const tcp::endpoint& endpoint,
    std::chrono::seconds timeout) {

    if (timeout.count() <= 0) {
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }
    auto& reactor = transport::internet::detail::CurrentSocketReactor(io_context);
    IoErrorCode ec;
    tcp::socket socket(reactor);
    socket.open(endpoint.protocol(), ec);
    if (ec)
        co_return DialResult::Fail(ErrorCode::SOCKET_CREATE_FAILED, ec.message(), ec.value());
    co_return co_await ConnectSocket(std::move(socket), endpoint, timeout);
}

net::awaitable<DialResult> TcpStream::ConnectWithBind(
    net::io_context& io_context,
    const net::ip::address& local_addr,
    const tcp::endpoint& remote_endpoint,
    std::chrono::seconds timeout) {

    if (timeout.count() <= 0) {
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }

    tcp::socket socket(transport::internet::detail::CurrentSocketReactor(io_context));
    IoErrorCode ec;
    socket.open(remote_endpoint.protocol(), ec);
    if (ec) {
        co_return DialResult::Fail(
            ErrorCode::SOCKET_CREATE_FAILED, ec.message(), ec.value());
    }

    socket.bind(tcp::endpoint(local_addr, 0), ec);
    if (ec) {
        co_return DialResult::Fail(
            ErrorCode::SOCKET_BIND_FAILED, ec.message(), ec.value());
    }

    co_return co_await ConnectSocket(std::move(socket), remote_endpoint, timeout);
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

