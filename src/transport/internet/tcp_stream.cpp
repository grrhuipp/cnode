#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"

#include <asio/read.hpp>
#include <asio/write.hpp>
#include <asio/connect.hpp>
#include <asio/buffer.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#else
#include <sys/socket.h>
#include <netinet/tcp.h>
#endif

namespace acpp {

namespace {
constexpr int kSocketBufferSizeLow  = 8 * 1024;
constexpr int kSocketBufferSizeMid  = 16 * 1024;
constexpr int kSocketBufferSizeHigh = 32 * 1024;
constexpr uint32_t kMaxReadAllocBuffers = 1;
constexpr uint32_t kReadGrowThreshold = buf::Buffer::kSize / 2;
constexpr uint8_t kReadGrowStreakRequired = 2;
constexpr size_t kProxyHeaderMaxBytes = 2048;
constexpr size_t kProxyProbeBytes = 256;
thread_local uint32_t g_active_tcp_streams = 0;
using std::chrono::steady_clock;

struct PendingOperationState {
    bool timed_out = false;
    bool active = true;

    bool TakeActive() noexcept {
        if (!active) {
            return false;
        }
        active = false;
        return true;
    }
};

int SelectSocketBufferSize() noexcept {
    const uint32_t active = g_active_tcp_streams;
    if (active >= 40000) return kSocketBufferSizeLow;
    if (active >= 12000) return kSocketBufferSizeMid;
    return kSocketBufferSizeHigh;
}

net::io_context& SocketIoContext(tcp::socket& socket) {
    return static_cast<net::io_context&>(socket.get_executor().context());
}

uint32_t SecondsToU32(std::chrono::seconds timeout) noexcept {
    if (timeout.count() <= 0) {
        return 0;
    }
    const auto value = static_cast<uint64_t>(timeout.count());
    return static_cast<uint32_t>(
        std::min<uint64_t>(value, std::numeric_limits<uint32_t>::max()));
}

std::chrono::seconds SecondsFromU32(uint32_t timeout_sec) noexcept {
    return std::chrono::seconds(timeout_sec);
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

enum class StreamLabelKind : uint8_t {
    Unknown,
    Inbound,
    Outbound,
};

enum Flag : uint8_t {
    kAbortiveClose          = 1u << 0,
    kReadShutdown           = 1u << 1,
    kWriteShutdown          = 1u << 2,
    kCountedActive          = 1u << 3,
    kIdleTimedOut           = 1u << 4,
    kReadTimedOut           = 1u << 5,
    kWriteTimedOut          = 1u << 6,
    kPhaseDeadlineTimedOut  = 1u << 7,
};

struct TcpStream::Impl {
    explicit Impl(tcp::socket socket)
        : socket(std::move(socket))
        , timeout_scheduler(&TimeoutScheduler::ForIoContext(SocketIoContext(this->socket))) {}

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

    [[nodiscard]] bool ConsumeFlag(Flag flag) noexcept {
        const bool value = HasFlag(flag);
        SetFlag(flag, false);
        return value;
    }

    tcp::socket socket;
    TimeoutScheduler* timeout_scheduler = nullptr;
    buf::MultiBuffer pending_data;
    std::chrono::steady_clock::time_point last_io_time;
    TimeoutToken idle_timer_token;
    TimeoutToken read_deadline_token;
    TimeoutToken write_deadline_token;
    TimeoutToken phase_deadline_token;
    uint32_t read_alloc_count = 1;
    uint8_t read_grow_streak = 0;
    StreamLabelKind stream_label = StreamLabelKind::Unknown;
    uint8_t flags = 0;
    uint32_t idle_timeout_sec = 0;
    uint32_t read_timeout_sec = 0;
    uint32_t write_timeout_sec = 0;
    uint32_t phase_deadline_generation = 0;
};

// ============================================================================
// TcpStream 实现
// ============================================================================

void* TcpStream::operator new(std::size_t size) {
    if (void* p = memory::AllocateRaw(size, alignof(TcpStream))) {
        memory::OnAsyncStreamNew();
        return p;
    }
    throw std::bad_alloc();
}

void TcpStream::operator delete(void* p) noexcept {
    memory::OnAsyncStreamFree();
    memory::DeallocateRaw(p, sizeof(TcpStream), alignof(TcpStream));
}

void TcpStream::operator delete(void* p, std::size_t size) noexcept {
    memory::OnAsyncStreamFree();
    memory::DeallocateRaw(p, size, alignof(TcpStream));
}

TcpStream::TcpStream(tcp::socket socket)
    : impl_(std::make_unique<Impl>(std::move(socket))) {
    if (impl_->socket.is_open()) {
        impl_->SetFlag(kCountedActive);
        ++g_active_tcp_streams;
        memory::OnTcpStreamNew();
        SetupConnectedSocket(impl_->socket);
    }
}

TcpStream::TcpStream(TcpStream&& other) noexcept
    : impl_(std::make_unique<Impl>(std::move(other.impl_->socket))) {
    impl_->pending_data = std::move(other.impl_->pending_data);
    impl_->last_io_time = other.impl_->last_io_time;
    impl_->idle_timer_token = other.impl_->idle_timer_token;
    impl_->read_deadline_token = other.impl_->read_deadline_token;
    impl_->write_deadline_token = other.impl_->write_deadline_token;
    impl_->phase_deadline_token = other.impl_->phase_deadline_token;
    impl_->read_alloc_count = other.impl_->read_alloc_count;
    impl_->read_grow_streak = other.impl_->read_grow_streak;
    impl_->stream_label = other.impl_->stream_label;
    impl_->flags = other.impl_->flags;
    impl_->idle_timeout_sec = other.impl_->idle_timeout_sec;
    impl_->read_timeout_sec = other.impl_->read_timeout_sec;
    impl_->write_timeout_sec = other.impl_->write_timeout_sec;
    impl_->phase_deadline_generation = other.impl_->phase_deadline_generation;
    other.CancelIdleTimer();
    other.CancelReadDeadline();
    other.CancelWriteDeadline();
    other.CancelPhaseDeadline();
    impl_->idle_timer_token.Reset();
    impl_->read_deadline_token.Reset();
    impl_->write_deadline_token.Reset();
    impl_->phase_deadline_token.Reset();
    other.impl_->idle_timeout_sec = 0;
    other.impl_->read_timeout_sec = 0;
    other.impl_->write_timeout_sec = 0;
    other.impl_->flags = static_cast<uint8_t>(kReadShutdown | kWriteShutdown);
    other.impl_->stream_label = StreamLabelKind::Unknown;
    other.impl_->read_alloc_count = 1;
    other.impl_->read_grow_streak = 0;
}

TcpStream& TcpStream::operator=(TcpStream&& other) noexcept {
    if (this != &other) {
        CancelIdleTimer();
        CancelReadDeadline();
        CancelWriteDeadline();
        CancelPhaseDeadline();
        Close();
        impl_->socket = std::move(other.impl_->socket);
        ReleasePendingData();
        impl_->timeout_scheduler = &TimeoutScheduler::ForIoContext(SocketIoContext(impl_->socket));
        impl_->pending_data = std::move(other.impl_->pending_data);
        impl_->last_io_time = other.impl_->last_io_time;
        impl_->idle_timer_token = other.impl_->idle_timer_token;
        impl_->read_deadline_token = other.impl_->read_deadline_token;
        impl_->write_deadline_token = other.impl_->write_deadline_token;
        impl_->phase_deadline_token = other.impl_->phase_deadline_token;
        impl_->read_alloc_count = other.impl_->read_alloc_count;
        impl_->read_grow_streak = other.impl_->read_grow_streak;
        impl_->stream_label = other.impl_->stream_label;
        impl_->flags = other.impl_->flags;
        impl_->idle_timeout_sec = other.impl_->idle_timeout_sec;
        impl_->read_timeout_sec = other.impl_->read_timeout_sec;
        impl_->write_timeout_sec = other.impl_->write_timeout_sec;
        impl_->phase_deadline_generation = other.impl_->phase_deadline_generation;
        other.CancelIdleTimer();
        other.CancelReadDeadline();
        other.CancelWriteDeadline();
        other.CancelPhaseDeadline();
        impl_->idle_timer_token.Reset();
        impl_->read_deadline_token.Reset();
        impl_->write_deadline_token.Reset();
        impl_->phase_deadline_token.Reset();
        other.impl_->idle_timeout_sec = 0;
        other.impl_->read_timeout_sec = 0;
        other.impl_->write_timeout_sec = 0;
        other.impl_->flags = static_cast<uint8_t>(kReadShutdown | kWriteShutdown);
        other.impl_->stream_label = StreamLabelKind::Unknown;
        other.impl_->read_alloc_count = 1;
        other.impl_->read_grow_streak = 0;
    }
    return *this;
}

TcpStream::~TcpStream() {
    // Close() 内部已包含所有 Cancel 调用，不重复
    Close();
    ReleasePendingData();
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

    ArmReadDeadline();
    auto [ec, n] = co_await impl_->socket.async_read_some(buf,
        net::as_tuple(net::use_awaitable));
    CancelReadDeadline();

    if (ec) {
        if (ec == io_error::eof) {
            co_return 0;  // 正常关闭
        }
        if (ec == io_error::connection_reset ||
            ec == io_error::broken_pipe) {
            LOG_ACCESS_DEBUG("AsyncRead: {} (fd={})", ec.message(), NativeHandle());
            co_return 0;
        }
        if (ec == io_error::operation_aborted) {
            co_return 0;  // 被取消（可能是 idle timeout）
        }
        throw IoSystemError(ec);
    }

    TouchActivity();
    co_return n;
}

// ============================================================================
// TcpStream::ReadMultiBuffer
//
// 优化路径：async_read_some 直接填充 pool Buffer，省去 relay buffer 中转。
// pending_data 优先返回（保持与 AsyncRead 相同语义）。
//
// 自适应散读（仿 Xray ReadVReader allocStrategy）：
//   - 低流量 / 启动：单 Buffer 快速路径，零额外堆分配
//   - RSS 优先：不升到 scatter-read，限制高并发时挂起读常驻 payload
//   - 未读满则收缩到实际使用数，避免浪费
// ============================================================================
net::awaitable<buf::MultiBuffer> TcpStream::ReadMultiBuffer() {
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) co_return buf::MultiBuffer{};

    // 先消费 pending_data；MultiBuffer move 即转移剩余 Buffer 所有权。
    if (!impl_->pending_data.empty()) {
        buf::MultiBuffer pending = std::move(impl_->pending_data);
        TouchActivity();
        co_return pending;
    }

    // 先等 fd 可读，再申请 relay Buffer。这样大量空闲连接挂读时不常驻 8KB
    // payload 块；Buffer 只覆盖真正的 read_some 生命周期。
    ArmReadDeadline();
    auto [wait_ec] = co_await impl_->socket.async_wait(
        tcp::socket::wait_read,
        net::as_tuple(net::use_awaitable));

    if (wait_ec) {
        CancelReadDeadline();
        if (wait_ec == io_error::operation_aborted) {
            co_return buf::MultiBuffer{};
        }
        if (wait_ec == io_error::connection_reset ||
            wait_ec == io_error::broken_pipe) {
            LOG_ACCESS_DEBUG("ReadMultiBuffer(wait): {} (fd={})", wait_ec.message(), NativeHandle());
            co_return buf::MultiBuffer{};
        }
        throw IoSystemError(wait_ec);
    }

    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        CancelReadDeadline();
        co_return buf::MultiBuffer{};
    }

    // ── 快速路径：单 Buffer（低流量 / 启动阶段，零额外分配）─────────────
    if (impl_->read_alloc_count == 1) {
        buf::BufferGuard buf{buf::Buffer::New()};
        if (!buf) {
            CancelReadDeadline();
            co_return buf::MultiBuffer{};
        }
        auto [ec, n] = co_await impl_->socket.async_read_some(
            net::mutable_buffer(buf->Tail().data(), buf->Available()),
            net::as_tuple(net::use_awaitable));
        CancelReadDeadline();

        if (ec || n == 0) {
            if (!ec || ec == io_error::eof ||
                ec == io_error::operation_aborted)
                co_return buf::MultiBuffer{};
            if (ec == io_error::connection_reset ||
                ec == io_error::broken_pipe) {
                LOG_ACCESS_DEBUG("ReadMultiBuffer: {} (fd={})", ec.message(), NativeHandle());
                co_return buf::MultiBuffer{};
            }
            throw IoSystemError(ec);
        }

        buf->Produce(static_cast<uint32_t>(n));
        TouchActivity();
        if constexpr (kMaxReadAllocBuffers > 1) {
            // 读满或连续"大包"读命中时，提前切换到 scatter-read。
            if (n == buf::Buffer::kSize || n >= kReadGrowThreshold) {
                if (impl_->read_grow_streak < 0xff) {
                    ++impl_->read_grow_streak;
                }
                if (impl_->read_grow_streak >= kReadGrowStreakRequired) {
                    impl_->read_alloc_count = std::min(2u, kMaxReadAllocBuffers);
                    impl_->read_grow_streak = 0;
                }
            } else {
                impl_->read_grow_streak = 0;
            }
        } else if (impl_->read_grow_streak != 0) {
            impl_->read_grow_streak = 0;
        }
        co_return buf::MultiBuffer{buf.release()};
    }

    // ── 散读路径：n_alloc 个 Buffer，单次 readv / WSARecv ───────────────
    const uint32_t n_alloc = impl_->read_alloc_count;

    // 在协程帧上分配（co_await 期间保持有效），最多 kMaxReadAllocBuffers 个。
    std::array<buf::BufferGuard, kMaxReadAllocBuffers> buffers{};
    for (uint32_t i = 0; i < n_alloc; ++i) {
        buffers[i] = buf::BufferGuard{buf::Buffer::New()};
        if (!buffers[i]) {
            CancelReadDeadline();
            throw std::bad_alloc();
        }
    }

    // 构造 scatter iovec（栈分配，n_alloc <= kMaxReadAllocBuffers）
    std::array<net::mutable_buffer, kMaxReadAllocBuffers> iov_arr;
    for (uint32_t i = 0; i < n_alloc; ++i)
        iov_arr[i] = net::mutable_buffer(buffers[i]->Tail().data(), buf::Buffer::kSize);
    auto iov = std::span(iov_arr.data(), n_alloc);

    auto [ec, n] = co_await impl_->socket.async_read_some(
        iov, net::as_tuple(net::use_awaitable));
    CancelReadDeadline();

    if (ec || n == 0) {
        if (!ec || ec == io_error::eof ||
            ec == io_error::operation_aborted)
            co_return buf::MultiBuffer{};
        if (ec == io_error::connection_reset ||
            ec == io_error::broken_pipe) {
            LOG_ACCESS_DEBUG("ReadMultiBuffer(scatter): {} (fd={})", ec.message(), NativeHandle());
            co_return buf::MultiBuffer{};
        }
        throw IoSystemError(ec);
    }

    // scatter-read 按顺序填充各 Buffer，将 n 字节分配给实际用到的 Buffer
    buf::MultiBuffer result;
    result.reserve(n_alloc);
    size_t remaining = n;
    uint32_t used = 0;
    for (uint32_t i = 0; i < n_alloc; ++i) {
        if (remaining == 0) {
            continue;
        }
        uint32_t fill = static_cast<uint32_t>(
            std::min<size_t>(remaining, buf::Buffer::kSize));
        buffers[i]->Produce(fill);
        remaining -= fill;
        result.push_back(buffers[i].get());
        (void)buffers[i].release();
        ++used;
    }

    TouchActivity();

    // 自适应调整：全部读满 → 加倍（上限 kMaxReadAllocBuffers），否则收缩到实际使用数
    if (used >= n_alloc) {
        impl_->read_alloc_count = std::min(n_alloc * 2u, kMaxReadAllocBuffers);
    } else {
        impl_->read_alloc_count = std::max(used, 1u);
    }
    impl_->read_grow_streak = 0;

    co_return result;
}

// ============================================================================
// TcpStream::WriteMultiBuffer
//
// 优化路径：将多个 Buffer 合并为 net::const_buffer_sequence，
// 通过 net::async_write 发出单次 scatter-write（WSASend / writev），
// 减少系统调用次数。
// ============================================================================
net::awaitable<void> TcpStream::WriteMultiBuffer(buf::MultiBuffer mb) {

    if (!impl_->socket.is_open() || impl_->HasFlag(kWriteShutdown) || mb.empty()) co_return;

    // 构造 scatter-write buffer 序列（栈分配，常规路径 <= 8 个 buffer）
    constexpr size_t kStackBufs = 8;
    std::array<net::const_buffer, kStackBufs> stack_bufs;
    memory::ThreadLocalVector<net::const_buffer> spill_bufs;
    size_t buf_count = 0;

    if (mb.size() <= kStackBufs) {
        for (auto* b : mb) {
            auto bytes = b->Bytes();
            if (!bytes.empty()) {
                stack_bufs[buf_count++] = net::const_buffer(bytes.data(), bytes.size());
            }
        }
    } else {
        spill_bufs.reserve(mb.size());
        for (auto* b : mb) {
            auto bytes = b->Bytes();
            if (!bytes.empty()) {
                spill_bufs.emplace_back(bytes.data(), bytes.size());
            }
        }
        buf_count = spill_bufs.size();
    }

    if (buf_count == 0) co_return;

    auto bufs_span = (mb.size() > kStackBufs)
        ? std::span<net::const_buffer>(spill_bufs)
        : std::span<net::const_buffer>(stack_bufs.data(), buf_count);

    ArmWriteDeadline();
    auto [ec, n] = co_await net::async_write(
        impl_->socket, bufs_span, net::as_tuple(net::use_awaitable));
    CancelWriteDeadline();

    if (ec) {
        throw IoSystemError(ec);
    }
    if (!ec) TouchActivity();
}

net::awaitable<std::size_t> TcpStream::AsyncWrite(net::const_buffer buf) {
    if (!impl_->socket.is_open() || impl_->HasFlag(kWriteShutdown)) {
        co_return 0;
    }

    ArmWriteDeadline();
    auto [ec, n] = co_await net::async_write(impl_->socket, buf,
        net::as_tuple(net::use_awaitable));
    CancelWriteDeadline();

    if (ec) {
        throw IoSystemError(ec);
    }

    TouchActivity();
    co_return n;
}

void TcpStream::ShutdownRead() {
    if (!impl_->socket.is_open() || impl_->HasFlag(kReadShutdown)) {
        return;
    }

    IoErrorCode ec;
    impl_->socket.shutdown(tcp::socket::shutdown_receive, ec);
    impl_->SetFlag(kReadShutdown);
    // 忽略错误，可能对端已关闭
}

void TcpStream::ShutdownWrite() {
    if (!impl_->socket.is_open() || impl_->HasFlag(kWriteShutdown)) {
        return;
    }

    IoErrorCode ec;
    impl_->socket.shutdown(tcp::socket::shutdown_send, ec);
    impl_->SetFlag(kWriteShutdown);
    // 忽略错误
}

void TcpStream::Close() {
    CancelIdleTimer();
    CancelReadDeadline();
    CancelWriteDeadline();
    CancelPhaseDeadline();
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
    ReleaseActiveCounter();
    impl_->SetFlag(kReadShutdown);
    impl_->SetFlag(kWriteShutdown);
}

void TcpStream::Cancel() noexcept {
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

    const auto flags = peek
        ? net::socket_base::message_peek
        : net::socket_base::message_flags{0};
    auto [ec, n] = co_await impl_->socket.async_receive(
        buffer, flags, net::as_tuple(net::use_awaitable));
    if (!ec && n > 0 && !peek) {
        TouchActivity();
    }
    co_return std::make_pair(ec, n);
}

net::awaitable<ProxyProtocolReadResult> TcpStream::ReadProxyProtocolHeader(
    std::chrono::seconds timeout) {
    SetIdleTimeout(timeout);
    auto deadline = StartPhaseDeadline(timeout);

    auto timed_out = [&]() noexcept {
        return deadline.Expired() ||
               ConsumePhaseDeadline() ||
               ConsumeIdleTimeout();
    };

    std::array<uint8_t, kProxyProbeBytes> probe;
    auto [peek_ec, probe_len] = co_await AsyncReceiveSome(
        net::buffer(probe), true);

    if (peek_ec || probe_len == 0) {
        auto out = timed_out()
            ? ProxyReadResult(ProxyProtocolReadStatus::TimedOut)
            : ProxyReadResult(ProxyProtocolReadStatus::Ok);
        ClearPhaseDeadline();
        co_return out;
    }

    auto result = ProxyProtocolParser::Parse(probe.data(), probe_len);

    if (!result.incomplete()) {
        if (result.status == ProxyProtocolParseStatus::Invalid) {
            ClearPhaseDeadline();
            co_return ProxyReadResult(ProxyProtocolReadStatus::Invalid, std::move(result));
        }

        size_t remaining = result.consumed;
        while (remaining > 0) {
            std::array<uint8_t, kProxyProbeBytes> discard;
            const size_t want = std::min(remaining, discard.size());
            auto [read_ec, n] = co_await AsyncReceiveSome(
                net::buffer(discard.data(), want));
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
    buf.reserve(kProxyProbeBytes * 2);

    while (buf.size() < kProxyHeaderMaxBytes) {
        std::array<uint8_t, kProxyProbeBytes> chunk;
        auto [read_ec, n] = co_await AsyncReceiveSome(net::buffer(chunk));
        if (read_ec || n == 0) {
            if (timed_out()) {
                ClearPhaseDeadline();
                co_return ProxyReadResult(ProxyProtocolReadStatus::TimedOut, std::move(result));
            }
            result = ProxyProtocolParser::Parse(buf.data(), buf.size());
            if (result.incomplete()) {
                ClearPhaseDeadline();
                co_return ProxyReadResult(ProxyProtocolReadStatus::Truncated, std::move(result));
            }
        } else {
            buf.insert(buf.end(), chunk.begin(),
                       chunk.begin() + static_cast<ptrdiff_t>(n));
            result = ProxyProtocolParser::Parse(buf.data(), buf.size());
            if (result.incomplete()) {
                continue;
            }
        }

        if (result.status == ProxyProtocolParseStatus::Invalid) {
            ClearPhaseDeadline();
            co_return ProxyReadResult(ProxyProtocolReadStatus::Invalid, std::move(result));
        }
        if (buf.size() >= kProxyHeaderMaxBytes) {
            ClearPhaseDeadline();
            co_return ProxyReadResult(ProxyProtocolReadStatus::TooLarge, std::move(result));
        }
        if (result.consumed < buf.size()) {
            SetPendingData(std::span<const uint8_t>(buf).subspan(result.consumed));
        }

        ClearPhaseDeadline();
        co_return ProxyReadResult(ProxyProtocolReadStatus::Ok, std::move(result));
    }

    ClearPhaseDeadline();
    co_return ProxyReadResult(ProxyProtocolReadStatus::TooLarge, std::move(result));
}

void TcpStream::SetPendingData(std::span<const uint8_t> data) {
    ReleasePendingData();
    size_t offset = 0;
    while (offset < data.size()) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            throw std::bad_alloc();
        }
        const size_t n = std::min(data.size() - offset,
                                  static_cast<size_t>(buffer->Available()));
        std::memcpy(buffer->Tail().data(), data.data() + offset, n);
        buffer->Produce(static_cast<uint32_t>(n));
        impl_->pending_data.push_back(buffer.release());
        offset += n;
    }
}

void TcpStream::SetStreamLabel(std::string_view label) noexcept {
    if (label == "in") {
        impl_->stream_label = StreamLabelKind::Inbound;
    } else if (label == "out") {
        impl_->stream_label = StreamLabelKind::Outbound;
    } else {
        impl_->stream_label = StreamLabelKind::Unknown;
    }
}

std::string_view TcpStream::StreamLabel() const noexcept {
    switch (impl_->stream_label) {
        case StreamLabelKind::Inbound:
            return "in";
        case StreamLabelKind::Outbound:
            return "out";
        case StreamLabelKind::Unknown:
        default:
            return {};
    }
}

void TcpStream::SetAbortiveClose(bool enable) noexcept {
    impl_->SetFlag(kAbortiveClose, enable);
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

net::awaitable<DialResult> TcpStream::Connect(
    net::io_context& io_context,
    const tcp::endpoint& endpoint,
    std::chrono::seconds timeout) {

    if (timeout.count() <= 0) {
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }

    tcp::socket socket(io_context);
    PendingOperationState op_state;

    auto& scheduler = TimeoutScheduler::ForIoContext(io_context);
    TimeoutToken token = scheduler.ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
        [&socket, &op_state]() {
            if (op_state.TakeActive()) {
                op_state.timed_out = true;
                IoErrorCode close_ec;
                socket.close(close_ec);
            }
        });

    IoErrorCode connect_ec;

    try {
        co_await socket.async_connect(endpoint, net::use_awaitable);
    } catch (const IoSystemError& e) {
        connect_ec = e.code();
    }

    if (op_state.TakeActive()) {
        scheduler.Cancel(token);
    } else {
        token.Reset();
    }

    if (op_state.timed_out) {
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }

    if (connect_ec) {
        auto err = MapAsioError(connect_ec);
        co_return DialResult::Fail(err, connect_ec.message());
    }
    co_return DialResult::Success(
        std::make_unique<TcpStream>(std::move(socket)));
}

net::awaitable<DialResult> TcpStream::ConnectWithBind(
    net::io_context& io_context,
    const net::ip::address& local_addr,
    const tcp::endpoint& remote_endpoint,
    std::chrono::seconds timeout) {

    if (timeout.count() <= 0) {
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }

    tcp::socket socket(io_context);
    PendingOperationState op_state;

    // 打开 socket
    IoErrorCode ec;
    socket.open(remote_endpoint.protocol(), ec);
    if (ec) {
        co_return DialResult::Fail(ErrorCode::SOCKET_CREATE_FAILED, ec.message());
    }

    // 绑定本地地址
    tcp::endpoint local_endpoint(local_addr, 0);  // 端口为 0，由系统分配
    socket.bind(local_endpoint, ec);
    if (ec) {
        co_return DialResult::Fail(ErrorCode::SOCKET_BIND_FAILED, ec.message());
    }

    auto& scheduler = TimeoutScheduler::ForIoContext(io_context);
    TimeoutToken token = scheduler.ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
        [&socket, &op_state]() {
            if (op_state.TakeActive()) {
                op_state.timed_out = true;
                IoErrorCode close_ec;
                socket.close(close_ec);
            }
        });

    IoErrorCode connect_ec;

    try {
        co_await socket.async_connect(remote_endpoint, net::use_awaitable);
    } catch (const IoSystemError& e) {
        connect_ec = e.code();
    }

    if (op_state.TakeActive()) {
        scheduler.Cancel(token);
    } else {
        token.Reset();
    }

    if (op_state.timed_out) {
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }

    if (connect_ec) {
        auto err = MapAsioError(connect_ec);
        co_return DialResult::Fail(err, connect_ec.message());
    }
    co_return DialResult::Success(
        std::make_unique<TcpStream>(std::move(socket)));
}

// ============================================================================
// Idle Timeout
// ============================================================================

void TcpStream::SetIdleTimeout(std::chrono::seconds timeout) {
    impl_->idle_timeout_sec = SecondsToU32(timeout);
    if (impl_->idle_timeout_sec > 0) {
        impl_->last_io_time = steady_clock::now();
        impl_->SetFlag(kIdleTimedOut, false);
        ScheduleIdleCheck();
    } else {
        impl_->SetFlag(kIdleTimedOut, false);
        CancelIdleTimer();
    }
}

bool TcpStream::ConsumeIdleTimeout() noexcept {
    return impl_->ConsumeFlag(kIdleTimedOut);
}

void TcpStream::SetReadTimeout(std::chrono::seconds timeout) {
    impl_->read_timeout_sec = SecondsToU32(timeout);
    if (impl_->read_timeout_sec == 0) {
        impl_->SetFlag(kReadTimedOut, false);
        CancelReadDeadline();
    }
}

void TcpStream::SetWriteTimeout(std::chrono::seconds timeout) {
    impl_->write_timeout_sec = SecondsToU32(timeout);
    if (impl_->write_timeout_sec == 0) {
        impl_->SetFlag(kWriteTimedOut, false);
        CancelWriteDeadline();
    }
}

bool TcpStream::ConsumeReadTimeout() noexcept {
    return impl_->ConsumeFlag(kReadTimedOut);
}

bool TcpStream::ConsumeWriteTimeout() noexcept {
    return impl_->ConsumeFlag(kWriteTimedOut);
}

PhaseDeadlineHandle TcpStream::StartPhaseDeadline(std::chrono::seconds timeout) {
    ClearPhaseDeadline();
    if (timeout.count() <= 0 || !impl_->socket.is_open() || impl_->timeout_scheduler == nullptr) {
        return {};
    }

    impl_->SetFlag(kPhaseDeadlineTimedOut, false);
    const uint32_t generation = impl_->phase_deadline_generation;

    tcp::socket* sock = &impl_->socket;
    uint8_t* flags = &impl_->flags;
    uint32_t* generation_state = &impl_->phase_deadline_generation;

    impl_->phase_deadline_token = impl_->timeout_scheduler->ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
        [sock, flags, generation_state, generation]() {
            if (*generation_state != generation) {
                return;
            }
            *flags |= static_cast<uint8_t>(kPhaseDeadlineTimedOut);
            IoErrorCode cancel_ec;
            sock->cancel(cancel_ec);
    });

    return PhaseDeadlineHandle{
        &impl_->flags,
        static_cast<uint8_t>(kPhaseDeadlineTimedOut),
        generation_state,
        generation};
}

void TcpStream::ClearPhaseDeadline() {
    impl_->SetFlag(kPhaseDeadlineTimedOut, false);
    ++impl_->phase_deadline_generation;
    CancelPhaseDeadline();
}

bool TcpStream::ConsumePhaseDeadline() noexcept {
    return impl_->ConsumeFlag(kPhaseDeadlineTimedOut);
}

size_t TcpStream::ConsumePendingData(net::mutable_buffer target) noexcept {
    auto* out = static_cast<uint8_t*>(target.data());
    size_t remaining = target.size();
    size_t copied = 0;

    while (remaining > 0 && !impl_->pending_data.empty()) {
        buf::Buffer* buffer = *impl_->pending_data.begin();
        if (!buffer || buffer->IsEmpty()) {
            buf::Buffer::Free(impl_->pending_data.pop_front());
            continue;
        }

        const auto bytes = buffer->Bytes();
        const size_t n = std::min(remaining, bytes.size());
        std::memcpy(out + copied, bytes.data(), n);
        buffer->Advance(static_cast<uint32_t>(n));
        copied += n;
        remaining -= n;

        if (buffer->IsEmpty()) {
            buf::Buffer::Free(impl_->pending_data.pop_front());
        }
    }

    return copied;
}

void TcpStream::ReleasePendingData() noexcept {
    impl_->pending_data.clear();
}

// 每次成功 I/O 后调用——仅写一个时间戳，零 epoll 操作
void TcpStream::TouchActivity() {
    if (impl_->idle_timeout_sec == 0) return;
    impl_->last_io_time = steady_clock::now();
    impl_->SetFlag(kIdleTimedOut, false);
}

// 启动/续调惰性 idle 检查。定时器到期后检查 impl_->last_io_time，
// 若真超时则 cancel socket，否则按剩余时间重新调度。
// 安全性：通过 token 从共享调度器撤销事件；析构路径先 cancel token 再释放对象。
void TcpStream::ScheduleIdleCheck() {
    if (impl_->idle_timeout_sec == 0 || !impl_->socket.is_open() || impl_->timeout_scheduler == nullptr) return;

    CancelIdleTimer();

    // 计算距离预期超时的剩余时间
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        steady_clock::now() - impl_->last_io_time);
    const auto timeout = SecondsFromU32(impl_->idle_timeout_sec);
    const auto timeout_ms = std::chrono::duration_cast<std::chrono::milliseconds>(timeout);
    auto remaining = timeout_ms - elapsed;
    if (remaining <= std::chrono::milliseconds::zero()) {
        remaining = std::chrono::milliseconds(1);
    }

    // 捕获 this——timer 是成员，析构前自动 cancel，安全
    TcpStream* self = this;
    impl_->idle_timer_token = impl_->timeout_scheduler->ScheduleAfter(remaining, [self]() {
        if (!self->impl_->socket.is_open()) return;
        auto elapsed = steady_clock::now() - self->impl_->last_io_time;
        const auto idle_timeout = SecondsFromU32(self->impl_->idle_timeout_sec);
        if (elapsed >= idle_timeout) {
            self->impl_->SetFlag(kIdleTimedOut);
            // 记录触发 idle timeout 的连接端点，辅助排查断连
            if (Log::ShouldLog(LogLevel::DEBUG)) {
                IoErrorCode ep_ec;
                auto remote = self->impl_->socket.remote_endpoint(ep_ec);
                auto idle_sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
                const std::string_view label = self->StreamLabel();
                if (!ep_ec) {
                    LOG_ACCESS_DEBUG("idle timeout fired: [{}] remote={}:{} idle={}s limit={}s",
                                    label.empty() ? "?" : label,
                                    remote.address().to_string(), remote.port(),
                                    idle_sec, self->impl_->idle_timeout_sec);
                } else {
                    LOG_ACCESS_DEBUG("idle timeout fired: [{}] idle={}s limit={}s",
                                    label.empty() ? "?" : label,
                                    idle_sec, self->impl_->idle_timeout_sec);
                }
            }
            IoErrorCode cancel_ec;
            self->impl_->socket.cancel(cancel_ec);
        } else {
            self->ScheduleIdleCheck();
        }
    });
}

void TcpStream::CancelIdleTimer() noexcept {
    if (impl_->timeout_scheduler) {
        impl_->timeout_scheduler->Cancel(impl_->idle_timer_token);
    } else {
        impl_->idle_timer_token.Reset();
    }
}

void TcpStream::ArmReadDeadline() {
    if (impl_->read_timeout_sec == 0 || !impl_->socket.is_open() || impl_->timeout_scheduler == nullptr) return;

    CancelReadDeadline();
    impl_->SetFlag(kReadTimedOut, false);
    tcp::socket* sock = &impl_->socket;
    uint8_t* flags = &impl_->flags;
    impl_->read_deadline_token = impl_->timeout_scheduler->ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            SecondsFromU32(impl_->read_timeout_sec)),
        [sock, flags]() {
            *flags |= static_cast<uint8_t>(kReadTimedOut);
            IoErrorCode cancel_ec;
            sock->cancel(cancel_ec);
    });
}

void TcpStream::ArmWriteDeadline() {
    if (impl_->write_timeout_sec == 0 || !impl_->socket.is_open() || impl_->timeout_scheduler == nullptr) return;

    CancelWriteDeadline();
    impl_->SetFlag(kWriteTimedOut, false);
    tcp::socket* sock = &impl_->socket;
    uint8_t* flags = &impl_->flags;
    impl_->write_deadline_token = impl_->timeout_scheduler->ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            SecondsFromU32(impl_->write_timeout_sec)),
        [sock, flags]() {
            *flags |= static_cast<uint8_t>(kWriteTimedOut);
            IoErrorCode cancel_ec;
            sock->cancel(cancel_ec);
    });
}

void TcpStream::CancelReadDeadline() noexcept {
    if (impl_->timeout_scheduler) {
        impl_->timeout_scheduler->Cancel(impl_->read_deadline_token);
    } else {
        impl_->read_deadline_token.Reset();
    }
}

void TcpStream::CancelWriteDeadline() noexcept {
    if (impl_->timeout_scheduler) {
        impl_->timeout_scheduler->Cancel(impl_->write_deadline_token);
    } else {
        impl_->write_deadline_token.Reset();
    }
}

void TcpStream::CancelPhaseDeadline() noexcept {
    if (impl_->timeout_scheduler) {
        impl_->timeout_scheduler->Cancel(impl_->phase_deadline_token);
    } else {
        impl_->phase_deadline_token.Reset();
    }
}

void TcpStream::ReleaseActiveCounter() noexcept {
    if (!impl_->HasFlag(kCountedActive)) return;
    --g_active_tcp_streams;
    memory::OnTcpStreamFree();
    impl_->SetFlag(kCountedActive, false);
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

    // TCP_NODELAY - 禁用 Nagle 算法，降低延迟
    sock.set_option(tcp::no_delay(true), ec);

    // 启用 TCP KeepAlive
    sock.set_option(net::socket_base::keep_alive(true), ec);

#ifdef _WIN32
    // Windows: 使用 tcp_keepalive 结构设置 KeepAlive 参数
    DWORD bytes_returned = 0;
    tcp_keepalive ka{};
    ka.onoff = 1;
    ka.keepalivetime = 60000;     // 60秒空闲后开始探测 (毫秒)
    ka.keepaliveinterval = 10000; // 探测间隔 10秒 (毫秒)
    WSAIoctl(fd, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes_returned, nullptr, nullptr);

    // 高连接数场景按并发档位自适应内核收发缓冲，降低每连接常驻内存。
    int bufsize = SelectSocketBufferSize();
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&bufsize), sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&bufsize), sizeof(bufsize));
#else
    // TCP keepalive 参数按平台能力设置；Linux 与 macOS 的宏名不同。
    int keepidle = 60;
#if defined(TCP_KEEPIDLE)
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
#elif defined(TCP_KEEPALIVE)
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, &keepidle, sizeof(keepidle));
#endif

    // TCP_KEEPINTVL: 探测间隔 (10秒)
#if defined(TCP_KEEPINTVL)
    int keepintvl = 10;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
#endif

    // TCP_KEEPCNT: 探测次数 (6次)
#if defined(TCP_KEEPCNT)
    int keepcnt = 6;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
#endif

    // TCP_QUICKACK - 立即发送 ACK，降低延迟 (Linux 特有)
#if defined(TCP_QUICKACK)
    int quickack = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &quickack, sizeof(quickack));
#endif

    // 高连接数场景按并发档位自适应内核收发缓冲，降低每连接常驻内存。
    int bufsize = SelectSocketBufferSize();
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
#endif
}
}  // namespace

}  // namespace acpp
