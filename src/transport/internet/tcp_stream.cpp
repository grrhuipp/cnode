#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "tcp_read_policy.hpp"

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
constexpr uint32_t kMaxReadAllocBuffers =
    transport::internet::tcp_read_policy::kNormalReadBufferCap;
constexpr uint32_t kReadGrowThreshold = buf::Buffer::kSize / 2;
constexpr uint8_t kReadGrowStreakRequired = 1;
constexpr size_t kProxyHeaderMaxBytes = 2048;
constexpr size_t kProxyProbeBytes = 256;
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
    TimeoutToken idle_timer_token;
    TimeoutToken read_deadline_token;
    TimeoutToken write_deadline_token;
    TimeoutToken phase_deadline_token;
    std::chrono::steady_clock::time_point write_deadline_at;
    uint32_t read_alloc_count = 1;
    uint8_t read_grow_streak = 0;
    StreamLabelKind stream_label = StreamLabelKind::Unknown;
    uint8_t flags = 0;
    uint32_t idle_timeout_sec = 0;
    uint32_t read_timeout_sec = 0;
    uint32_t write_timeout_sec = 0;
    uint32_t phase_deadline_generation = 0;
    uint64_t idle_activity_epoch = 0;
    bool write_deadline_active = false;
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
        transport::internet::tcp_read_policy::RegisterActiveStream();
        memory::OnTcpStreamNew();
        SetupConnectedSocket(impl_->socket);
    }
}

TcpStream::TcpStream(TcpStream&& other) noexcept
    : impl_(std::make_unique<Impl>(std::move(other.impl_->socket))) {
    impl_->pending_data = std::move(other.impl_->pending_data);
    impl_->idle_timer_token = other.impl_->idle_timer_token;
    impl_->read_deadline_token = other.impl_->read_deadline_token;
    impl_->write_deadline_token = other.impl_->write_deadline_token;
    impl_->phase_deadline_token = other.impl_->phase_deadline_token;
    impl_->write_deadline_at = other.impl_->write_deadline_at;
    impl_->read_alloc_count = other.impl_->read_alloc_count;
    impl_->read_grow_streak = other.impl_->read_grow_streak;
    impl_->stream_label = other.impl_->stream_label;
    impl_->flags = other.impl_->flags;
    impl_->idle_timeout_sec = other.impl_->idle_timeout_sec;
    impl_->read_timeout_sec = other.impl_->read_timeout_sec;
    impl_->write_timeout_sec = other.impl_->write_timeout_sec;
    impl_->phase_deadline_generation = other.impl_->phase_deadline_generation;
    impl_->idle_activity_epoch = other.impl_->idle_activity_epoch;
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
        impl_->write_deadline_at = other.impl_->write_deadline_at;
        impl_->write_deadline_active = other.impl_->write_deadline_active;
        impl_->idle_activity_epoch = other.impl_->idle_activity_epoch;
        other.impl_->write_deadline_active = false;
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
//   - 连续大包后按 1/2/4 个 Buffer 自适应增长
//   - 当前 Worker 活跃 TCP stream 达到压力阈值时，把上限收紧到 2
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

    const uint32_t read_cap =
        transport::internet::tcp_read_policy::MaxReadBufferCount();
    impl_->read_alloc_count = std::min(impl_->read_alloc_count, read_cap);

    // ── 快速路径：单 Buffer（低流量 / 启动阶段）───────────────────────
    // 对齐 xray-core：直接挂起 read 到 8KB Buffer，避免 wait+read 的双
    // IOCP 往返。Buffer 只在一次挂起读生命周期内持有，不进入长期池。
    if (impl_->read_alloc_count == 1) {
        ArmReadDeadline();
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
        // 读满或连续"大包"读命中时，提前切换到 scatter-read。
        if (n == buf::Buffer::kSize || n >= kReadGrowThreshold) {
            if (impl_->read_grow_streak < 0xff) {
                ++impl_->read_grow_streak;
            }
            if (impl_->read_grow_streak >= kReadGrowStreakRequired) {
                impl_->read_alloc_count = 2;
                impl_->read_grow_streak = 0;
            }
        } else {
            impl_->read_grow_streak = 0;
        }
        co_return buf::MultiBuffer{buf.release()};
    }

    // ── 散读路径：已证明活跃，跳过 pre-wait，直接预分配并散读 ──────────
    // read_alloc_count>=2 表示连接连续命中大包；省去 async_wait 的额外一次
    // reactor 往返，直接 readv / WSARecv。转空闲后下方自适应会收回 alloc_count，
    // 自动退回上面的 wait-first 低流量档。
    ArmReadDeadline();
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

    // 自适应调整：全部读满时按当前 Worker 压力上限增长，否则收缩到
    // 实际使用数。压力解除后，连接会在后续满读时从 readv2 恢复到 readv4。
    if (used >= n_alloc) {
        impl_->read_alloc_count = std::min(
            n_alloc * 2u,
            transport::internet::tcp_read_policy::MaxReadBufferCount());
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

    if (!impl_->socket.is_open() || impl_->HasFlag(kWriteShutdown) || !buf::HasData(mb)) co_return;

    ConstBufferSpanBuilder<8> out;
    out.AppendMultiBuffer(mb);
    if (out.empty()) co_return;

    ArmWriteDeadline();
    auto [ec, n] = co_await net::async_write(
        impl_->socket, out.Span(), net::as_tuple(net::use_awaitable));
    DisarmWriteDeadline();

    if (ec) {
        throw IoSystemError(ec);
    }
    if (!ec) TouchActivity();
}

net::awaitable<void> TcpStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {

    if (!impl_->socket.is_open() || impl_->HasFlag(kWriteShutdown) || buffers.empty()) {
        co_return;
    }

    ConstBufferSpanBuilder<16> out;
    out.AppendBuffers(buffers);
    if (out.empty()) {
        co_return;
    }

    ArmWriteDeadline();
    auto [ec, n] = co_await net::async_write(
        impl_->socket, out.Span(), net::as_tuple(net::use_awaitable));
    DisarmWriteDeadline();
    (void)n;

    if (ec) {
        throw IoSystemError(ec);
    }
    TouchActivity();
}

net::awaitable<std::size_t> TcpStream::AsyncWrite(net::const_buffer buf) {
    if (!impl_->socket.is_open() || impl_->HasFlag(kWriteShutdown)) {
        co_return 0;
    }

    ArmWriteDeadline();
    auto [ec, n] = co_await net::async_write(impl_->socket, buf,
        net::as_tuple(net::use_awaitable));
    DisarmWriteDeadline();

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

tcp::socket::executor_type TcpStream::GetExecutor() noexcept {
    return impl_->socket.get_executor();
}

tcp::socket& TcpStream::TlsLayerSocket() noexcept {
    return impl_->socket;
}

bool TcpStream::TlsLayerCanRead() const noexcept {
    return impl_->socket.is_open() && !impl_->HasFlag(kReadShutdown);
}

bool TcpStream::TlsLayerCanWrite() const noexcept {
    return impl_->socket.is_open() && !impl_->HasFlag(kWriteShutdown);
}

size_t TcpStream::ConsumeTlsLayerPendingData(net::mutable_buffer target) noexcept {
    return ConsumePendingData(target);
}

void TcpStream::BeginTlsLayerRead() {
    ArmReadDeadline();
}

void TcpStream::EndTlsLayerRead(const IoErrorCode& ec, std::size_t n) noexcept {
    CancelReadDeadline();
    if (!ec && n > 0) {
        TouchActivity();
    }
}

void TcpStream::BeginTlsLayerWrite() {
    ArmWriteDeadline();
}

void TcpStream::EndTlsLayerWrite(const IoErrorCode& ec, std::size_t n) noexcept {
    DisarmWriteDeadline();
    if (!ec && n > 0) {
        TouchActivity();
    }
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
        ++impl_->idle_activity_epoch;
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
    auto& pending = impl_->pending_data;
    return pending.ConsumePrefixTo(
        std::span<uint8_t>(
            static_cast<uint8_t*>(target.data()),
            target.size()));
}

void TcpStream::ReleasePendingData() noexcept {
    impl_->pending_data.clear();
}

// 每次成功 I/O 后调用。idle timeout 只需要判断“期间是否发生过 I/O”，
// 用递增序号避免热路径每包读取 steady_clock。
void TcpStream::TouchActivity() {
    if (impl_->idle_timeout_sec == 0) return;
    ++impl_->idle_activity_epoch;
    impl_->SetFlag(kIdleTimedOut, false);
}

// 启动/续调惰性 idle 检查。定时器到期后比较活动序号；
// 若期间没有 I/O 则 cancel socket，否则重新调度一个完整 idle 周期。
// 安全性：通过 token 从共享调度器撤销事件；析构路径先 cancel token 再释放对象。
void TcpStream::ScheduleIdleCheck() {
    if (impl_->idle_timeout_sec == 0 || !impl_->socket.is_open() || impl_->timeout_scheduler == nullptr) return;

    CancelIdleTimer();

    const auto timeout = SecondsFromU32(impl_->idle_timeout_sec);
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(timeout);
    const auto observed_epoch = impl_->idle_activity_epoch;

    // 捕获 this——timer 是成员，析构前自动 cancel，安全
    TcpStream* self = this;
    impl_->idle_timer_token = impl_->timeout_scheduler->ScheduleAfter(remaining, [self, observed_epoch]() {
        if (!self->impl_->socket.is_open()) return;
        if (self->impl_->idle_activity_epoch == observed_epoch) {
            self->impl_->SetFlag(kIdleTimedOut);
            // 记录触发 idle timeout 的连接端点，辅助排查断连
            if (Log::ShouldLog(LogLevel::DEBUG)) {
                IoErrorCode ep_ec;
                auto remote = self->impl_->socket.remote_endpoint(ep_ec);
                const std::string_view label = self->StreamLabel();
                if (!ep_ec) {
                    LOG_ACCESS_DEBUG("idle timeout fired: [{}] remote={}:{} limit={}s",
                                    label.empty() ? "?" : label,
                                    remote.address().to_string(), remote.port(),
                                    self->impl_->idle_timeout_sec);
                } else {
                    LOG_ACCESS_DEBUG("idle timeout fired: [{}] limit={}s",
                                    label.empty() ? "?" : label,
                                    self->impl_->idle_timeout_sec);
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

    impl_->SetFlag(kWriteTimedOut, false);
    impl_->write_deadline_active = true;
    impl_->write_deadline_at = steady_clock::now() + SecondsFromU32(impl_->write_timeout_sec);
    if (!impl_->write_deadline_token.Valid()) {
        ScheduleWriteDeadlineCheck();
    }
}

void TcpStream::DisarmWriteDeadline() noexcept {
    impl_->write_deadline_active = false;
}

void TcpStream::ScheduleWriteDeadlineCheck() {
    if (impl_->write_timeout_sec == 0 || !impl_->socket.is_open() || impl_->timeout_scheduler == nullptr) return;
    if (!impl_->write_deadline_active) return;

    const auto now = steady_clock::now();
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        impl_->write_deadline_at - now);
    if (remaining <= std::chrono::milliseconds::zero()) {
        remaining = std::chrono::milliseconds(1);
    }

    TcpStream* self = this;
    impl_->write_deadline_token = impl_->timeout_scheduler->ScheduleAfter(
        remaining,
        [self]() {
            self->impl_->write_deadline_token.Reset();
            if (!self->impl_->socket.is_open() || self->impl_->write_timeout_sec == 0) {
                return;
            }
            if (!self->impl_->write_deadline_active) {
                return;
            }

            const auto now = steady_clock::now();
            if (now >= self->impl_->write_deadline_at) {
                self->impl_->SetFlag(kWriteTimedOut);
                self->impl_->write_deadline_active = false;
                IoErrorCode cancel_ec;
                self->impl_->socket.cancel(cancel_ec);
                return;
            }

            self->ScheduleWriteDeadlineCheck();
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
    impl_->write_deadline_active = false;
    impl_->SetFlag(kWriteTimedOut, false);
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
    transport::internet::tcp_read_policy::UnregisterActiveStream();
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

#endif
}
}  // namespace

}  // namespace acpp
