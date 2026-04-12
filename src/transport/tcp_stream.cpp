#include "acppnode/transport/tcp_stream.hpp"
#include "acppnode/common/buffer_util.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/timeout_scheduler.hpp"

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/buffer.hpp>

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
constexpr uint32_t kReadGrowThreshold = Buffer::kSize / 2;
constexpr uint8_t kReadGrowStreakRequired = 2;
std::atomic<uint32_t> g_active_tcp_streams{0};
// 合并 socket + timeout 状态为单次分配，减少每次 Connect 的堆操作
struct ConnectState {
    tcp::socket socket;
    std::atomic<bool> timed_out{false};
    std::atomic<bool> active{true};

    explicit ConnectState(net::any_io_executor executor)
        : socket(std::move(executor)) {}
};

int SelectSocketBufferSize() noexcept {
    const uint32_t active = g_active_tcp_streams.load(std::memory_order_relaxed);
    if (active >= 40000) return kSocketBufferSizeLow;
    if (active >= 12000) return kSocketBufferSizeMid;
    return kSocketBufferSizeHigh;
}
}

// ============================================================================
// TcpStream 实现
// ============================================================================

TcpStream::TcpStream(tcp::socket socket)
    : socket_(std::move(socket))
    , timeout_scheduler_(&TimeoutScheduler::ForExecutor(socket_.get_executor())) {
    if (socket_.is_open()) {
        counted_active_ = true;
        g_active_tcp_streams.fetch_add(1, std::memory_order_relaxed);
        SetupConnectedSocket(socket_);
    }
}

TcpStream::TcpStream(TcpStream&& other) noexcept
    : socket_(std::move(other.socket_))
    , stream_label_(std::move(other.stream_label_))
    , abortive_close_(other.abortive_close_)
    , read_shutdown_(other.read_shutdown_)
    , write_shutdown_(other.write_shutdown_)
    , counted_active_(other.counted_active_)
    , pending_data_(std::move(other.pending_data_))
    , pending_offset_(other.pending_offset_)
    , read_alloc_count_(other.read_alloc_count_)
    , read_grow_streak_(other.read_grow_streak_)
    , idle_timeout_(other.idle_timeout_)
    , last_io_time_(other.last_io_time_)
    , read_timeout_(other.read_timeout_)
    , write_timeout_(other.write_timeout_)
    , timeout_scheduler_(&TimeoutScheduler::ForExecutor(socket_.get_executor())) {
    other.CancelIdleTimer();
    other.CancelReadDeadline();
    other.CancelWriteDeadline();
    other.CancelPhaseDeadline();
    idle_timed_out_.store(
        other.idle_timed_out_.exchange(false, std::memory_order_acq_rel),
        std::memory_order_release);
    read_timed_out_.store(
        other.read_timed_out_.exchange(false, std::memory_order_acq_rel),
        std::memory_order_release);
    write_timed_out_.store(
        other.write_timed_out_.exchange(false, std::memory_order_acq_rel),
        std::memory_order_release);
    phase_deadline_timed_out_.store(
        other.phase_deadline_timed_out_.exchange(false, std::memory_order_acq_rel),
        std::memory_order_release);
    other.idle_timeout_ = std::chrono::seconds{0};
    other.read_timeout_ = std::chrono::seconds{0};
    other.write_timeout_ = std::chrono::seconds{0};
    other.counted_active_ = false;
    other.abortive_close_ = false;
    other.read_alloc_count_ = 1;
    other.read_grow_streak_ = 0;
    other.read_shutdown_ = true;
    other.write_shutdown_ = true;
}

TcpStream& TcpStream::operator=(TcpStream&& other) noexcept {
    if (this != &other) {
        CancelIdleTimer();
        CancelReadDeadline();
        CancelWriteDeadline();
        CancelPhaseDeadline();
        Close();
        socket_ = std::move(other.socket_);
        stream_label_ = std::move(other.stream_label_);
        abortive_close_ = other.abortive_close_;
        read_shutdown_ = other.read_shutdown_;
        write_shutdown_ = other.write_shutdown_;
        counted_active_ = other.counted_active_;
        pending_data_ = std::move(other.pending_data_);
        pending_offset_ = other.pending_offset_;
        read_alloc_count_ = other.read_alloc_count_;
        read_grow_streak_ = other.read_grow_streak_;
        idle_timeout_ = other.idle_timeout_;
        read_timeout_ = other.read_timeout_;
        write_timeout_ = other.write_timeout_;
        timeout_scheduler_ = &TimeoutScheduler::ForExecutor(socket_.get_executor());
        last_io_time_ = other.last_io_time_;
        other.CancelIdleTimer();
        other.CancelReadDeadline();
        other.CancelWriteDeadline();
        other.CancelPhaseDeadline();
        idle_timed_out_.store(
            other.idle_timed_out_.exchange(false, std::memory_order_acq_rel),
            std::memory_order_release);
        read_timed_out_.store(
            other.read_timed_out_.exchange(false, std::memory_order_acq_rel),
            std::memory_order_release);
        write_timed_out_.store(
            other.write_timed_out_.exchange(false, std::memory_order_acq_rel),
            std::memory_order_release);
        phase_deadline_timed_out_.store(
            other.phase_deadline_timed_out_.exchange(false, std::memory_order_acq_rel),
            std::memory_order_release);
        other.idle_timeout_ = std::chrono::seconds{0};
        other.read_timeout_ = std::chrono::seconds{0};
        other.write_timeout_ = std::chrono::seconds{0};
        other.counted_active_ = false;
        other.abortive_close_ = false;
        other.read_alloc_count_ = 1;
        other.read_grow_streak_ = 0;
        other.read_shutdown_ = true;
        other.write_shutdown_ = true;
    }
    return *this;
}

TcpStream::~TcpStream() {
    // Close() 内部已包含所有 Cancel 调用，不重复
    Close();
}

cobalt::task<std::size_t> TcpStream::AsyncRead(net::mutable_buffer buf) {
    if (!socket_.is_open() || read_shutdown_) {
        co_return 0;
    }

    // 先返回 pending 数据（使用偏移游标避免 O(n) erase）
    if (pending_offset_ < pending_data_.size()) {
        size_t avail = pending_data_.size() - pending_offset_;
        size_t copy = std::min(buf.size(), avail);
        std::memcpy(buf.data(), pending_data_.data() + pending_offset_, copy);
        pending_offset_ += copy;
        if (pending_offset_ >= pending_data_.size()) {
            pending_data_.clear();
            pending_offset_ = 0;
            ReleaseIdleBuffer(pending_data_, 1024);
        }
        TouchActivity();
        co_return copy;
    }

    ArmReadDeadline();
    auto [ec, n] = co_await socket_.async_read_some(buf,
        net::as_tuple(cobalt::use_op));
    CancelReadDeadline();

    if (ec) {
        if (ec == net::error::eof) {
            co_return 0;  // 正常关闭
        }
        if (ec == net::error::connection_reset ||
            ec == net::error::broken_pipe) {
            LOG_ACCESS_DEBUG("AsyncRead: {} (fd={})", ec.message(), NativeHandle());
            co_return 0;
        }
        if (ec == net::error::operation_aborted) {
            co_return 0;  // 被取消（可能是 idle timeout）
        }
        throw boost::system::system_error(ec);
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
//   - 读满后加倍（1→2→4→8），使用 readv / WSARecv 单次系统调用填多个 Buffer
//   - 未读满则收缩到实际使用数，避免浪费
// ============================================================================
cobalt::task<MultiBuffer> TcpStream::ReadMultiBuffer() {
    if (!socket_.is_open() || read_shutdown_) co_return MultiBuffer{};

    // 先消费 pending_data（使用偏移游标避免 O(n) erase）
    if (pending_offset_ < pending_data_.size()) {
        Buffer* buf = Buffer::New();
        size_t avail = pending_data_.size() - pending_offset_;
        uint32_t copy = static_cast<uint32_t>(
            std::min<size_t>(avail, buf->Available()));
        std::memcpy(buf->Tail().data(), pending_data_.data() + pending_offset_, copy);
        pending_offset_ += copy;
        if (pending_offset_ >= pending_data_.size()) {
            pending_data_.clear();
            pending_offset_ = 0;
            ReleaseIdleBuffer(pending_data_, 1024);
        }
        buf->Produce(copy);
        TouchActivity();
        co_return MultiBuffer{buf};
    }

    // ── 快速路径：单 Buffer（低流量 / 启动阶段，零额外分配）─────────────
    if (read_alloc_count_ == 1) {
        Buffer* buf = Buffer::New();
        ArmReadDeadline();
        auto [ec, n] = co_await socket_.async_read_some(
            net::mutable_buffer(buf->Tail().data(), buf->Available()),
            net::as_tuple(cobalt::use_op));
        CancelReadDeadline();

        if (ec || n == 0) {
            Buffer::Free(buf);
            if (!ec || ec == net::error::eof ||
                ec == net::error::operation_aborted)
                co_return MultiBuffer{};
            if (ec == net::error::connection_reset ||
                ec == net::error::broken_pipe) {
                LOG_ACCESS_DEBUG("ReadMultiBuffer: {} (fd={})", ec.message(), NativeHandle());
                co_return MultiBuffer{};
            }
            throw boost::system::system_error(ec);
        }

        buf->Produce(static_cast<uint32_t>(n));
        TouchActivity();
        // 读满或连续"大包"读命中时，提前切换到 scatter-read。
        if (n == Buffer::kSize || n >= kReadGrowThreshold) {
            if (read_grow_streak_ < 0xff) {
                ++read_grow_streak_;
            }
            if (read_grow_streak_ >= kReadGrowStreakRequired) {
                read_alloc_count_ = 2;
                read_grow_streak_ = 0;
            }
        } else {
            read_grow_streak_ = 0;
        }
        co_return MultiBuffer{buf};
    }

    // ── 散读路径：n_alloc 个 Buffer，单次 readv / WSARecv ───────────────
    const uint32_t n_alloc = read_alloc_count_;

    // 在协程帧上分配（co_await 期间保持有效），最多 8 个
    std::array<Buffer*, 8> ptrs{};
    for (uint32_t i = 0; i < n_alloc; ++i) ptrs[i] = Buffer::New();

    // 构造 scatter iovec（栈分配，n_alloc <= 8）
    std::array<net::mutable_buffer, 8> iov_arr;
    for (uint32_t i = 0; i < n_alloc; ++i)
        iov_arr[i] = net::mutable_buffer(ptrs[i]->Tail().data(), Buffer::kSize);
    auto iov = std::span(iov_arr.data(), n_alloc);

    ArmReadDeadline();
    auto [ec, n] = co_await socket_.async_read_some(
        iov, net::as_tuple(cobalt::use_op));
    CancelReadDeadline();

    if (ec || n == 0) {
        for (uint32_t i = 0; i < n_alloc; ++i) Buffer::Free(ptrs[i]);
        if (!ec || ec == net::error::eof ||
            ec == net::error::operation_aborted)
            co_return MultiBuffer{};
        if (ec == net::error::connection_reset ||
            ec == net::error::broken_pipe) {
            LOG_ACCESS_DEBUG("ReadMultiBuffer(scatter): {} (fd={})", ec.message(), NativeHandle());
            co_return MultiBuffer{};
        }
        throw boost::system::system_error(ec);
    }

    // scatter-read 按顺序填充各 Buffer，将 n 字节分配给实际用到的 Buffer
    MultiBuffer result;
    result.reserve(n_alloc);
    size_t remaining = n;
    uint32_t used = 0;
    for (uint32_t i = 0; i < n_alloc; ++i) {
        if (remaining == 0) {
            Buffer::Free(ptrs[i]);
            continue;
        }
        uint32_t fill = static_cast<uint32_t>(
            std::min<size_t>(remaining, Buffer::kSize));
        ptrs[i]->Produce(fill);
        remaining -= fill;
        result.push_back(ptrs[i]);
        ++used;
    }

    TouchActivity();

    // 自适应调整：全部读满 → 加倍（上限 8），否则收缩到实际使用数
    if (used >= n_alloc) {
        read_alloc_count_ = std::min(n_alloc * 2u, 8u);
    } else {
        read_alloc_count_ = std::max(used, 1u);
    }
    read_grow_streak_ = 0;

    co_return result;
}

// ============================================================================
// TcpStream::WriteMultiBuffer
//
// 优化路径：将多个 Buffer 合并为 net::const_buffer_sequence，
// 通过 net::async_write 发出单次 scatter-write（WSASend / writev），
// 减少系统调用次数。
// ============================================================================
cobalt::task<void> TcpStream::WriteMultiBuffer(MultiBuffer mb) {
    MultiBufferGuard guard{mb};

    if (!socket_.is_open() || write_shutdown_ || mb.empty()) co_return;

    // 构造 scatter-write buffer 序列（栈分配，常规路径 <= 8 个 buffer）
    constexpr size_t kStackBufs = 8;
    std::array<net::const_buffer, kStackBufs> stack_bufs;
    size_t buf_count = 0;

    for (auto* b : mb) {
        auto bytes = b->Bytes();
        if (!bytes.empty() && buf_count < kStackBufs) {
            stack_bufs[buf_count++] = net::const_buffer(bytes.data(), bytes.size());
        }
    }

    if (buf_count == 0) co_return;

    // 超过 kStackBufs 的情况（理论上不会，relay 产出 <= 8）回退到 vector
    std::vector<net::const_buffer> heap_bufs;
    if (mb.size() > kStackBufs) {
        heap_bufs.reserve(mb.size());
        for (auto* b : mb) {
            auto bytes = b->Bytes();
            if (!bytes.empty()) heap_bufs.emplace_back(bytes.data(), bytes.size());
        }
    }

    auto bufs_span = (mb.size() > kStackBufs)
        ? std::span<net::const_buffer>(heap_bufs)
        : std::span<net::const_buffer>(stack_bufs.data(), buf_count);

    ArmWriteDeadline();
    auto [ec, n] = co_await net::async_write(
        socket_, bufs_span, net::as_tuple(cobalt::use_op));
    CancelWriteDeadline();

    if (ec) {
        throw boost::system::system_error(ec);
    }
    if (!ec) TouchActivity();
}

cobalt::task<std::size_t> TcpStream::AsyncWrite(net::const_buffer buf) {
    if (!socket_.is_open() || write_shutdown_) {
        co_return 0;
    }

    ArmWriteDeadline();
    auto [ec, n] = co_await net::async_write(socket_, buf,
        net::as_tuple(cobalt::use_op));
    CancelWriteDeadline();

    if (ec) {
        throw boost::system::system_error(ec);
    }

    TouchActivity();
    co_return n;
}

void TcpStream::ShutdownRead() {
    if (!socket_.is_open() || read_shutdown_) {
        return;
    }
    
    boost::system::error_code ec;
    socket_.shutdown(tcp::socket::shutdown_receive, ec);
    read_shutdown_ = true;
    // 忽略错误，可能对端已关闭
}

void TcpStream::ShutdownWrite() {
    if (!socket_.is_open() || write_shutdown_) {
        return;
    }
    
    boost::system::error_code ec;
    socket_.shutdown(tcp::socket::shutdown_send, ec);
    write_shutdown_ = true;
    // 忽略错误
}

void TcpStream::Close() {
    CancelIdleTimer();
    CancelReadDeadline();
    CancelWriteDeadline();
    CancelPhaseDeadline();
    if (socket_.is_open()) {
        boost::system::error_code ec;
        // 仅错误路径使用 abortive close；正常关闭保持 FIN 语义，
        // 避免高并发下统一 RST 导致对端看到 connection reset。
        if (abortive_close_) {
            struct linger lg = {1, 0};
            ::setsockopt(socket_.native_handle(), SOL_SOCKET, SO_LINGER,
                         reinterpret_cast<const char*>(&lg), sizeof(lg));
        }
        socket_.shutdown(tcp::socket::shutdown_both, ec);
        socket_.close(ec);
    }
    ReleaseActiveCounter();
    read_shutdown_ = true;
    write_shutdown_ = true;
}

void TcpStream::Cancel() noexcept {
    if (socket_.is_open()) {
        boost::system::error_code ec;
        socket_.cancel(ec);
    }
}

int TcpStream::NativeHandle() const {
    if (!socket_.is_open()) {
        return -1;
    }
    return static_cast<int>(const_cast<tcp::socket&>(socket_).native_handle());
}

net::any_io_executor TcpStream::GetExecutor() const {
    return const_cast<tcp::socket&>(socket_).get_executor();
}

bool TcpStream::IsOpen() const {
    return socket_.is_open();
}

tcp::endpoint TcpStream::LocalEndpoint() const {
    if (!socket_.is_open()) {
        return tcp::endpoint();
    }
    boost::system::error_code ec;
    auto ep = socket_.local_endpoint(ec);
    return ec ? tcp::endpoint() : ep;
}

tcp::endpoint TcpStream::RemoteEndpoint() const {
    if (!socket_.is_open()) {
        return tcp::endpoint();
    }
    boost::system::error_code ec;
    auto ep = socket_.remote_endpoint(ec);
    return ec ? tcp::endpoint() : ep;
}

// ============================================================================
// 静态连接方法
// ============================================================================

cobalt::task<DialResult> TcpStream::Connect(
    net::any_io_executor executor,
    const tcp::endpoint& endpoint,
    std::chrono::seconds timeout) {

    if (timeout.count() <= 0) {
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }

    auto state = std::make_shared<ConnectState>(executor);
    auto& scheduler = TimeoutScheduler::ForExecutor(executor);
    TimeoutToken token = scheduler.ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
        [state]() {
            if (state->active.exchange(false, std::memory_order_acq_rel)) {
                state->timed_out.store(true, std::memory_order_release);
                boost::system::error_code close_ec;
                state->socket.close(close_ec);
            }
        });

    boost::system::error_code connect_ec;

    try {
        co_await state->socket.async_connect(endpoint, cobalt::use_op);
    } catch (const boost::system::system_error& e) {
        connect_ec = e.code();
    }

    if (state->active.exchange(false, std::memory_order_acq_rel)) {
        scheduler.Cancel(token);
    } else {
        token.Reset();
    }

    if (state->timed_out.load(std::memory_order_acquire)) {
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }

    if (connect_ec) {
        auto err = MapAsioError(connect_ec);
        co_return DialResult::Fail(err, connect_ec.message());
    }
    co_return DialResult::Success(
        std::make_unique<TcpStream>(std::move(state->socket)));
}

cobalt::task<DialResult> TcpStream::ConnectWithBind(
    net::any_io_executor executor,
    const net::ip::address& local_addr,
    const tcp::endpoint& remote_endpoint,
    std::chrono::seconds timeout) {

    if (timeout.count() <= 0) {
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }

    auto state = std::make_shared<ConnectState>(executor);

    // 打开 socket
    boost::system::error_code ec;
    state->socket.open(remote_endpoint.protocol(), ec);
    if (ec) {
        co_return DialResult::Fail(ErrorCode::SOCKET_CREATE_FAILED, ec.message());
    }

    // 绑定本地地址
    tcp::endpoint local_endpoint(local_addr, 0);  // 端口为 0，由系统分配
    state->socket.bind(local_endpoint, ec);
    if (ec) {
        co_return DialResult::Fail(ErrorCode::SOCKET_BIND_FAILED, ec.message());
    }

    auto& scheduler = TimeoutScheduler::ForExecutor(executor);
    TimeoutToken token = scheduler.ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
        [state]() {
            if (state->active.exchange(false, std::memory_order_acq_rel)) {
                state->timed_out.store(true, std::memory_order_release);
                boost::system::error_code close_ec;
                state->socket.close(close_ec);
            }
        });

    boost::system::error_code connect_ec;

    try {
        co_await state->socket.async_connect(remote_endpoint, cobalt::use_op);
    } catch (const boost::system::system_error& e) {
        connect_ec = e.code();
    }

    if (state->active.exchange(false, std::memory_order_acq_rel)) {
        scheduler.Cancel(token);
    } else {
        token.Reset();
    }

    if (state->timed_out.load(std::memory_order_acquire)) {
        co_return DialResult::Fail(ErrorCode::DIAL_TIMEOUT, "connection timed out");
    }

    if (connect_ec) {
        auto err = MapAsioError(connect_ec);
        co_return DialResult::Fail(err, connect_ec.message());
    }
    co_return DialResult::Success(
        std::make_unique<TcpStream>(std::move(state->socket)));
}

// ============================================================================
// Idle Timeout
// ============================================================================

void TcpStream::SetIdleTimeout(std::chrono::seconds timeout) {
    idle_timeout_ = timeout;
    if (timeout.count() > 0) {
        last_io_time_ = steady_clock::now();
        idle_timed_out_.store(false, std::memory_order_release);
        ScheduleIdleCheck();
    } else {
        idle_timed_out_.store(false, std::memory_order_release);
        CancelIdleTimer();
    }
}

bool TcpStream::ConsumeIdleTimeout() noexcept {
    return idle_timed_out_.exchange(false, std::memory_order_acq_rel);
}

void TcpStream::SetReadTimeout(std::chrono::seconds timeout) {
    read_timeout_ = timeout;
    if (timeout.count() <= 0) {
        read_timed_out_.store(false, std::memory_order_release);
        CancelReadDeadline();
    }
}

void TcpStream::SetWriteTimeout(std::chrono::seconds timeout) {
    write_timeout_ = timeout;
    if (timeout.count() <= 0) {
        write_timed_out_.store(false, std::memory_order_release);
        CancelWriteDeadline();
    }
}

bool TcpStream::ConsumeReadTimeout() noexcept {
    return read_timed_out_.exchange(false, std::memory_order_acq_rel);
}

bool TcpStream::ConsumeWriteTimeout() noexcept {
    return write_timed_out_.exchange(false, std::memory_order_acq_rel);
}

PhaseDeadlineHandle TcpStream::StartPhaseDeadline(std::chrono::seconds timeout) {
    ClearPhaseDeadline();
    if (timeout.count() <= 0 || !socket_.is_open() || timeout_scheduler_ == nullptr) {
        return {};
    }

    phase_deadline_timed_out_.store(false, std::memory_order_release);
    if (!phase_deadline_handle_state_) {
        phase_deadline_handle_state_ = std::make_shared<std::atomic<bool>>(false);
    }
    phase_deadline_handle_state_->store(false, std::memory_order_release);

    tcp::socket* sock = &socket_;
    std::atomic<bool>* timed_out = &phase_deadline_timed_out_;
    auto handle_state = phase_deadline_handle_state_;

    phase_deadline_token_ = timeout_scheduler_->ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(timeout),
        [sock, timed_out, handle_state]() {
            timed_out->store(true, std::memory_order_release);
            handle_state->store(true, std::memory_order_release);
            boost::system::error_code cancel_ec;
            sock->cancel(cancel_ec);
    });

    return PhaseDeadlineHandle{std::move(handle_state)};
}

void TcpStream::ClearPhaseDeadline() {
    phase_deadline_timed_out_.store(false, std::memory_order_release);
    if (phase_deadline_handle_state_) {
        phase_deadline_handle_state_->store(false, std::memory_order_release);
    }
    CancelPhaseDeadline();
}

bool TcpStream::ConsumePhaseDeadline() noexcept {
    const bool timed_out =
        phase_deadline_timed_out_.exchange(false, std::memory_order_acq_rel);
    if (phase_deadline_handle_state_) {
        phase_deadline_handle_state_->store(false, std::memory_order_release);
    }
    return timed_out;
}

// 每次成功 I/O 后调用——仅写一个时间戳，零 epoll 操作
void TcpStream::TouchActivity() {
    if (idle_timeout_.count() <= 0) return;
    last_io_time_ = steady_clock::now();
    idle_timed_out_.store(false, std::memory_order_release);
}

// 启动/续调惰性 idle 检查。定时器到期后检查 last_io_time_，
// 若真超时则 cancel socket，否则按剩余时间重新调度。
// 安全性：通过 token 从共享调度器撤销事件；析构路径先 cancel token 再释放对象。
void TcpStream::ScheduleIdleCheck() {
    if (idle_timeout_.count() <= 0 || !socket_.is_open() || timeout_scheduler_ == nullptr) return;

    CancelIdleTimer();

    // 计算距离预期超时的剩余时间
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        steady_clock::now() - last_io_time_);
    const auto timeout_ms = std::chrono::duration_cast<std::chrono::milliseconds>(idle_timeout_);
    auto remaining = timeout_ms - elapsed;
    if (remaining <= std::chrono::milliseconds::zero()) {
        remaining = std::chrono::milliseconds(1);
    }

    // 捕获 this——timer 是成员，析构前自动 cancel，安全
    TcpStream* self = this;
    idle_timer_token_ = timeout_scheduler_->ScheduleAfter(remaining, [self]() {
        if (!self->socket_.is_open()) return;
        auto elapsed = steady_clock::now() - self->last_io_time_;
        if (elapsed >= self->idle_timeout_) {
            self->idle_timed_out_.store(true, std::memory_order_release);
            // 记录触发 idle timeout 的连接端点，辅助排查断连
            if (Log::ShouldLog(LogLevel::DEBUG)) {
                boost::system::error_code ep_ec;
                auto remote = self->socket_.remote_endpoint(ep_ec);
                auto idle_sec = std::chrono::duration_cast<std::chrono::seconds>(elapsed).count();
                const auto& label = self->stream_label_;
                if (!ep_ec) {
                    LOG_ACCESS_DEBUG("idle timeout fired: [{}] remote={}:{} idle={}s limit={}s",
                                    label.empty() ? "?" : label,
                                    remote.address().to_string(), remote.port(),
                                    idle_sec, self->idle_timeout_.count());
                } else {
                    LOG_ACCESS_DEBUG("idle timeout fired: [{}] idle={}s limit={}s",
                                    label.empty() ? "?" : label,
                                    idle_sec, self->idle_timeout_.count());
                }
            }
            boost::system::error_code cancel_ec;
            self->socket_.cancel(cancel_ec);
        } else {
            self->ScheduleIdleCheck();
        }
    });
}

void TcpStream::CancelIdleTimer() noexcept {
    if (timeout_scheduler_) {
        timeout_scheduler_->Cancel(idle_timer_token_);
    } else {
        idle_timer_token_.Reset();
    }
}

void TcpStream::ArmReadDeadline() {
    if (read_timeout_.count() <= 0 || !socket_.is_open() || timeout_scheduler_ == nullptr) return;

    CancelReadDeadline();
    read_timed_out_.store(false, std::memory_order_release);
    tcp::socket* sock = &socket_;
    std::atomic<bool>* timed_out = &read_timed_out_;
    read_deadline_token_ = timeout_scheduler_->ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(read_timeout_),
        [sock, timed_out]() {
            timed_out->store(true, std::memory_order_release);
            boost::system::error_code cancel_ec;
            sock->cancel(cancel_ec);
    });
}

void TcpStream::ArmWriteDeadline() {
    if (write_timeout_.count() <= 0 || !socket_.is_open() || timeout_scheduler_ == nullptr) return;

    CancelWriteDeadline();
    write_timed_out_.store(false, std::memory_order_release);
    tcp::socket* sock = &socket_;
    std::atomic<bool>* timed_out = &write_timed_out_;
    write_deadline_token_ = timeout_scheduler_->ScheduleAfter(
        std::chrono::duration_cast<std::chrono::milliseconds>(write_timeout_),
        [sock, timed_out]() {
            timed_out->store(true, std::memory_order_release);
            boost::system::error_code cancel_ec;
            sock->cancel(cancel_ec);
    });
}

void TcpStream::CancelReadDeadline() noexcept {
    if (timeout_scheduler_) {
        timeout_scheduler_->Cancel(read_deadline_token_);
    } else {
        read_deadline_token_.Reset();
    }
}

void TcpStream::CancelWriteDeadline() noexcept {
    if (timeout_scheduler_) {
        timeout_scheduler_->Cancel(write_deadline_token_);
    } else {
        write_deadline_token_.Reset();
    }
}

void TcpStream::CancelPhaseDeadline() noexcept {
    if (timeout_scheduler_) {
        timeout_scheduler_->Cancel(phase_deadline_token_);
    } else {
        phase_deadline_token_.Reset();
    }
}

void TcpStream::ReleaseActiveCounter() noexcept {
    if (!counted_active_) return;
    g_active_tcp_streams.fetch_sub(1, std::memory_order_relaxed);
    counted_active_ = false;
}

// ============================================================================
// Socket 设置函数
// ============================================================================

void SetupConnectedSocket(tcp::socket& sock) {
    if (!sock.is_open()) {
        return;
    }

    boost::system::error_code ec;
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
    // TCP_KEEPIDLE: 空闲多久后开始探测 (60秒)
    int keepidle = 60;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));

    // TCP_KEEPINTVL: 探测间隔 (10秒)
    int keepintvl = 10;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));

    // TCP_KEEPCNT: 探测次数 (6次)
    int keepcnt = 6;
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));

    // TCP_QUICKACK - 立即发送 ACK，降低延迟 (Linux 特有)
    int quickack = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &quickack, sizeof(quickack));

    // 高连接数场景按并发档位自适应内核收发缓冲，降低每连接常驻内存。
    int bufsize = SelectSocketBufferSize();
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
#endif
}

void SetupListenerSocket(tcp::acceptor& acceptor, const tcp::endpoint& endpoint) {
    boost::system::error_code ec;

    // 打开 acceptor
    acceptor.open(endpoint.protocol(), ec);
    if (ec) {
        throw boost::system::system_error(ec, "open acceptor");
    }

    // SO_REUSEADDR
    acceptor.set_option(tcp::acceptor::reuse_address(true), ec);

#ifndef _WIN32
    auto fd = acceptor.native_handle();

    // 单 Acceptor 架构：不需要 SO_REUSEPORT

    // TCP_DEFER_ACCEPT - 只有收到数据才唤醒 accept (Linux 特有)
    // 减少 SYN flood 攻击和空连接的影响
    int defer_accept = 5;  // 5秒
    setsockopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &defer_accept, sizeof(defer_accept));

    // TCP_FASTOPEN - 启用 TFO (如果内核支持)
    int qlen = 256;  // TFO 队列长度
    setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
#endif

    // 绑定
    acceptor.bind(endpoint, ec);
    if (ec) {
        throw boost::system::system_error(ec, "bind");
    }

    // 监听，增大 backlog
    acceptor.listen(8192, ec);
    if (ec) {
        throw boost::system::system_error(ec, "listen");
    }
}

}  // namespace acpp
