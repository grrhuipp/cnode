#include "transport/async_stream.hpp"
#include "common/allocator.hpp"
#include "common/buffer_util.hpp"
#include "common/memory_stats.hpp"
#include "transport/internet/tcp_stream.hpp"

#include <new>


StreamPhaseDeadline::StreamPhaseDeadline(net::io_context& io_context, AsyncStream& owner)
    : TimeoutEvent(io_context), owner_(owner) {}

StreamPhaseDeadline::~StreamPhaseDeadline() noexcept {
    Clear();
}

PhaseDeadlineHandle StreamPhaseDeadline::Start(std::chrono::seconds timeout) {
    ++generation_;
    expired_ = 0;
    if (timeout <= std::chrono::seconds::zero() || !owner_.IsOpen()) {
        TimeoutEvent::Cancel();
        return {};
    }
    constexpr auto maximum =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds::max());
    const auto delay = timeout >= maximum
        ? std::chrono::milliseconds::max()
        : std::chrono::duration_cast<std::chrono::milliseconds>(timeout);
    if (!ScheduleAfter(delay)) {
        TimeoutEvent::Cancel();
        return {};
    }
    return {&expired_, 1, &generation_, generation_};
}

void StreamPhaseDeadline::Clear() noexcept {
    TimeoutEvent::Cancel();
    ++generation_;
    expired_ = 0;
}

bool StreamPhaseDeadline::Consume() noexcept {
    return std::exchange(expired_, uint8_t{0}) != 0;
}

void StreamPhaseDeadline::OnTimeout() noexcept {
    expired_ = 1;
    // Do not touch this owner after cancellation: its callback may close it.
    owner_.Cancel();
}

// ============================================================================
// AsyncStream::WriteMultiBuffer - 默认实现
//
// 将 MultiBuffer 展开为 const_buffer 视图序列转发至 WriteBuffers，完成后释放。
// ============================================================================
net::awaitable<void> AsyncStream::WriteMultiBuffer(buf::MultiBuffer mb) {
    if (mb.byte_size() == 0) {
        mb.clear();
        co_return;
    }
    ConstBufferSpanBuilder<buf::MultiBuffer::kInlineCapacity> buffers;
    buffers.AppendMultiBuffer(mb);
    try {
        co_await WriteBuffers(buffers.Span());
    } catch (...) {
        mb.clear();
        throw;
    }
    mb.clear();
}

net::awaitable<void> AsyncStream::WriteBuffers(
    std::span<const net::const_buffer> buffers) {

    for (const auto& buffer : buffers) {
        if (buffer.size() == 0) {
            continue;
        }
        co_await AsyncWrite(buffer);
    }
}

void AsyncStream::SetIdleTimeout(std::chrono::seconds timeout) {
    if (auto* tcp = BaseTcpStream()) {
        tcp->SetIdleTimeout(timeout);
    }
}

void AsyncStream::SetReadTimeout(std::chrono::seconds timeout) {
    if (auto* tcp = BaseTcpStream()) {
        tcp->SetReadTimeout(timeout);
    }
}

void AsyncStream::SetWriteTimeout(std::chrono::seconds timeout) {
    if (auto* tcp = BaseTcpStream()) {
        tcp->SetWriteTimeout(timeout);
    }
}


void AsyncStream::SetAbortiveClose(bool enable) noexcept {
    if (LogicalPhaseDeadline()) return;
    if (auto* tcp = BaseTcpStream()) {
        tcp->SetAbortiveClose(enable);
    }
}

bool AsyncStream::DeferWriteCancellation() noexcept {
    if (auto* tcp = BaseTcpStream()) {
        tcp->SetWriteCancellationDeferred();
        return true;
    }
    return false;
}

void AsyncStream::CloseAbortive() {
    SetAbortiveClose(true);
    Close();
}
void AsyncStream::PrependReadData(std::span<const uint8_t> data) {
    if (data.empty()) {
        return;
    }
    throw IoSystemError(
        io_error::operation_not_supported,
        "HTTP handshake requires a TCP or TLS byte stream");
}

transport::CancellationSource& AsyncStream::Cancellation() noexcept {
    if (LogicalPhaseDeadline()) return cancellation_;
    if (auto* tcp = BaseTcpStream(); tcp && static_cast<AsyncStream*>(tcp) != this)
        return tcp->Cancellation();
    return cancellation_;
}

bool AsyncStream::ConsumeIdleTimeout() noexcept {
    auto* tcp = BaseTcpStream();
    return tcp && tcp->ConsumeIdleTimeout();
}

bool AsyncStream::ConsumeReadTimeout() noexcept {
    auto* tcp = BaseTcpStream();
    return tcp && tcp->ConsumeReadTimeout();
}

bool AsyncStream::ConsumeWriteTimeout() noexcept {
    auto* tcp = BaseTcpStream();
    return tcp && tcp->ConsumeWriteTimeout();
}

PhaseDeadlineHandle AsyncStream::StartPhaseDeadline(std::chrono::seconds timeout) {
    if (auto* deadline = LogicalPhaseDeadline()) {
        return deadline->Start(timeout);
    }
    if (auto* tcp = BaseTcpStream()) {
        return tcp->StartPhaseDeadline(timeout);
    }
    return {};
}

void AsyncStream::ClearPhaseDeadline() {
    if (auto* deadline = LogicalPhaseDeadline()) {
        deadline->Clear();
        return;
    }
    if (auto* tcp = BaseTcpStream()) {
        tcp->ClearPhaseDeadline();
    }
}

bool AsyncStream::ConsumePhaseDeadline() noexcept {
    if (auto* deadline = LogicalPhaseDeadline()) {
        return deadline->Consume();
    }
    auto* tcp = BaseTcpStream();
    return tcp && tcp->ConsumePhaseDeadline();
}

std::optional<tcp::endpoint> AsyncStream::LocalEndpoint() const {
    if (auto* tcp = BaseTcpStream()) {
        return tcp->LocalEndpoint();
    }
    return std::nullopt;
}

std::optional<tcp::endpoint> AsyncStream::RemoteEndpoint() const {
    if (auto* tcp = BaseTcpStream()) {
        return tcp->RemoteEndpoint();
    }
    return std::nullopt;
}

