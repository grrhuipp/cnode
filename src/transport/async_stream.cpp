#include "acppnode/transport/async_stream.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"

#include <new>

namespace acpp {

StreamPhaseDeadline::StreamPhaseDeadline(net::io_context& io_context, AsyncStream& owner)
    : scheduler_(TimeoutScheduler::ForIoContext(io_context)), owner_(owner) {}

StreamPhaseDeadline::~StreamPhaseDeadline() noexcept {
    Clear();
}

PhaseDeadlineHandle StreamPhaseDeadline::Start(std::chrono::seconds timeout) {
    Clear();
    if (timeout <= std::chrono::seconds::zero() || !owner_.IsOpen()) return {};
    constexpr auto maximum =
        std::chrono::duration_cast<std::chrono::seconds>(std::chrono::milliseconds::max());
    const auto delay = timeout >= maximum
        ? std::chrono::milliseconds::max()
        : std::chrono::duration_cast<std::chrono::milliseconds>(timeout);
    if (!scheduler_.ScheduleAfter(delay, *this)) return {};
    return {&expired_, 1, &generation_, generation_};
}

void StreamPhaseDeadline::Clear() noexcept {
    scheduler_.Cancel(*this);
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

void* AsyncStream::operator new(std::size_t size) {
    if (void* ptr = memory::AllocatePmr(size, alignof(AsyncStream))) {
        memory::OnAsyncStreamNew();
        return ptr;
    }
    throw std::bad_alloc();
}

void* AsyncStream::operator new(std::size_t size, std::align_val_t alignment) {
    if (void* ptr = memory::AllocatePmr(size, static_cast<std::size_t>(alignment))) {
        memory::OnAsyncStreamNew();
        return ptr;
    }
    throw std::bad_alloc();
}

void AsyncStream::operator delete(void* ptr) noexcept {
    memory::OnAsyncStreamFree();
    memory::DeallocatePmr(ptr, 0, alignof(AsyncStream));
}

void AsyncStream::operator delete(void* ptr, std::size_t size) noexcept {
    memory::OnAsyncStreamFree();
    memory::DeallocatePmr(ptr, size, alignof(AsyncStream));
}

void AsyncStream::operator delete(void* ptr, std::align_val_t alignment) noexcept {
    memory::OnAsyncStreamFree();
    memory::DeallocatePmr(ptr, 0, static_cast<std::size_t>(alignment));
}

void AsyncStream::operator delete(
    void* ptr,
    std::size_t size,
    std::align_val_t alignment) noexcept {
    memory::OnAsyncStreamFree();
    memory::DeallocatePmr(ptr, size, static_cast<std::size_t>(alignment));
}

// ============================================================================
// AsyncStream::WriteMultiBuffer - 默认实现
//
// 逐个 Buffer 调用 AsyncWrite，写完后释放。
// TcpStream override 使用 scatter-write (writev) 将多个 Buffer 合并为单次系统调用。
// ============================================================================
net::awaitable<void> AsyncStream::WriteMultiBuffer(buf::MultiBuffer mb) {

    for (auto* b : mb) {
        auto bytes = b->Bytes();
        if (bytes.empty()) continue;

        // AsyncWrite 保证写完整个 buffer（内部循环）
        co_await AsyncWrite(net::const_buffer(bytes.data(), bytes.size()));
    }
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

void AsyncStream::SetStreamLabel(std::string_view label) noexcept {
    if (auto* tcp = BaseTcpStream()) {
        tcp->SetStreamLabel(label);
    }
}

void AsyncStream::SetAbortiveClose(bool enable) noexcept {
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

}  // namespace acpp
