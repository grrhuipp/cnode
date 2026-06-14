#include "acppnode/transport/async_stream.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/memory_stats.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"

#include <new>

namespace acpp {

void* AsyncStream::operator new(std::size_t size) {
    if (void* ptr = memory::AllocateRaw(size, alignof(AsyncStream))) {
        memory::OnAsyncStreamNew();
        return ptr;
    }
    throw std::bad_alloc();
}

void* AsyncStream::operator new(std::size_t size, std::align_val_t alignment) {
    if (void* ptr = memory::AllocateRaw(size, static_cast<std::size_t>(alignment))) {
        memory::OnAsyncStreamNew();
        return ptr;
    }
    throw std::bad_alloc();
}

void AsyncStream::operator delete(void* ptr) noexcept {
    memory::OnAsyncStreamFree();
    memory::DeallocateRaw(ptr, 0, alignof(AsyncStream));
}

void AsyncStream::operator delete(void* ptr, std::size_t size) noexcept {
    memory::OnAsyncStreamFree();
    memory::DeallocateRaw(ptr, size, alignof(AsyncStream));
}

void AsyncStream::operator delete(void* ptr, std::align_val_t alignment) noexcept {
    memory::OnAsyncStreamFree();
    memory::DeallocateRaw(ptr, 0, static_cast<std::size_t>(alignment));
}

void AsyncStream::operator delete(
    void* ptr,
    std::size_t size,
    std::align_val_t alignment) noexcept {
    memory::OnAsyncStreamFree();
    memory::DeallocateRaw(ptr, size, static_cast<std::size_t>(alignment));
}

// ============================================================================
// AsyncStream::ReadMultiBuffer - 默认实现
//
// 分配一个 8KB pool Buffer，调用 AsyncRead 填充，返回指针。
// 子类（TcpStream、VMessStream 等）可 override 实现零拷贝优化路径。
// ============================================================================
net::awaitable<buf::MultiBuffer> AsyncStream::ReadMultiBuffer() {
    buf::BufferGuard buf{buf::Buffer::New()};
    if (!buf) co_return buf::MultiBuffer{};

    size_t n = co_await AsyncRead(
        net::mutable_buffer(buf->Tail().data(), buf->Available()));

    if (n == 0) {
        co_return buf::MultiBuffer{};  // EOF
    }

    buf->Produce(static_cast<uint32_t>(n));
    co_return buf::MultiBuffer{buf.release()};
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
    if (auto* tcp = BaseTcpStream()) {
        return tcp->StartPhaseDeadline(timeout);
    }
    return {};
}

void AsyncStream::ClearPhaseDeadline() {
    if (auto* tcp = BaseTcpStream()) {
        tcp->ClearPhaseDeadline();
    }
}

bool AsyncStream::ConsumePhaseDeadline() noexcept {
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
