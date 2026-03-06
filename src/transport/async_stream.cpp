#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/tcp_stream.hpp"

namespace acpp {

// ============================================================================
// AsyncStream::ReadMultiBuffer - 默认实现
//
// 分配一个 8KB pool Buffer，调用 AsyncRead 填充，返回指针。
// 子类（TcpStream、VMessStream 等）可 override 实现零拷贝优化路径。
// ============================================================================
cobalt::task<MultiBuffer> AsyncStream::ReadMultiBuffer() {
    Buffer* buf = Buffer::New();
    if (!buf) co_return MultiBuffer{};

    try {
        size_t n = co_await AsyncRead(
            net::mutable_buffer(buf->Tail().data(), buf->Available()));

        if (n == 0) {
            Buffer::Free(buf);
            co_return MultiBuffer{};  // EOF
        }

        buf->Produce(static_cast<uint32_t>(n));
        co_return MultiBuffer{buf};

    } catch (...) {
        Buffer::Free(buf);
        throw;
    }
}

// ============================================================================
// AsyncStream::WriteMultiBuffer - 默认实现
//
// 逐个 Buffer 调用 AsyncWrite，写完后释放。
// TcpStream override 使用 scatter-write (writev) 将多个 Buffer 合并为单次系统调用。
// ============================================================================
cobalt::task<void> AsyncStream::WriteMultiBuffer(MultiBuffer mb) {
    MultiBufferGuard guard{mb};

    for (auto* b : mb) {
        auto bytes = b->Bytes();
        if (bytes.empty()) continue;

        // AsyncWrite 保证写完整个 buffer（内部循环）
        co_await AsyncWrite(net::const_buffer(bytes.data(), bytes.size()));
    }
}

void AsyncStream::SetIdleTimeout(std::chrono::seconds timeout) {
    if (auto* tcp = GetBaseTcpStream()) {
        tcp->SetIdleTimeout(timeout);
    }
}

void AsyncStream::SetReadTimeout(std::chrono::seconds timeout) {
    if (auto* tcp = GetBaseTcpStream()) {
        tcp->SetReadTimeout(timeout);
    }
}

void AsyncStream::SetWriteTimeout(std::chrono::seconds timeout) {
    if (auto* tcp = GetBaseTcpStream()) {
        tcp->SetWriteTimeout(timeout);
    }
}

bool AsyncStream::ConsumeIdleTimeout() noexcept {
    auto* tcp = GetBaseTcpStream();
    return tcp && tcp->ConsumeIdleTimeout();
}

bool AsyncStream::ConsumeReadTimeout() noexcept {
    auto* tcp = GetBaseTcpStream();
    return tcp && tcp->ConsumeReadTimeout();
}

bool AsyncStream::ConsumeWriteTimeout() noexcept {
    auto* tcp = GetBaseTcpStream();
    return tcp && tcp->ConsumeWriteTimeout();
}

PhaseDeadlineHandle AsyncStream::StartPhaseDeadline(std::chrono::seconds timeout) {
    if (auto* tcp = GetBaseTcpStream()) {
        return tcp->StartPhaseDeadline(timeout);
    }
    return {};
}

void AsyncStream::ClearPhaseDeadline() {
    if (auto* tcp = GetBaseTcpStream()) {
        tcp->ClearPhaseDeadline();
    }
}

bool AsyncStream::ConsumePhaseDeadline() noexcept {
    auto* tcp = GetBaseTcpStream();
    return tcp && tcp->ConsumePhaseDeadline();
}

std::optional<tcp::endpoint> AsyncStream::LocalEndpoint() const {
    if (auto* tcp = GetBaseTcpStream()) {
        return tcp->LocalEndpoint();
    }
    return std::nullopt;
}

std::optional<tcp::endpoint> AsyncStream::RemoteEndpoint() const {
    if (auto* tcp = GetBaseTcpStream()) {
        return tcp->RemoteEndpoint();
    }
    return std::nullopt;
}

}  // namespace acpp
