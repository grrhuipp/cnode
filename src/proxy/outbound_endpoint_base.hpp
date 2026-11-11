#pragma once

// 出站逻辑端点的两个基类：流式（借用已拨号的 AsyncStream）与原生数据报
// （独占一个 DatagramSocket）。只依赖传输层契约，不含 DNS、配置解析或
// asio experimental 运算符，供协议编解码头文件直接 include。

#include "common/asio_types.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/datagram_socket.hpp"
#include "transport/link.hpp"

#include <chrono>
#include <span>

namespace proxy {

class OutboundStreamEndpointBase
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    explicit OutboundStreamEndpointBase(AsyncStream& stream) noexcept
        : stream_(stream) {}

    bool ConsumeIdleTimeout() noexcept {
        return stream_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return stream_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return stream_.ConsumeWriteTimeout();
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds timeout) {
        return stream_.StartPhaseDeadline(timeout);
    }

    void ClearPhaseDeadline() {
        stream_.ClearPhaseDeadline();
    }

    bool ConsumePhaseDeadline() noexcept {
        return stream_.ConsumePhaseDeadline();
    }

    void Cancel() noexcept {
        stream_.Cancel();
    }

    void SetWriteTimeout(std::chrono::seconds timeout) {
        stream_.SetWriteTimeout(timeout);
    }

    void Close() {
        stream_.Close();
    }

    void CloseAbortive() {
        stream_.CloseAbortive();
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return stream_.Cancellation();
    }

    transport::EofAction ReadEofAction() const noexcept override {
        return stream_.ReadEofAction();
    }

    bool WriteShutdownClosesLink() const noexcept override {
        return stream_.WriteShutdownClosesLink();
    }

protected:
    AsyncStream& stream_;
};

class OutboundDatagramEndpointBase
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    OutboundDatagramEndpointBase(net::io_context& io, const net::ip::address& bind_address)
        : socket_(io, bind_address) {}

    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer> buffers) override {
        return WriteBuffersAsMultiBuffer(buffers);
    }

    net::awaitable<void> AsyncShutdownWrite() override {
        write_closed_ = true;
        co_return;
    }

    void Cancel() noexcept {
        socket_.Cancel();
    }

    void Close() noexcept {
        socket_.Close();
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return socket_.Cancellation();
    }

    void SetIdleTimeout(std::chrono::seconds value) {
        socket_.SetIdleTimeout(value);
    }

    void SetReadTimeout(std::chrono::seconds value) {
        socket_.SetReadTimeout(value);
    }

    void SetWriteTimeout(std::chrono::seconds value) {
        socket_.SetWriteTimeout(value);
    }

    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds value) {
        return socket_.StartPhaseDeadline(value);
    }

    void ClearPhaseDeadline() noexcept {
        socket_.ClearPhaseDeadline();
    }

    bool ConsumeIdleTimeout() noexcept {
        return socket_.ConsumeIdleTimeout();
    }

    bool ConsumeReadTimeout() noexcept {
        return socket_.ConsumeReadTimeout();
    }

    bool ConsumeWriteTimeout() noexcept {
        return socket_.ConsumeWriteTimeout();
    }

    bool ConsumePhaseDeadline() noexcept {
        return socket_.ConsumePhaseDeadline();
    }

protected:
    transport::internet::DatagramSocket socket_;
    bool write_closed_ = false;
};

}  // namespace proxy
