#pragma once

// 出站逻辑端点的两个基类：流式（借用已拨号的 AsyncStream）与原生数据报
// （独占一个 DatagramSocket）。只依赖传输层契约，不含 DNS、配置解析或
// asio experimental 运算符，供协议编解码头文件直接 include。

#include "common/asio_types.hpp"
#include "transport/async_stream.hpp"
#include "transport/datagram_socket.hpp"
#include "transport/link.hpp"

#include <chrono>
#include <span>

namespace proxy {

class OutboundStreamEndpointBase
    : public transport::MultiBufferReader
    , public transport::MultiBufferWriter {
public:
    explicit OutboundStreamEndpointBase(transport::AsyncStream& stream) noexcept
        : stream_(stream) {}

    transport::AsyncStream& RelayControl() noexcept {
        return stream_;
    }

    const transport::AsyncStream& RelayControl() const noexcept {
        return stream_;
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
    transport::AsyncStream& stream_;
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

    transport::DatagramSocket& RelayControl() noexcept {
        return socket_;
    }

    const transport::DatagramSocket& RelayControl() const noexcept {
        return socket_;
    }

    transport::CancellationSource& Cancellation() noexcept override {
        return socket_.Cancellation();
    }

protected:
    transport::DatagramSocket socket_;
    bool write_closed_ = false;
};

}  // namespace proxy
