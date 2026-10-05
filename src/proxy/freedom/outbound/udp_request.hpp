#pragma once

#include "../../udp_target.hpp"
#include "acppnode/common/ip_utils.hpp"

namespace acpp::proxy::freedom::outbound {

// One direct UDP association. Target resolution belongs to this outbound;
// its concrete transport owns the socket, byte I/O and aggregate deadlines.
class UdpRequest final {
public:
    UdpRequest(net::any_io_executor executor, app::dns::DNS& dns,
               const net::ip::address& bind_address)
        : executor_(executor), dns_(dns), socket_(executor, bind_address) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() {
        auto read = socket_.StartRead();
        auto packet = co_await read.Receive();
        // MultiBuffer links cannot represent an empty datagram independently
        // of EOF. Reject it explicitly instead of pretending the socket closed.
        if (!buf::HasData(packet.payload))
            throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
        const TargetAddress source(iputil::NormalizeAddress(packet.source.address()),
                                   packet.source.port());
        for (auto* buffer : packet.payload) buffer->SetUDP(source);
        socket_.TouchActivity();
        co_return std::move(packet.payload);
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) {
        const auto datagram = buf::InspectUdpDatagram(payload);
        if (datagram.status == buf::UdpDatagramStatus::Empty) co_return;
        if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid())
            throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
        if (write_closed_) throw transport::WriteClosed{};
        auto write = socket_.StartWrite();
        if (datagram.target->resolved_addr) {
            co_await write.SendTo(udp::endpoint(*datagram.target->resolved_addr, datagram.target->port),
                                 std::move(payload));
        } else {
            auto target = co_await ResolveUdpEndpoint(dns_, *datagram.target, socket_, write, executor_);
            if (!target) throw transport::LinkError(target.error());
            co_await write.SendTo(*target, std::move(payload));
        }
    }

    net::awaitable<void> AsyncShutdownWrite() { write_closed_ = true; co_return; }
    void Cancel() noexcept { socket_.Cancel(); }
    void Close() noexcept { socket_.Close(); }
    transport::CancellationSource& Cancellation() noexcept { return socket_.Cancellation(); }
    void SetIdleTimeout(std::chrono::seconds value) { socket_.SetIdleTimeout(value); }
    void SetReadTimeout(std::chrono::seconds value) { socket_.SetReadTimeout(value); }
    void SetWriteTimeout(std::chrono::seconds value) { socket_.SetWriteTimeout(value); }
    PhaseDeadlineHandle StartPhaseDeadline(std::chrono::seconds value) { return socket_.StartPhaseDeadline(value); }
    void ClearPhaseDeadline() noexcept { socket_.ClearPhaseDeadline(); }
    bool ConsumeIdleTimeout() noexcept { return socket_.ConsumeIdleTimeout(); }
    bool ConsumeReadTimeout() noexcept { return socket_.ConsumeReadTimeout(); }
    bool ConsumeWriteTimeout() noexcept { return socket_.ConsumeWriteTimeout(); }
    bool ConsumePhaseDeadline() noexcept { return socket_.ConsumePhaseDeadline(); }

private:
    net::any_io_executor executor_;
    app::dns::DNS& dns_;
    transport::internet::DatagramSocket socket_;
    bool write_closed_ = false;
};

}  // namespace acpp::proxy::freedom::outbound
