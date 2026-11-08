#pragma once

#include "../../outbound_stream_endpoint.hpp"
#include "../../udp_target.hpp"
#include "common/ip_utils.hpp"

namespace proxy::freedom::outbound {

// One direct UDP association. Target resolution belongs to this outbound;
// its concrete transport owns the socket, byte I/O and aggregate deadlines.
class UdpRequest final : public ::proxy::OutboundDatagramEndpointBase {
public:
    UdpRequest(net::io_context& io, app::dns::DNS& dns,
               const net::ip::address& bind_address)
        : OutboundDatagramEndpointBase(io, bind_address), io_(io), dns_(dns) {}

    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        auto read = socket_.StartRead();
        for (;;) {
            auto packet = co_await read.Receive();
            if (packet.source.port() == 0) {
                continue;
            }
            const TargetAddress source(iputil::NormalizeAddress(packet.source.address()),
                                       packet.source.port());
            if (!buf::SetUdpTarget(packet.payload, source))
                throw transport::LinkError(ErrorCode::RESOURCE_EXHAUSTED);
            socket_.TouchActivity();
            co_return std::move(packet.payload);
        }
    }

    net::awaitable<void> WriteMultiBuffer(buf::MultiBuffer payload) override {
        const auto datagram = buf::InspectUdpDatagram(payload);
        if (datagram.status == buf::UdpDatagramStatus::Empty) co_return;
        if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid())
            throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
        if (write_closed_) throw transport::WriteClosed{};
        auto write = socket_.StartWrite();
        if (datagram.target->resolved_addr) {
            if (datagram.target->resolved_addr->is_v6() != socket_.IsIPv6())
                throw transport::LinkError(ErrorCode::INVALID_ARGUMENT);
            co_await write.SendTo(udp::endpoint(*datagram.target->resolved_addr, datagram.target->port),
                                 std::move(payload));
        } else {
            auto& reactor = ExecutionDomain::Current()
                ? ExecutionDomain::Current()->Reactor() : io_;
            auto target = co_await ResolveUdpEndpoint(dns_, *datagram.target, socket_, write, reactor);
            if (!target) throw transport::LinkError(target.error());
            co_await write.SendTo(*target, std::move(payload));
        }
    }
private:
    net::io_context& io_;
    app::dns::DNS& dns_;
};

}  // namespace proxy::freedom::outbound
