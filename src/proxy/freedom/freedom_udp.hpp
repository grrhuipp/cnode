#pragma once

// Freedom 出站私有的原生 UDP 关联。只有 freedom_outbound.cpp 与其契约测试
// （tests/udp_request_test.cpp）使用；测试需要直接构造端点，因此放在私有头
// 而不是 .cpp 内。

#include "app/dns.hpp"
#include "common/multi_buffer.hpp"
#include "common/error.hpp"
#include "common/ip_address.hpp"
#include "common/target_address.hpp"
#include "proxy/outbound_endpoint_base.hpp"
#include "proxy/outbound_stream_endpoint.hpp"
#include "transport/link.hpp"

#include <utility>

namespace proxy {

// One direct UDP association. Target resolution belongs to this outbound;
// its concrete transport owns the socket, byte I/O and aggregate deadlines.
class FreedomUdpRequest final : public ::proxy::OutboundDatagramEndpointBase {
public:
    FreedomUdpRequest(net::io_context& io, app::DNS& dns, const net::ip::address& bind_address)
        : OutboundDatagramEndpointBase(io, bind_address), dns_(dns) {}

    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        auto read = socket_.StartRead();
        for (;;) {
            auto packet = co_await read.Receive();
            if (packet.source.port() == 0) {
                continue;
            }
            const common::TargetAddress source(common::NormalizeAddress(packet.source.address()),
                                       packet.source.port());
            if (!common::SetUdpTarget(packet.payload, source))
                throw transport::LinkError(common::ErrorCode::RESOURCE_EXHAUSTED);
            socket_.TouchActivity();
            co_return std::move(packet.payload);
        }
    }

    net::awaitable<void> WriteMultiBuffer(common::MultiBuffer payload) override {
        // Native socket arguments are not a UDP-over-stream protocol frame.
        const auto datagram = common::InspectUdpDatagram(payload);
        if (datagram.status == common::UdpDatagramStatus::Empty) co_return;
        if (!datagram.Valid() || !datagram.target || !datagram.target->IsValid())
            throw transport::LinkError(common::ErrorCode::INVALID_ARGUMENT);
        const common::TargetAddress& target = *datagram.target;
        if (write_closed_) throw transport::WriteClosed{};
        auto write = socket_.StartWrite();
        if (target.resolved_addr) {
            if (target.resolved_addr->is_v6() != socket_.IsIPv6())
                throw transport::LinkError(common::ErrorCode::INVALID_ARGUMENT);
            // target 借用 payload 的元数据：先取出端点，再移交 payload。
            const udp::endpoint endpoint(*target.resolved_addr, target.port);
            co_await write.SendTo(endpoint, std::move(payload));
        } else {
            auto endpoint = co_await ResolveUdpEndpoint(dns_, target, socket_, write);
            if (!endpoint) throw transport::LinkError(endpoint.error());
            co_await write.SendTo(*endpoint, std::move(payload));
        }
    }

private:
    app::DNS& dns_;
};

}  // namespace proxy
