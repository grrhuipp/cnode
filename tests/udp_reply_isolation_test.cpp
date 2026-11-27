#include <gtest/gtest.h>

#include "app/udp_ingress.hpp"
#include "datagram_only_test_inbound.hpp"
#include "transport/timeout_scheduler.hpp"

#include <asio/co_spawn.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <vector>

namespace {
using namespace std::chrono_literals;

class RejectingDatagrams final : public DatagramOnlyTestInbound {
public:
    tl::expected<proxy::InboundDatagramResult, common::ErrorCode> Process(
        const proxy::InboundDatagramRequest&) override {
        return tl::unexpected(common::ErrorCode::PROTOCOL_AUTH_FAILED);
    }
};

class PlainResponse final : public proxy::InboundDatagramResponse {
public:
    common::MultiBuffer Encode(proxy::UDPPacketView packet) override {
        common::MultiBuffer encoded;
        if (!encoded.AppendSpan(packet.data)) throw std::bad_alloc();
        return encoded;
    }
};

common::MultiBuffer Bytes(size_t size, uint8_t fill) {
    std::vector<uint8_t> bytes(size, fill);
    common::MultiBuffer payload;
    if (!payload.AppendSpan(bytes)) throw std::bad_alloc();
    return payload;
}

class UdpReplyIsolation : public ::testing::Test {
protected:
    net::io_context io;
    transport::TimeoutScheduler& scheduler = transport::TimeoutScheduler::ForIoContext(io);
    app::UdpAssociationReclaimer reclaimer{
        scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); }};
    app::UdpResourceBudget budget;
    app::UdpIngress ingress{"reply-isolation", std::make_unique<RejectingDatagrams>(),
                            reclaimer, budget, io};
    udp::socket peer{io, udp::endpoint(net::ip::address_v4::loopback(), 0)};
    app::UdpIngress::SocketStatePtr listener;
    proxy::InboundDatagramOwner owner;

    void SetUp() override {
        auto socket = app::UdpIngress::MakeSocket(io);
        socket->open(udp::v4());
        socket->bind(udp::endpoint(net::ip::address_v4::loopback(), 0));
        listener = ingress.AttachSocket(std::move(socket));
        ASSERT_NE(listener, nullptr);
        peer.non_blocking(true);
        const std::array<uint8_t, 1> bytes{3};
        ASSERT_TRUE(owner.Assign(bytes));
    }
    void TearDown() override {
        ingress.RequestStop();
        io.restart();
        bool joined = false;
        net::co_spawn(io, ingress.AsyncJoin(), [&](std::exception_ptr failure) {
            EXPECT_FALSE(failure);
            joined = true;
        });
        io.run();
        EXPECT_TRUE(joined);
    }
    std::vector<size_t> Received() {
        std::vector<size_t> sizes;
        std::vector<uint8_t> packet(65536);
        for (;;) {
            udp::endpoint sender;
            IoErrorCode ec;
            const auto size = peer.receive_from(net::buffer(packet), sender, 0, ec);
            if (ec) return sizes;
            sizes.push_back(size);
        }
    }
};

// One destination's send error (here EMSGSIZE) must not discard the replies
// other sessions queued on the same listener socket.
TEST_F(UdpReplyIsolation, SendErrorDropsOnlyItsDatagram) {
    const auto destination = peer.local_endpoint();
    ASSERT_TRUE(ingress.SendReply(listener, destination, Bytes(70000, 0x51), 0));
    ASSERT_TRUE(ingress.SendReply(listener, destination, Bytes(3, 0x52), 0));
    ASSERT_TRUE(ingress.SendReply(listener, destination, Bytes(5, 0x53), 0));
    io.run_for(100ms);
    io.restart();
    EXPECT_EQ(Received(), (std::vector<size_t>{3, 5}));
    const auto stats = ingress.GetResourceStats();
    EXPECT_EQ(stats.reply_datagrams, 0u);
    EXPECT_EQ(stats.reply_bytes, 0u);
    EXPECT_EQ(stats.active_reply_senders, 0u);
    EXPECT_EQ(budget.GetUsage().datagrams, 0u);
    EXPECT_EQ(budget.GetUsage().payload_capacity, 0u);
    EXPECT_EQ(ingress.EnqueueReply(listener, destination, Bytes(1, 0x54)),
              app::UdpIngress::ReplyEnqueueResult::StartSend)
        << "the dropped datagram left the reply sender marked running";
}

// Xray refreshes the UDP inactivity timer in both directions: a session that
// keeps receiving replies is not idle.
TEST_F(UdpReplyIsolation, DownlinkRepliesKeepAssociationActive) {
    auto session = ingress.CreateClientSession(listener,
        app::ClientSessionKey{owner, 1}, io,
        app::UdpIngress::ReplyRoute{.socket = listener,
            .response = std::make_shared<PlainResponse>(), .owner = &ingress, .worker_id = 0},
        peer.local_endpoint(), owner, std::chrono::steady_clock::now() - 900ms, 1s);
    ASSERT_NE(session, nullptr);
    auto reply = Bytes(4, 0x61);
    ASSERT_TRUE(common::SetUdpTarget(reply, common::TargetAddress("198.51.100.7", 53)));
    bool written = false;
    net::co_spawn(io, session->WriteMultiBuffer(std::move(reply)),
        [&](std::exception_ptr failure) {
            EXPECT_FALSE(failure);
            written = true;
        });
    io.run_for(400ms);
    io.restart();
    EXPECT_TRUE(written);
    EXPECT_EQ(Received(), (std::vector<size_t>{4}));
    EXPECT_FALSE(session->Closed()) << "an association receiving replies was reclaimed as idle";
    EXPECT_EQ(ingress.GetResourceStats().associations, 1u);
    // Without further traffic in either direction it still expires.
    io.run_for(900ms);
    io.restart();
    EXPECT_TRUE(session->Closed());
    EXPECT_EQ(ingress.GetResourceStats().associations, 0u);
}

}  // namespace
