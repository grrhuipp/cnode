#include <gtest/gtest.h>

#include "transport/hysteria_ingress.hpp"
#include "common/asio_types.hpp"

#include <openssl/rand.h>
#include <ngtcp2/ngtcp2.h>
#include <sys/socket.h>
#include <array>
#include <vector>

using namespace ::transport;

namespace {
class QuicDirectory : public testing::TestWithParam<bool> {};

TEST_P(QuicDirectory, ServerCidRoutesToWorkerAcrossClientPorts) {
    constexpr uint32_t kWorkers = 4;
    std::vector<net::io_context> ios(kWorkers);
    std::vector<udp::socket> sockets;
    sockets.reserve(kWorkers);
    uint16_t port = 0;

    for (uint32_t w = 0; w < kWorkers; ++w) {
        udp::socket sock(ios[w]);
        sock.open(udp::v4());
        sock.set_option(net::socket_base::reuse_address(true));
        int optval = 1;
        ASSERT_EQ(::setsockopt(sock.native_handle(), SOL_SOCKET, SO_REUSEPORT,
                               &optval, sizeof(optval)), 0);
        sock.non_blocking(true);
        sock.bind(udp::endpoint(net::ip::address_v4::loopback(), port));
        if (port == 0) port = sock.local_endpoint().port();
        ASSERT_TRUE(AttachQuicReuseportBpf(sock.native_handle(), kWorkers));
        sockets.push_back(std::move(sock));
    }

    for (uint32_t target_worker : {0u, 1u, 2u, 3u, 2u, 0u, 3u, 1u}) {
        ngtcp2_cid scid{};
        ASSERT_EQ(RAND_bytes(scid.data, kServerConnectionIdLength), 1);
        EncodeWorkerServerCid(scid, kServerConnectionIdLength, target_worker);

        SCOPED_TRACE(target_worker);
        net::io_context client_io;
        udp::socket client(client_io, udp::endpoint(net::ip::address_v4::loopback(), 0));
        const bool long_header = GetParam();
        const size_t cid_offset = long_header ? 6 : 1;
        std::vector<uint8_t> packet(cid_offset + kServerConnectionIdLength + 16, 0x42);
        packet[0] = long_header ? 0xe0 : 0x40;
        if (long_header) {
            packet[1] = 0; packet[2] = 0; packet[3] = 0; packet[4] = 1;
            packet[5] = static_cast<uint8_t>(kServerConnectionIdLength);
        }
        std::copy_n(scid.data, kServerConnectionIdLength, packet.begin() + cid_offset);
        client.send_to(net::buffer(packet), udp::endpoint(net::ip::address_v4::loopback(), port));

        size_t deliveries = 0;
        std::array<uint8_t, 128> received{};
        udp::endpoint peer;
        for (uint32_t worker = 0; worker < kWorkers; ++worker) {
            IoErrorCode error;
            const auto size = sockets[worker].receive_from(net::buffer(received), peer, 0, error);
            if (error) {
                EXPECT_EQ(error, net::error::would_block);
                continue;
            }
            ++deliveries;
            EXPECT_EQ(worker, target_worker);
            EXPECT_EQ(size, packet.size());
            EXPECT_TRUE(std::equal(packet.begin(), packet.end(), received.begin()));
        }
        EXPECT_EQ(deliveries, 1u);
    }
}

INSTANTIATE_TEST_SUITE_P(Headers, QuicDirectory, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "Long" : "Short";
    });
} // namespace
