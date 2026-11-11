#include <gtest/gtest.h>

#include "transport/internet/hysteria/hysteria_ingress.hpp"
#include "common/asio_types.hpp"

#include <openssl/rand.h>
#include <sys/socket.h>
#include <array>
#include <stdexcept>
#include <vector>

using namespace ::transport::internet::hysteria;

namespace {
void Require(bool condition) {
    if (!condition) throw std::runtime_error("QUIC SCID routing invariant failed");
}

TEST(QuicDirectory, ScidEncodesWorkerAndCbpfRoutesShortAndLongHeaders) {
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
        Require(::setsockopt(sock.native_handle(), SOL_SOCKET, SO_REUSEPORT,
                             &optval, sizeof(optval)) == 0);
        sock.non_blocking(true);
        sock.bind(udp::endpoint(net::ip::address_v4::loopback(), port));
        if (port == 0) port = sock.local_endpoint().port();
        Require(AttachQuicReuseportBpf(sock.native_handle(), kWorkers));
        sockets.push_back(std::move(sock));
    }

    for (uint32_t target_worker : {0u, 1u, 2u, 3u, 2u, 0u, 3u, 1u}) {
        ngtcp2_cid scid{};
        Require(RAND_bytes(scid.data, kServerConnectionIdLength) == 1);
        EncodeWorkerServerCid(scid, kServerConnectionIdLength, target_worker);
        Require(scid.datalen == kServerConnectionIdLength);
        Require(scid.data[0] == kServerCidMagic0);
        Require(scid.data[1] == kServerCidMagic1);
        Require(scid.data[2] == target_worker);

        // 1. Short Header packet from a fresh ephemeral client socket (simulating NAT rebinding)
        {
            net::io_context client_io;
            udp::socket client(client_io, udp::endpoint(net::ip::address_v4::loopback(), 0));
            std::vector<uint8_t> pkt(1 + kServerConnectionIdLength + 16, 0x42);
            pkt[0] = 0x40; // Short Header
            std::copy_n(scid.data, kServerConnectionIdLength, pkt.begin() + 1);
            client.send_to(net::buffer(pkt), udp::endpoint(net::ip::address_v4::loopback(), port));

            int hit = -1;
            std::array<uint8_t, 128> buf{};
            udp::endpoint peer;
            for (uint32_t w = 0; w < kWorkers; ++w) {
                IoErrorCode ec;
                const auto n = sockets[w].receive_from(net::buffer(buf), peer, 0, ec);
                if (!ec && n > 0) hit = static_cast<int>(w);
            }
            EXPECT_EQ(hit, static_cast<int>(target_worker));
        }

        // 2. Long Header Handshake packet carrying server-issued DCID from another ephemeral port
        {
            net::io_context client_io;
            udp::socket client(client_io, udp::endpoint(net::ip::address_v4::loopback(), 0));
            std::vector<uint8_t> pkt(6 + kServerConnectionIdLength + 16, 0x55);
            pkt[0] = 0xe0; // Long Header
            pkt[1] = 0x00; pkt[2] = 0x00; pkt[3] = 0x00; pkt[4] = 0x01; // Version 1
            pkt[5] = static_cast<uint8_t>(kServerConnectionIdLength);
            std::copy_n(scid.data, kServerConnectionIdLength, pkt.begin() + 6);
            client.send_to(net::buffer(pkt), udp::endpoint(net::ip::address_v4::loopback(), port));

            int hit = -1;
            std::array<uint8_t, 128> buf{};
            udp::endpoint peer;
            for (uint32_t w = 0; w < kWorkers; ++w) {
                IoErrorCode ec;
                const auto n = sockets[w].receive_from(net::buffer(buf), peer, 0, ec);
                if (!ec && n > 0) hit = static_cast<int>(w);
            }
            EXPECT_EQ(hit, static_cast<int>(target_worker));
        }
    }
}
} // namespace
