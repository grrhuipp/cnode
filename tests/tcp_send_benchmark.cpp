#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "transport/internet/tcp_stream.hpp"

#include <asio/co_spawn.hpp>
#include <asio/read.hpp>
#include <asio/use_future.hpp>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <future>
#include <stdexcept>
#include <vector>

namespace {
using namespace std::chrono_literals;

struct Measurement {
    double wall_ns;
    double cpu_ns;
};

int64_t CpuNanoseconds(const timespec& value) {
    return static_cast<int64_t>(value.tv_sec) * 1000000000 + value.tv_nsec;
}

net::awaitable<Measurement> Transfer(
    TcpStream& stream, tcp::socket& peer, const std::vector<uint8_t>& payload,
    std::span<const net::const_buffer> buffers, std::size_t iterations) {
    std::vector<uint8_t> received(payload.size());
    timespec cpu_start{}, cpu_end{};
    if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_start) != 0)
        throw std::runtime_error("cannot read process CPU clock");
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        co_await stream.WriteBuffers(buffers);
        co_await net::async_read(peer, net::buffer(received), net::use_awaitable);
        if (received != payload)
            throw std::runtime_error("TCP send benchmark corrupted payload");
    }
    const auto finish = std::chrono::steady_clock::now();
    if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end) != 0)
        throw std::runtime_error("cannot read process CPU clock");
    co_return Measurement{
        std::chrono::duration<double, std::nano>(finish - start).count(),
        static_cast<double>(CpuNanoseconds(cpu_end) - CpuNanoseconds(cpu_start))};
}

TEST(TcpSendBenchmark, VerifiedBursts) {
    memory::AllocationDomain domain;
    memory::ScopedAllocationDomain lease(domain);
    for (const std::size_t burst : {1u, 8192u, 65536u}) {
        for (const std::size_t pieces : {1u, 8u, 16u}) {
            if (pieces > burst) continue;
            SCOPED_TRACE(burst);
            SCOPED_TRACE(pieces);
            net::io_context io;
            tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
            tcp::socket socket(io), peer(io);
            socket.open(tcp::v4());
            socket.set_option(net::socket_base::send_buffer_size(256 * 1024));
            socket.connect(acceptor.local_endpoint());
            acceptor.accept(peer);
            peer.set_option(net::socket_base::receive_buffer_size(256 * 1024));
            TcpStream stream(std::move(socket));
            stream.SetWriteTimeout(2s);
            std::vector<uint8_t> payload(burst);
            for (std::size_t index = 0; index < burst; ++index)
                payload[index] = static_cast<uint8_t>((index * 131 + index / 251) & 255);
            std::vector<net::const_buffer> buffers;
            buffers.reserve(pieces);
            for (std::size_t index = 0; index < pieces; ++index)
                buffers.emplace_back(payload.data() + index * (burst / pieces), burst / pieces);
            constexpr std::size_t iterations = 4096;
            auto exercise = [&]() -> net::awaitable<Measurement> {
                (void)co_await Transfer(stream, peer, payload, buffers, 128);
                co_return co_await Transfer(stream, peer, payload, buffers, iterations);
            };
            auto result = net::co_spawn(io, exercise(), net::use_future);
            io.run_for(30s);
            const bool finished = result.wait_for(0s) == std::future_status::ready;
            stream.Close();
            IoErrorCode ignored;
            peer.close(ignored);
            io.restart();
            io.run();
            ASSERT_TRUE(finished) << "TCP send benchmark exceeded overall deadline";
            const auto measured = result.get();
            // Both loopback endpoints and exact byte verification are measured;
            // fixture construction and receive-buffer allocation are excluded.
            std::printf("tcp-send burst_bytes=%zu pieces=%zu iterations=%zu "
                        "wall_ns_per_burst=%.3f cpu_ns_per_burst=%.3f\n",
                burst, pieces, iterations,
                measured.wall_ns / iterations, measured.cpu_ns / iterations);
        }
    }
    EXPECT_EQ(domain.OutstandingAllocations(), 0u);
}
} // namespace
