#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "transport/internet/tcp_stream.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <asio/write.hpp>
#include <algorithm>
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
    std::size_t reads;
};

int64_t CpuNanoseconds(const timespec& value) {
    return static_cast<int64_t>(value.tv_sec) * 1000000000 + value.tv_nsec;
}

net::awaitable<Measurement> Transfer(
    TcpStream& stream, tcp::socket& peer, const std::vector<uint8_t>& payload,
    std::size_t iterations) {
    timespec cpu_start{}, cpu_end{};
    if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_start) != 0)
        throw std::runtime_error("cannot read process CPU clock");
    const auto start = std::chrono::steady_clock::now();
    std::size_t reads = 0;
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        co_await net::async_write(peer, net::buffer(payload), net::use_awaitable);
        std::size_t offset = 0;
        while (offset != payload.size()) {
            auto received = co_await stream.ReadMultiBuffer();
            if (received.empty() || received.byte_size() > payload.size() - offset)
                throw std::runtime_error("TCP benchmark changed burst boundaries");
            for (const auto* buffer : received) {
                const auto bytes = buffer->Bytes();
                if (!std::equal(bytes.begin(), bytes.end(), payload.begin() + offset))
                    throw std::runtime_error("TCP benchmark corrupted payload");
                offset += bytes.size();
            }
            ++reads;
        }
    }
    const auto finish = std::chrono::steady_clock::now();
    if (::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end) != 0)
        throw std::runtime_error("cannot read process CPU clock");
    co_return Measurement{
        std::chrono::duration<double, std::nano>(finish - start).count(),
        static_cast<double>(CpuNanoseconds(cpu_end) - CpuNanoseconds(cpu_start)), reads};
}

TEST(TcpReceiveBenchmark, VerifiedBursts) {
    memory::AllocationDomain domain;
    memory::ScopedAllocationDomain lease(domain);
    for (const std::size_t burst : {1u, 8192u, 65536u}) {
        SCOPED_TRACE(burst);
        net::io_context io;
        tcp::acceptor acceptor(io, {net::ip::address_v4::loopback(), 0});
        tcp::socket socket(io), peer(io);
        socket.open(tcp::v4());
        socket.set_option(net::socket_base::receive_buffer_size(256 * 1024));
        socket.connect(acceptor.local_endpoint());
        acceptor.accept(peer);
        TcpStream stream(std::move(socket));
        stream.SetReadTimeout(2s);
        std::vector<uint8_t> payload(burst);
        for (std::size_t index = 0; index < burst; ++index)
            payload[index] = static_cast<uint8_t>((index * 131 + index / 251) & 255);
        constexpr std::size_t iterations = 4096;
        auto exercise = [&]() -> net::awaitable<Measurement> {
            (void)co_await Transfer(stream, peer, payload, 128);
            co_return co_await Transfer(stream, peer, payload, iterations);
        };
        auto result = net::co_spawn(io, exercise(), net::use_future);
        io.run_for(30s);
        const bool finished = result.wait_for(0s) == std::future_status::ready;
        stream.Close();
        IoErrorCode ignored;
        peer.close(ignored);
        io.restart();
        io.run();
        ASSERT_TRUE(finished) << "TCP benchmark exceeded overall deadline";
        const auto measured = result.get();
        // Both real loopback endpoints and byte verification run on this thread.
        // These CPU values are not daemon-only or network-throughput measurements.
        std::printf("tcp-receive burst_bytes=%zu iterations=%zu reads=%zu "
                    "wall_ns_per_burst=%.3f cpu_ns_per_burst=%.3f\n",
            burst, iterations, measured.reads,
            measured.wall_ns / iterations, measured.cpu_ns / iterations);
    }
    EXPECT_EQ(domain.OutstandingAllocations(), 0u);
}
} // namespace
