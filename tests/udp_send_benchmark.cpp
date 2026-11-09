#include <gtest/gtest.h>

#include "benchmark_memory.hpp"
#include "common/allocator.hpp"
#include "transport/internet/datagram_socket.hpp"

#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <ctime>
#include <future>
#include <stdexcept>
#include <vector>

namespace {
using namespace std::chrono_literals;
using transport::internet::DatagramSocket;

uint64_t CpuNanoseconds() {
    timespec time{};
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &time) != 0)
        throw std::runtime_error("cannot read process CPU clock");
    return uint64_t(time.tv_sec) * 1000000000 + uint64_t(time.tv_nsec);
}

buf::MultiBuffer MakePayload(std::span<const uint8_t> bytes) {
    buf::MultiBuffer payload;
    while (!bytes.empty()) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) throw std::bad_alloc();
        const auto count = std::min(bytes.size(), size_t(buffer->Available()));
        std::copy_n(bytes.begin(), count, buffer->Tail().begin());
        buffer->Produce(static_cast<uint32_t>(count));
        bytes = bytes.subspan(count);
        payload.push_back(std::move(buffer));
    }
    return payload;
}

struct Measurement {
    double wall_ns;
    uint64_t cpu_ns;
    benchmark::AllocationCounts allocations;
};

net::awaitable<Measurement> Transfer(
    DatagramSocket& sender, udp::socket& peer, const std::vector<uint8_t>& payload,
    bool owned, size_t iterations) {
    std::vector<uint8_t> received(payload.size() + 1);
    const auto destination = peer.local_endpoint();
    const auto expected_source = sender.LocalEndpoint();
    const std::array<net::const_buffer, 1> buffers{net::buffer(payload)};
    benchmark::AllocationCounts allocations;
    benchmark::AllocationCountScope allocation_scope(allocations);
    const auto cpu_start = CpuNanoseconds();
    const auto start = std::chrono::steady_clock::now();
    for (size_t iteration = 0; iteration < iterations; ++iteration) {
        {
            auto write = sender.StartWrite();
            if (owned) co_await write.SendTo(destination, MakePayload(payload));
            else co_await write.SendTo(destination, buffers);
        }
        udp::endpoint source;
        const auto size = co_await peer.async_receive_from(
            net::buffer(received), source, net::use_awaitable);
        if (size != payload.size() || source != expected_source ||
            !std::equal(payload.begin(), payload.end(), received.begin()))
            throw std::runtime_error("UDP send benchmark changed payload or source");
    }
    const auto finish = std::chrono::steady_clock::now();
    const auto cpu_end = CpuNanoseconds();
    co_return Measurement{
        std::chrono::duration<double, std::nano>(finish - start).count(),
        cpu_end - cpu_start, allocations};
}

TEST(UdpSendBenchmark, VerifiedDatagrams) {
    memory::ConfigureProcessAllocator();
    memory::AllocationDomain domain;
    memory::ScopedAllocationDomain lease(domain);
    for (const size_t size : {0u, 1u, 1200u, 60000u}) {
        for (const bool owned : {false, true}) {
            SCOPED_TRACE(::testing::Message() << "bytes=" << size << " owned=" << owned);
            net::io_context io;
            DatagramSocket sender(io, net::ip::address_v4::loopback());
            sender.SetWriteTimeout(2s);
            udp::socket peer(io, {net::ip::address_v4::loopback(), 0});
            std::vector<uint8_t> payload(size);
            for (size_t i = 0; i < size; ++i)
                payload[i] = static_cast<uint8_t>(i * 131 + i / 251);
            constexpr size_t iterations = 4096;
            size_t pool_before = 0;
            size_t warm_rss = 0;
            auto exercise = [&]() -> net::awaitable<Measurement> {
                (void)co_await Transfer(sender, peer, payload, owned, 128);
                pool_before = memory::ThreadMemoryPool().GetFootprint().mapped_bytes;
                warm_rss = benchmark::ResidentBytes();
                co_return co_await Transfer(sender, peer, payload, owned, iterations);
            };
            auto result = net::co_spawn(io, exercise(), net::use_future);
            io.run_for(30s);
            const bool finished = result.wait_for(0s) == std::future_status::ready;
            sender.Close();
            IoErrorCode ignored;
            peer.close(ignored);
            io.restart();
            io.run();
            ASSERT_TRUE(finished) << "UDP send benchmark exceeded overall deadline";
            const auto measured = result.get();
            const auto pool_after = memory::ThreadMemoryPool().GetFootprint().mapped_bytes;
            const auto process_memory = benchmark::ReadProcessMemory();
            // Both endpoints and exact verification are timed. The owned path
            // also includes payload construction and release, not just sendto.
            std::printf("udp-send payload_bytes=%zu owned=%d iterations=%zu "
                "wall_ns=%.3f cpu_ns=%.3f cpp_new_calls=%.3f cpp_bytes=%.3f "
                "mi_aligned_calls=%.3f pool_before=%zu pool_after=%zu "
                "warm_rss=%zu after_rss=%zu process_peak_rss=%zu anonymous_rss=%zu file_rss=%zu\n",
                size, owned, iterations, measured.wall_ns / iterations,
                double(measured.cpu_ns) / iterations,
                double(measured.allocations.cpp_calls) / iterations,
                double(measured.allocations.cpp_bytes) / iterations,
                double(measured.allocations.aligned_calls) / iterations,
                pool_before, pool_after, warm_rss, benchmark::ResidentBytes(),
                process_memory.peak_resident_bytes, process_memory.anonymous_resident_bytes,
                process_memory.file_resident_bytes);
        }
    }
    EXPECT_EQ(domain.OutstandingAllocations(), 0u);
}
} // namespace
