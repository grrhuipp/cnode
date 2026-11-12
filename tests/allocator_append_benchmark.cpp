// 分配与容器微基准，与守护进程使用相同的全局 mimalloc。
// - AllocatorAppendBenchmark：64 B～64 KiB 字节缓冲追加，分预留与按需增长两种模式。
// - MultiBufferBenchmark：1/8/9/16 块 MultiBuffer 所有权移交，不复制 payload。
// - BufferSpanBenchmark：分别以 span 与 MultiBuffer 为输入构建散布写描述符，覆盖内联容量
//   与溢出边界，计时前校验借用视图的地址与长度。
// - RingDequeBenchmark：每批 1/8/64 个元素填充并完全排空，预热 128 批后测量 262144/批大小 批，
//   校验 FIFO、checksum 与排空后归还存储。
// 输出 CPU/墙钟耗时；微基准不代表端到端吞吐。

#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/const_buffer_span.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <vector>

namespace {
using Bytes = std::vector<uint8_t>;
constexpr std::size_t kBytesPerWorkload = 16 * 1024 * 1024;
constexpr std::size_t kGrowingAppends = 4;
// Match the TLS operation's output bound; a 64 KiB append fills a fresh buffer.
constexpr std::size_t kOperationByteLimit = 65536;

// The memory clobber makes every append observable, including immediately before
// the operation-scoped vector is freed, under -O3 and ThinLTO.
void Observe(const Bytes& bytes) {
    asm volatile("" : : "g"(bytes.data()), "g"(bytes.size()) : "memory");
}

void Append(Bytes& output, const std::vector<uint8_t>& input) {
    const auto required = output.size() + input.size();
    if (required > output.capacity())
        output.reserve(std::min(kOperationByteLimit,
            std::max(required, output.capacity() * 2)));
    output.insert(output.end(), input.begin(), input.end());
}

int64_t CpuNanoseconds(const timespec& value) {
    return static_cast<int64_t>(value.tv_sec) * 1000000000 + value.tv_nsec;
}

TEST(AllocatorAppendBenchmark, TrackedResource) {
    for (const std::size_t append_bytes : {64u, 1024u, 16384u, 65536u}) {
        std::vector<uint8_t> input(append_bytes);
        for (std::size_t index = 0; index < input.size(); ++index)
            input[index] = static_cast<uint8_t>((index * 131 + index / 251) & 255);

        for (const bool growing : {false, true}) {
            SCOPED_TRACE(append_bytes);
            SCOPED_TRACE(growing ? "fresh-growing" : "pre-reserved");
            const std::size_t appends = growing
                ? std::min(kGrowingAppends, kOperationByteLimit / append_bytes) : 1;
            const std::size_t iterations = kBytesPerWorkload / (append_bytes * appends);
            ASSERT_GT(iterations, 0u);
            memory::CollectThreadHeap();

            // Validate the measured append path and preserved prefixes before timing.
            std::size_t sampled_capacity = 0;
            {
                Bytes probe;
                if (!growing) probe.reserve(append_bytes);
                for (std::size_t part = 0; part < appends; ++part) {
                    Append(probe, input);
                    ASSERT_EQ(probe.size(), (part + 1) * append_bytes);
                    for (std::size_t offset = 0; offset < probe.size(); offset += append_bytes)
                        ASSERT_TRUE(std::equal(input.begin(), input.end(), probe.begin() + offset));
                }
                sampled_capacity = probe.capacity();
            }

            Bytes reserved;
            if (!growing) reserved.reserve(append_bytes);
            timespec cpu_start{}, cpu_end{};
            ASSERT_EQ(::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_start), 0);
            const auto wall_start = std::chrono::steady_clock::now();
            if (growing) {
                for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
                    Bytes output;
                    for (std::size_t part = 0; part < appends; ++part) {
                        Append(output, input);
                        Observe(output);
                    }
                    // Destruction/deallocation belongs to the measured operation.
                }
            } else {
                for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
                    reserved.clear();
                    Append(reserved, input);
                    Observe(reserved);
                }
            }
            const auto wall_end = std::chrono::steady_clock::now();
            const int cpu_result = ::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end);
            ASSERT_EQ(cpu_result, 0);
            if (!growing) {
                ASSERT_EQ(reserved.size(), input.size());
                EXPECT_TRUE(std::equal(input.begin(), input.end(), reserved.begin()));
            }
            const double bytes = static_cast<double>(iterations * appends * append_bytes);
            const double wall_ns = std::chrono::duration<double, std::nano>(wall_end - wall_start).count();
            const double cpu_ns = static_cast<double>(CpuNanoseconds(cpu_end) - CpuNanoseconds(cpu_start));
            std::printf("allocator-append mode=%s append_bytes=%zu appends_per_operation=%zu "
                        "operations=%zu bytes=%.0f wall_ns_per_byte=%.3f cpu_ns_per_byte=%.3f "
                        "sample_capacity=%zu\n",
                growing ? "fresh-growing" : "pre-reserved", append_bytes, appends,
                iterations, bytes, wall_ns / bytes, cpu_ns / bytes, sampled_capacity);
        }
    }
    memory::CollectThreadHeap();
}

buf::MultiBuffer TransferBuffers(std::size_t count) {
    buf::MultiBuffer source;
    for (std::size_t index = 0; index < count; ++index) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) throw std::bad_alloc();
        buffer->Tail()[0] = static_cast<uint8_t>(index);
        buffer->Produce(1);
        source.push_back(std::move(buffer));
    }
    // Model ownership handoffs, not payload copies. Escaping each container's
    // address prevents ThinLTO from eliding the intermediate moved-from states.
    buf::MultiBuffer first(std::move(source));
    asm volatile("" : : "g"(&source), "g"(&first) : "memory");
    buf::MultiBuffer second;
    second = std::move(first);
    asm volatile("" : : "g"(&first), "g"(&second) : "memory");
    buf::MultiBuffer third(std::move(second));
    asm volatile("" : : "g"(&second), "g"(&third) : "memory");
    return third;
}

TEST(MultiBufferBenchmark, TrackedTransfers) {
    for (const std::size_t blocks : {1u, 8u, 9u, 16u}) {
        SCOPED_TRACE(blocks);
        memory::CollectThreadHeap();
        {
            auto probe = TransferBuffers(blocks);
            ASSERT_EQ(probe.size(), blocks);
            ASSERT_EQ(probe.byte_size(), blocks);
            for (std::size_t index = 0; index < blocks; ++index) {
                auto buffer = probe.pop_front();
                ASSERT_TRUE(buffer);
                ASSERT_EQ(buffer->Len(), 1u);
                ASSERT_EQ(buffer->Bytes()[0], index);
            }
            ASSERT_TRUE(probe.empty());
        }
        const std::size_t iterations = 262144 / blocks;
        timespec cpu_start{}, cpu_end{};
        ASSERT_EQ(::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_start), 0);
        const auto start = std::chrono::steady_clock::now();
        for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
            auto payload = TransferBuffers(blocks);
            payload.drop_front(blocks - 1);
            asm volatile("" : : "g"(&payload) : "memory");
        }
        const auto finish = std::chrono::steady_clock::now();
        ASSERT_EQ(::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end), 0);
        const double wall_ns = std::chrono::duration<double, std::nano>(finish - start).count();
        const double cpu_ns = static_cast<double>(CpuNanoseconds(cpu_end) - CpuNanoseconds(cpu_start));
        std::printf("multibuffer-transfer blocks=%zu operations=%zu "
                    "wall_ns_per_operation=%.3f cpu_ns_per_operation=%.3f\n",
            blocks, iterations, wall_ns / iterations, cpu_ns / iterations);
    }
    memory::CollectThreadHeap();
}

TEST(BufferSpanBenchmark, TrackedDescriptors) {
    for (const std::size_t blocks : {1u, 8u, 9u, 16u}) {
        memory::CollectThreadHeap();
        {
            auto payload = TransferBuffers(blocks);
            std::array<net::const_buffer, 16> input;
            std::size_t position = 0;
            for (const auto* buffer : payload) {
                const auto bytes = buffer->Bytes();
                input[position++] = net::buffer(bytes.data(), bytes.size());
            }
            const auto descriptors = std::span(input).first(blocks);
            for (const bool from_multibuffer : {false, true}) {
                SCOPED_TRACE(blocks);
                SCOPED_TRACE(from_multibuffer);
                {
                    common::ConstBufferSpanBuilder<8> probe;
                    if (from_multibuffer) probe.AppendMultiBuffer(payload);
                    else probe.AppendBuffers(descriptors);
                    ASSERT_EQ(probe.size(), blocks);
                    for (std::size_t index = 0; index < blocks; ++index) {
                        EXPECT_EQ(probe.Span()[index].data(), input[index].data());
                        EXPECT_EQ(probe.Span()[index].size(), input[index].size());
                    }
                }
                const std::size_t iterations = 1048576 / blocks;
                timespec cpu_start{}, cpu_end{};
                ASSERT_EQ(::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_start), 0);
                const auto start = std::chrono::steady_clock::now();
                for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
                    common::ConstBufferSpanBuilder<8> output;
                    if (from_multibuffer) output.AppendMultiBuffer(payload);
                    else output.AppendBuffers(descriptors);
                    const auto views = output.Span();
                    asm volatile("" : : "g"(views.data()), "g"(views.size()) : "memory");
                }
                const auto finish = std::chrono::steady_clock::now();
                ASSERT_EQ(::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end), 0);
                const double wall_ns = std::chrono::duration<double, std::nano>(finish - start).count();
                const double cpu_ns = static_cast<double>(CpuNanoseconds(cpu_end) - CpuNanoseconds(cpu_start));
                std::printf("buffer-span source=%s blocks=%zu operations=%zu "
                            "wall_ns_per_operation=%.3f cpu_ns_per_operation=%.3f\n",
                    from_multibuffer ? "multibuffer" : "descriptors", blocks, iterations,
                    wall_ns / iterations, cpu_ns / iterations);
            }
        }
    }
    memory::CollectThreadHeap();
}

uint64_t FillAndDrain(memory::RingDeque<uint64_t>& queue,
                     std::size_t batch, std::size_t iterations) {
    uint64_t checksum = 0;
    for (std::size_t iteration = 0; iteration < iterations; ++iteration) {
        for (std::size_t value = 0; value < batch; ++value) queue.push_back(value);
        asm volatile("" : : "g"(&queue) : "memory");
        while (!queue.empty()) {
            checksum += queue.front();
            queue.pop_front();
        }
        asm volatile("" : : "g"(&queue), "g"(checksum) : "memory");
    }
    return checksum;
}

TEST(RingDequeBenchmark, TrackedFillAndDrain) {
    for (const std::size_t batch : {1u, 8u, 64u}) {
        SCOPED_TRACE(batch);
        memory::CollectThreadHeap();
        memory::RingDeque<uint64_t> queue;
        for (std::size_t value = 0; value < batch; ++value) queue.push_back(value);
        for (std::size_t value = 0; value < batch; ++value) {
            ASSERT_EQ(queue.front(), value);
            queue.pop_front();
        }
        ASSERT_EQ(queue.capacity(), 0u);
        constexpr std::size_t warmup = 128;
        const std::size_t iterations = 262144 / batch;
        const uint64_t batch_sum = batch * (batch - 1) / 2;
        ASSERT_EQ(FillAndDrain(queue, batch, warmup), warmup * batch_sum);
        timespec cpu_start{}, cpu_end{};
        ASSERT_EQ(::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_start), 0);
        const auto start = std::chrono::steady_clock::now();
        const auto checksum = FillAndDrain(queue, batch, iterations);
        const auto finish = std::chrono::steady_clock::now();
        ASSERT_EQ(::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_end), 0);
        EXPECT_EQ(checksum, iterations * batch_sum);
        EXPECT_EQ(queue.capacity(), 0u);
        const double wall_ns = std::chrono::duration<double, std::nano>(finish - start).count();
        const double cpu_ns = static_cast<double>(CpuNanoseconds(cpu_end) - CpuNanoseconds(cpu_start));
        std::printf("ring-deque batch=%zu operations=%zu "
                    "wall_ns_per_operation=%.3f cpu_ns_per_operation=%.3f\n",
            batch, iterations, wall_ns / iterations, cpu_ns / iterations);
    }
    memory::CollectThreadHeap();
}
} // namespace
