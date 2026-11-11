// 运行时统计基准：先建立真实 VLESS → Freedom 回环链路，覆盖 0/1/64/512 条物理连接、
// 有/无资源统计，预热 16 轮后采集 64/256 轮。计时只包含 Worker::CollectRuntimeStats 与结果校验，
// 不含建连、载荷转发和停机。
// 输出 CPU、延迟分位数和进程 RSS/峰值，并区分匿名页与文件页；峰值读取 /proc/self/status 的
// VmHWM，包含准备阶段，RSS 不代表单个 Worker 的占用。分配计数只统计被拦截的 throwing C++ new
// 与 mi_malloc_aligned 入口，不等于全部分配，两类不能相加。用 CTest 运行使每个参数位于独立进程。

#include <gtest/gtest.h>

#include "runtime_sampling_fixture.hpp"
#include "common/allocator.hpp"
#include "benchmark_memory.hpp"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <ctime>
#include <tuple>
#include <asio/steady_timer.hpp>

namespace {
using runtime_sampling::Require;
using benchmark::ResidentBytes;

uint64_t CpuNanoseconds() {
    timespec value{};
    Require(::clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) == 0, "CPU clock unavailable");
    return static_cast<uint64_t>(value.tv_sec) * 1000000000 + value.tv_nsec;
}


using Workload = std::tuple<size_t, size_t, bool>;
class RuntimeSamplingBenchmark : public testing::TestWithParam<Workload> {};

TEST_P(RuntimeSamplingBenchmark, EstablishedVlessSessions) {
    const auto [sessions, rounds, resources] = GetParam();
    runtime_sampling::Fixture fixture;
    fixture.Run([&]() -> net::awaitable<void> {
        fixture.clients.reserve(sessions);
        fixture.peers.reserve(sessions);
        for (size_t index = 0; index < sessions; ++index) co_await fixture.Open();
        const auto idle = co_await fixture.WaitActive(sessions);
        Require(idle.stats.connections_total == sessions, "benchmark did not establish requested sessions");
        const auto idle_rss = ResidentBytes();
        constexpr size_t warmup = 16;
        for (size_t index = 0; index < warmup; ++index)
            (void)fixture.worker.CollectRuntimeStats(resources);
        std::vector<double> latency(rounds);
        const auto warm_rss = ResidentBytes();
        benchmark::AllocationCounts counts;
        const auto cpu_start = CpuNanoseconds();
        const auto start = std::chrono::steady_clock::now();
        uint64_t checksum = 0;
        {
            benchmark::AllocationCountScope allocation_scope(counts);
            for (size_t index = 0; index < rounds; ++index) {
                const auto sample_start = std::chrono::steady_clock::now();
                const auto sample = fixture.worker.CollectRuntimeStats(resources);
                latency[index] = std::chrono::duration<double, std::nano>(
                    std::chrono::steady_clock::now() - sample_start).count();
                Require(sample.active_connections == sessions && sample.stats.connections_total == sessions,
                        "collection lost an established session");
                Require(sample.resources.has_value() == resources, "resource flag was not preserved");
                checksum += sample.stats.connections_total + sample.active_connections;
            }
        }
        const auto finish = std::chrono::steady_clock::now();
        const auto cpu_finish = CpuNanoseconds();
        const auto after_rss = ResidentBytes();
        const auto process_memory = benchmark::ReadProcessMemory();
        std::sort(latency.begin(), latency.end());
        const auto wall_ns = std::chrono::duration<double, std::nano>(finish - start).count();
        std::printf("runtime-sampling sessions=%zu rounds=%zu resources=%u warmup=%zu "
                    "scope=worker_collect_only wall_ns_per_sample=%.3f cpu_ns_per_sample=%.3f "
                    "p50_ns=%.3f p95_ns=%.3f max_ns=%.3f cxx_new_calls=%" PRIu64 " "
                    "mi_aligned_calls=%" PRIu64 " idle_rss_bytes=%zu warm_rss_bytes=%zu "
                    "after_rss_bytes=%zu process_peak_rss_bytes=%zu anonymous_rss_bytes=%zu "
                    "file_rss_bytes=%zu checksum=%" PRIu64 "\n",
            sessions, rounds, static_cast<unsigned>(resources), warmup,
            wall_ns / rounds, static_cast<double>(cpu_finish - cpu_start) / rounds,
            latency[rounds / 2], latency[(rounds * 95 - 1) / 100], latency.back(),
            counts.cpp_calls, counts.aligned_calls, idle_rss, warm_rss, after_rss,
            process_memory.peak_resident_bytes, process_memory.anonymous_resident_bytes,
            process_memory.file_resident_bytes,
            checksum);
        // Setup, authentication, payload verification and shutdown are outside
        // timing. Run each parameter in a fresh process for comparable peak RSS.
        co_return;
    });
}

INSTANTIATE_TEST_SUITE_P(SessionCountsAndRounds, RuntimeSamplingBenchmark,
    testing::Combine(testing::Values(size_t{0}, size_t{1}, size_t{64}, size_t{512}),
                     testing::Values(size_t{64}, size_t{256}), testing::Bool()));
} // namespace
