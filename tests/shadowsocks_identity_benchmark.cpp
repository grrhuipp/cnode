#include "shadowsocks_identity_fixture.hpp"
#include "common/allocator.hpp"
#include "benchmark_memory.hpp"
#include <gtest/gtest.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <limits>

namespace {
using namespace ss_identity_test;
using benchmark::ResidentBytes;
uint64_t CpuNs() {
    timespec value{};
    Require(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) == 0);
    return uint64_t(value.tv_sec) * 1000000000 + value.tv_nsec;
}

TEST(ShadowsocksIdentityBenchmark, AuthenticationMatrix) {
    memory::ConfigureProcessAllocator();
    memory::AllocationDomain domain;
    memory::ScopedAllocationDomain lease(domain);
    const size_t iterations = [] {
        const char* value = std::getenv("CNODE_BENCH_ITERATIONS");
        return value ? std::max(size_t{1}, static_cast<size_t>(std::stoull(value))) : size_t{512};
    }();
    const auto cipher = *ss::ParseCipherMethod("2022-blake3-aes-128-gcm");
    net::io_context io;
    const size_t idle_rss = ResidentBytes();
    for (size_t count : {1u, 16u, 256u, 4096u}) {
        for (size_t groups : {0u, 1u, 4u}) {
            if (groups > count) continue;
            auto users = Users(count, cipher, groups);
            Install(users);
            const auto view = UserStore::ShadowsocksUsers(kTag);
            std::array<size_t, 3> positions{0, count / 2, count - 1};
            const auto positions_end = std::unique(positions.begin(), positions.end());
            for (auto position_it = positions.begin(); position_it != positions_end; ++position_it) {
                const size_t position = *position_it;
                Wire wire;
                Prepare(io, wire, users[position], cipher);
                size_t actual_hint = 0, wrong_hint = 0;
                const auto other_user = users[(position + 1) % count].profile.user_id;
                // Sorting must not change which credential supplies the miss.
                for (size_t i = 0; i < view.size(); ++i) {
                    if (view[i].profile.user_id == users[position].profile.user_id) actual_hint = i;
                    if (view[i].profile.user_id == other_user) wrong_hint = i;
                }
                for (const char* hint_mode : {"hit", "miss", "absent"}) {
                    if (count == 1 && std::string_view(hint_mode) == "miss") continue;
                    const size_t hint_value = std::string_view(hint_mode) == "hit" ? actual_hint
                        : std::string_view(hint_mode) == "miss" ? wrong_hint
                        : std::numeric_limits<size_t>::max();
                    for (size_t i = 0; i < 32; ++i) {
                        size_t hint = hint_value;
                        Require(bool(Authenticate(io, wire, cipher, hint)));
                    }
                    std::vector<double> latencies(iterations);
                    const auto pool_before = memory::ThreadMemoryPool().GetFootprint();
                    const size_t warm_rss = ResidentBytes();
                    benchmark::AllocationCounts counts;
                    uint64_t cpu_ns = 0;
                    size_t live_peak = 0;
                    for (size_t i = 0; i < iterations; ++i) {
                        size_t hint = hint_value;
                        benchmark::AllocationCountScope allocation_scope(counts);
                        const auto cpu_start = CpuNs();
                        const auto start = std::chrono::steady_clock::now();
                        {
                            auto result = Authenticate(io, wire, cipher, hint);
                            Require(bool(result));
                            Require(result->user->profile.user_id == users[position].profile.user_id);
                            live_peak = std::max(live_peak, domain.OutstandingAllocations());
                        }
                        const auto finish = std::chrono::steady_clock::now();
                        cpu_ns += CpuNs() - cpu_start;
                        latencies[i] = std::chrono::duration<double, std::nano>(finish - start).count();
                    }
                    const auto pool_after = memory::ThreadMemoryPool().GetFootprint();
                    const size_t after_rss = ResidentBytes();
                    const auto process_memory = benchmark::ReadProcessMemory();
                    std::sort(latencies.begin(), latencies.end());
                    double total_ns = 0;
                    for (double value : latencies) total_ns += value;
                    std::printf("ss-identity users=%zu groups=%zu input_position=%zu hint=%s n=%zu "
                        "cpu_ns=%.1f mean_ns=%.1f p50_ns=%.1f p95_ns=%.1f p99_ns=%.1f "
                        "cpp_new_calls=%.3f cpp_bytes=%.1f pmr_live_allocations_peak=%zu pool_before=%zu pool_after=%zu "
                        "idle_rss=%zu warm_rss=%zu after_rss=%zu process_peak_rss=%zu "
                        "anonymous_rss=%zu file_rss=%zu\n",
                        count, groups, position, hint_mode, iterations, double(cpu_ns) / iterations,
                        total_ns / iterations, latencies[iterations / 2],
                        latencies[(iterations - 1) * 95 / 100], latencies[(iterations - 1) * 99 / 100],
                        double(counts.cpp_calls) / iterations, double(counts.cpp_bytes) / iterations, live_peak,
                        pool_before.mapped_bytes, pool_after.mapped_bytes, idle_rss, warm_rss,
                        after_rss, process_memory.peak_resident_bytes,
                        process_memory.anonymous_resident_bytes, process_memory.file_resident_bytes);
                }
            }
            UserStore::ClearWorkerView();
        }
    }
    EXPECT_EQ(domain.OutstandingAllocations(), 0u);
}
} // namespace
