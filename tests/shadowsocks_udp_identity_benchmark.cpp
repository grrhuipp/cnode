#include "shadowsocks_identity_fixture.hpp"
#include "benchmark_memory.hpp"
#include "common/allocator.hpp"
#include "ss_udp.hpp"

#include <gtest/gtest.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <span>
#include <string>
#include <vector>

namespace {
using namespace ss_identity_test;
constexpr size_t kBatchSize = 32;
constexpr uint64_t kSessionId = 0x00123456789abcdeULL;

uint64_t CpuNs() {
    timespec value{};
    Require(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &value) == 0);
    return uint64_t(value.tv_sec) * 1000000000 + value.tv_nsec;
}

void Verify(const ss::SsUdpDecodeResult& result,
            const UserStore::ShadowsocksUsersView& users,
            size_t position, const TargetAddress& target,
            std::span<const uint8_t> payload, uint64_t packet_id) {
    Require(result.user_index == position);
    Require(result.target.SameEndpoint(target) && !result.forwarded);
    Require(result.session_id == kSessionId && result.packet_id == packet_id);
    const auto expected_owner = users[position].derived_key.span();
    Require(result.session_owner.size == expected_owner.size());
    Require(std::equal(expected_owner.begin(), expected_owner.end(),
                       result.session_owner.span().begin()));
    const auto datagram = buf::InspectUdpDatagram(result.payload);
    Require(datagram.Valid() && datagram.target->SameEndpoint(target) &&
            datagram.payload_size == payload.size());
    size_t offset = 0;
    for (const auto* buffer : result.payload) {
        Require(buffer != nullptr);
        const auto bytes = buffer->Bytes();
        Require(bytes.size() <= payload.size() - offset);
        Require(std::equal(bytes.begin(), bytes.end(), payload.begin() + offset));
        offset += bytes.size();
    }
    Require(offset == payload.size());
}

void RunCase(const char* cipher_name, const ss::SsCipherInfo& cipher,
             const UserStore::ShadowsocksUsersView& users, size_t groups,
             size_t position, size_t payload_size, bool deferred_replay,
             size_t iterations, memory::AllocationDomain& domain, size_t idle_rss) {
    SCOPED_TRACE(::testing::Message() << cipher_name << " users=" << users.size()
        << " groups=" << groups << " snapshot_position=" << position
        << " payload=" << payload_size << " deferred_replay=" << deferred_replay);
    const TargetAddress target("127.0.0.1", 443);
    std::array<uint8_t, 1200> payload_storage{};
    for (size_t i = 0; i < payload_storage.size(); ++i)
        payload_storage[i] = static_cast<uint8_t>(i * 29 + 17);
    const auto payload = std::span<const uint8_t>(payload_storage).first(payload_size);
    ss::KeyBytes key;
    Require(key.assign(users[position].derived_key.span()));
    std::array<ss::KeyBytes, 2> chain{};
    std::span<const ss::KeyBytes> psk_chain;
    if (!users[position].identity_key.empty()) {
        Require(chain[0].assign(users[position].identity_key.span()));
        chain[1] = key;
        psk_chain = chain;
    }
    ss::Ss2022UdpSessionState encoder;
    Require(ss::Init2022UdpSessionState(encoder, cipher, key));
    encoder.client_session_id = {0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde};
    const size_t wire_size = ss::Encode2022UdpRequestPacketTo(
        target, payload.data(), payload.size(), encoder, psk_chain, nullptr, 0);
    Require(wire_size != 0);
    // At most 32 packets live, independent of CNODE_BENCH_ITERATIONS. Re-encode
    // immediately before every short batch, outside all measurement scopes, so
    // timestamps do not age over a long case or across the whole matrix.
    std::vector<uint8_t> wire(kBatchSize * wire_size);
    std::array<uint64_t, kBatchSize> packet_ids{};
    std::vector<double> latencies(iterations);
    ss::Ss2022UdpReplayCache replay_cache;
    const auto prepare = [&](size_t count) {
        for (size_t i = 0; i < count; ++i) {
            packet_ids[i] = encoder.next_packet_id;
            Require(ss::Encode2022UdpRequestPacketTo(
                target, payload.data(), payload.size(), encoder, psk_chain,
                wire.data() + i * wire_size, wire_size) == wire_size);
        }
    };
    const auto decode = [&](size_t i, bool deferred) {
        return ss::DecodeUdpPacket(wire.data() + i * wire_size, wire_size, users,
            cipher.type, cipher.key_size, cipher.salt_size, replay_cache, deferred);
    };
    const auto authenticate = [&](size_t i, bool deferred, size_t& live_peak) {
        auto result = decode(i, deferred);
        Require(result.has_value());
        Verify(*result, users, position, target, payload, packet_ids[i]);
        live_peak = std::max(live_peak, domain.OutstandingAllocations());
        // Result/payload release belongs to the timed call, not the next packet.
    };
    size_t warm_live_peak = 0;
    prepare(kBatchSize);
    for (size_t i = 0; i < kBatchSize; ++i)
        authenticate(i, deferred_replay, warm_live_peak);
    Require(replay_cache.Size() == (deferred_replay ? 0u : 1u));

    const auto pool_before = memory::ThreadMemoryPool().GetFootprint();
    const size_t pmr_before = domain.OutstandingAllocations();
    const size_t warm_rss = benchmark::ResidentBytes();
    benchmark::AllocationCounts counts;
    uint64_t cpu_ns = 0;
    size_t live_peak = pmr_before;
    size_t final_batch_size = 0;
    for (size_t offset = 0; offset < iterations;) {
        const size_t count = std::min(kBatchSize, iterations - offset);
        prepare(count);
        {
            benchmark::AllocationCountScope allocation_scope(counts);
            // Batch process CPU includes wall-clock sampling and loop overhead,
            // but never preparation, memory probes, sorting, or row formatting.
            const auto cpu_start = CpuNs();
            for (size_t i = 0; i < count; ++i) {
                const auto start = std::chrono::steady_clock::now();
                authenticate(i, deferred_replay, live_peak);
                const auto finish = std::chrono::steady_clock::now();
                latencies[offset + i] =
                    std::chrono::duration<double, std::nano>(finish - start).count();
            }
            cpu_ns += CpuNs() - cpu_start;
        }
        Require(replay_cache.Size() == (deferred_replay ? 0u : 1u));
        offset += count;
        final_batch_size = count;
    }
    const size_t pmr_after = domain.OutstandingAllocations();
    const auto pool_after = memory::ThreadMemoryPool().GetFootprint();
    const size_t after_rss = benchmark::ResidentBytes();
    const auto process_memory = benchmark::ReadProcessMemory();

    // Behavioral controls are outside measurement. Ordinary mode has accepted
    // unique IDs throughout warmup and measurement; the most recent duplicate
    // must fail. Deferred authentication accepts duplicates without consulting
    // or populating the cache, including after an ordinary commit populates it.
    const size_t last = final_batch_size - 1;
    size_t control_live_peak = 0;
    if (deferred_replay) {
        authenticate(last, true, control_live_peak);
        authenticate(last, true, control_live_peak);
        Require(replay_cache.Size() == 0);
        authenticate(last, false, control_live_peak);
        Require(replay_cache.Size() == 1);
    }
    Require(!decode(last, false));
    authenticate(last, true, control_live_peak);
    Require(replay_cache.Size() == 1);

    std::sort(latencies.begin(), latencies.end());
    double total_ns = 0;
    for (double value : latencies) total_ns += value;
    std::printf("ss-udp-identity cipher=%s users=%zu groups=%zu snapshot_position=%zu "
        "payload_bytes=%zu replay=%s n=%zu cpu_ns=%.1f mean_ns=%.1f "
        "p50_ns=%.1f p95_ns=%.1f p99_ns=%.1f cpp_new_calls=%.3f cpp_bytes=%.1f "
        "mi_aligned_calls=%.3f pmr_before=%zu pmr_after=%zu pmr_live_allocations_peak=%zu "
        "pool_before=%zu pool_after=%zu idle_rss=%zu warm_rss=%zu after_rss=%zu "
        "process_peak_rss=%zu anonymous_rss=%zu file_rss=%zu\n",
        cipher_name, users.size(), groups, position, payload_size,
        deferred_replay ? "deferred-auth-only" : "ordinary-accept", iterations,
        double(cpu_ns) / iterations, total_ns / iterations, latencies[iterations / 2],
        latencies[(iterations - 1) * 95 / 100], latencies[(iterations - 1) * 99 / 100],
        double(counts.cpp_calls) / iterations, double(counts.cpp_bytes) / iterations,
        double(counts.aligned_calls) / iterations, pmr_before, pmr_after, live_peak,
        pool_before.mapped_bytes, pool_after.mapped_bytes, idle_rss, warm_rss, after_rss,
        process_memory.peak_resident_bytes, process_memory.anonymous_resident_bytes,
        process_memory.file_resident_bytes);
}

TEST(ShadowsocksUdpIdentityBenchmark, AuthenticationMatrix) {
    memory::ConfigureProcessAllocator();
    memory::AllocationDomain domain;
    memory::ScopedAllocationDomain lease(domain);
    const size_t iterations = [] {
        const char* value = std::getenv("CNODE_BENCH_ITERATIONS");
        return value ? std::max(size_t{1}, static_cast<size_t>(std::stoull(value))) : size_t{512};
    }();
    const size_t idle_rss = benchmark::ResidentBytes();
    {
        struct ClearView {
            ~ClearView() { UserStore::ClearWorkerView(); }
        } clear_view;
        // 112 identity + 16 no-identity deferred rows; two ordinary replay
        // controls (256 users, four groups, last position, 1200-byte payload).
        // This is codec/authentication work, NOT full UDP ingress: deferred rows
        // exclude directory/association replay commit, routing and network I/O.
        for (const char* cipher_name : {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"}) {
            const auto cipher = ss::ParseCipherMethod(cipher_name);
            ASSERT_TRUE(cipher.has_value());
            for (size_t count : {1u, 16u, 256u, 4096u}) {
                for (size_t groups : {0u, 1u, 4u, 16u}) {
                    if (groups > count || (groups == 0 && count != 1 && count != 256)) continue;
                    Install(Users(count, *cipher, groups));
                    const auto users = UserStore::ShadowsocksUsers(kTag);
                    ASSERT_EQ(users.size(), count);
                    std::array<size_t, 3> positions{0, count / 2, count - 1};
                    const auto end = std::unique(positions.begin(), positions.end());
                    for (auto it = positions.begin(); it != end; ++it) {
                        // Select credentials FROM the published immutable view,
                        // never from the fixture's pre-sort input order.
                        for (size_t payload_size : {0u, 1200u}) {
                            RunCase(cipher_name, *cipher, users, groups, *it,
                                    payload_size, true, iterations, domain, idle_rss);
                            if (count == 256 && groups == 4 && *it == count - 1 && payload_size == 1200)
                                RunCase(cipher_name, *cipher, users, groups, *it,
                                        payload_size, false, iterations, domain, idle_rss);
                        }
                    }
                    UserStore::ClearWorkerView();
                }
            }
        }
    }
    EXPECT_EQ(domain.OutstandingAllocations(), 0u);
}
} // namespace
