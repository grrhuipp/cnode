#include "tls_wire.hpp"

#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <sys/resource.h>

namespace cnode::e2e {
namespace {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
using tls::Require;

constexpr size_t MiB = 1024 * 1024;
constexpr size_t WarmupBytes = MiB;
constexpr size_t MeasuredBytes = 16 * MiB;
constexpr size_t ChunkBytes = 64 * 1024;
constexpr unsigned Workers = 1;

Milliseconds Remaining(Deadline deadline) {
    const auto left = deadline - Clock::now();
    Require(left > Clock::duration::zero(), "TLS benchmark workload deadline expired");
    return std::chrono::ceil<Milliseconds>(left);
}

std::filesystem::path BenchmarkBinary() {
    if (const char* path = std::getenv("CNODE_BENCHMARK_BINARY")) {
        Require(*path != '\0', "CNODE_BENCHMARK_BINARY must not be empty when set");
        return std::filesystem::absolute(path);
    }
    return Binary();
}

std::string Payload() {
    // A fixed PRNG sequence catches corruption and misplaced chunks without
    // making payload generation part of the timed workload.
    std::string bytes(MeasuredBytes, '\0');
    uint32_t state = 0x63ac91e5;
    for (auto& byte : bytes) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        byte = static_cast<char>(state & 0xff);
    }
    return bytes;
}

template <class Stream>
void ReceiveVerified(Stream& stream, std::string_view expected, Deadline deadline) {
    size_t offset = 0;
    while (offset < expected.size()) {
        // TLS may return one 8 KiB record per read. Fill the complete chunk
        // before allocating again, so peer allocation churn cannot cap cnode.
        const auto bytes = stream.ReadExact(
            std::min(ChunkBytes, expected.size() - offset), Remaining(deadline));
        if (std::string_view(bytes) != expected.substr(offset, bytes.size()))
            throw std::runtime_error("benchmark payload mismatch at offset " + std::to_string(offset));
        offset += bytes.size();
    }
}

template <class Stream>
void SendPayload(Stream& stream, std::string_view payload, Deadline deadline) {
    while (!payload.empty()) {
        const auto chunk = payload.substr(0, ChunkBytes);
        stream.Write(chunk, Remaining(deadline));
        payload.remove_prefix(chunk.size());
    }
}

struct Workload {
    unsigned streams;
    bool upload;
};

// Client threads and TLS/VLESS connections already exist when the start gate
// opens. The interval ends at the last verified payload/completion marker,
// excluding joins and shutdown. For upload, the marker acknowledges that the
// independent TCP target has checked every byte, not merely accepted a write.
double Transfer(std::vector<std::unique_ptr<TlsSocket>>& clients, bool upload,
                std::string_view payload, std::string_view command, Deadline deadline) {
    std::mutex mutex;
    std::condition_variable changed;
    size_t ready = 0;
    bool released = false;
    bool cancelled = false;
    std::vector<Deadline> finished(clients.size());
    auto cancel = [&] {
        { std::lock_guard lock(mutex); cancelled = true; }
        changed.notify_all();
    };
    std::vector<std::unique_ptr<PeerThread>> peers;
    peers.reserve(clients.size());
    Deadline started;
    try {
        for (size_t index = 0; index < clients.size(); ++index) {
            peers.push_back(std::make_unique<PeerThread>([&, index] {
                try {
                    {
                        std::unique_lock lock(mutex);
                        ++ready;
                        changed.notify_all();
                        Require(changed.wait_until(lock, deadline, [&] { return released || cancelled; }),
                                "benchmark start gate deadline expired");
                        Require(!cancelled, "benchmark start gate cancelled");
                    }
                    auto& client = *clients[index];
                    client.Write(command, Remaining(deadline));
                    if (upload) SendPayload(client, payload, deadline);
                    else ReceiveVerified(client, payload, deadline);
                    Require(client.ReadExact(1, Remaining(deadline)) == "F", "missing target completion marker");
                    finished[index] = Clock::now();
                } catch (...) {
                    cancel();
                    throw;
                }
            }));
        }
        {
            std::unique_lock lock(mutex);
            Require(changed.wait_until(lock, deadline, [&] { return ready == clients.size() || cancelled; }),
                    "benchmark client readiness deadline expired");
            Require(!cancelled, "benchmark client failed before release");
            started = Clock::now();
            released = true;
        }
        changed.notify_all();
        for (auto& peer : peers) peer->Join();
    } catch (...) {
        cancel();
        throw;
    }
    return std::chrono::duration<double>(*std::max_element(finished.begin(), finished.end()) - started).count();
}

rusage ChildrenUsage() {
    rusage usage{};
    Require(::getrusage(RUSAGE_CHILDREN, &usage) == 0, "getrusage(RUSAGE_CHILDREN) failed");
    return usage;
}

double Seconds(timeval value) {
    return static_cast<double>(value.tv_sec) + static_cast<double>(value.tv_usec) / 1000000.0;
}

class TlsThroughputBenchmark : public testing::TestWithParam<Workload> {};

TEST_P(TlsThroughputBenchmark, VerifiedTransfer) {
    const auto workload = GetParam();
    const auto binary = BenchmarkBinary();
    const auto payload = Payload();
    const auto deadline = Clock::now() + 120s;
    TempDir root;
    std::atomic<unsigned> completed{0};
    Targets target([&](Socket& socket) {
        Require(socket.ReadExact(1, Remaining(deadline)) == "B", "missing target request");
        socket.Write("R", Remaining(deadline));
        for (const auto command : {std::string_view("W"), std::string_view("M")}) {
            Require(socket.ReadExact(1, Remaining(deadline)) == command, "unexpected target phase");
            const auto bytes = std::string_view(payload).substr(0, command == "W" ? WarmupBytes : MeasuredBytes);
            if (workload.upload) ReceiveVerified(socket, bytes, deadline);
            else SendPayload(socket, bytes, deadline);
            socket.Write("F", Remaining(deadline));
        }
        Require(socket.ReadExact(1, Remaining(deadline)) == "D", "missing target shutdown marker");
        Require(socket.Read(1, Remaining(deadline)).empty(), "unexpected bytes after benchmark transfer");
        socket.ShutdownWrite();
        ++completed;
    });
    auto reservation = Socket::Listen();
    const auto port = reservation.Port();
    tls::Config(root.Path(), Json::array({tls::Inbound(port, TlsSettings(true))}),
                Json::array({tls::Direct()}),
                {{"log", {{"loglevel", "info"}}},
                 {"timeouts", {{"handshake", 10}, {"connIdle", 120}, {"write", 120},
                               {"uplinkOnly", 10}, {"downlinkOnly", 10}}}});
    reservation.Close();

    // Child deliberately exposes no pid. No other child is spawned in this
    // test: the rusage difference after reap is this daemon's complete lifetime
    // CPU, including startup, handshakes, warmup, both phase markers and stop.
    // It is NOT CPU restricted to the measured transfer interval. ru_maxrss is
    // a cumulative maximum across children, so do not mislabel it as per-run RSS.
    const auto usage_before = ChildrenUsage();
    const auto lifetime_started = Clock::now();
    Child child({binary.string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started", Remaining(deadline));
    Require(child.Running(), "cnode exited at startup");
    const auto startup_memory = child.ReadMemorySnapshot();
    TlsContext context(false);
    std::vector<std::unique_ptr<TlsSocket>> clients;
    clients.reserve(workload.streams);
    for (unsigned index = 0; index < workload.streams; ++index) {
        auto socket = Socket::Connect(port, "127.0.0.1", Remaining(deadline));
        auto client = std::make_unique<TlsSocket>(std::move(socket), context, false, Remaining(deadline));
        client->Write(VlessRequest(target.Port(), "B"), Remaining(deadline));
        Require(client->ReadExact(3, Remaining(deadline)) == std::string("\0\0R", 3),
                "invalid VLESS response or target readiness marker");
        clients.push_back(std::move(client));
    }

    Transfer(clients, workload.upload, std::string_view(payload).substr(0, WarmupBytes), "W", deadline);
    // All warmup completion markers are verified; targets now wait for M.
    const auto warmup_memory = child.ReadMemorySnapshot();
    const double elapsed = Transfer(clients, workload.upload, payload, "M", deadline);
    // Transfer has recorded its last completion time. D/EOF has not been sent,
    // so every TLS/VLESS connection remains open during this sample.
    const auto measured_memory = child.ReadMemorySnapshot();

    for (auto& client : clients) {
        client->Write("D", Remaining(deadline));
        client->ShutdownWrite();
        Require(client->Read(1, Remaining(deadline)).empty(), "unexpected bytes after TLS transfer");
        client->Close();
    }
    Until([&] { return completed.load() == workload.streams; }, Remaining(deadline));
    target.Join();
    Require(child.Running(), "cnode exited during transfer");
    const int status = child.Stop(5s);
    const auto usage_after = ChildrenUsage();
    const double lifetime = std::chrono::duration<double>(Clock::now() - lifetime_started).count();
    ASSERT_EQ(status, 0) << ReadFile(child.LogPath());

    const auto total_bytes = MeasuredBytes * workload.streams;
    const double user_cpu = Seconds(usage_after.ru_utime) - Seconds(usage_before.ru_utime);
    const double system_cpu = Seconds(usage_after.ru_stime) - Seconds(usage_before.ru_stime);
    const auto memory_sample = [](std::string_view stage, const Child::MemorySnapshot& sample) {
        return Json{{"stage", stage}, {"vm_rss_bytes", sample.vm_rss_bytes},
                    {"vm_hwm_bytes", sample.vm_hwm_bytes},
                    {"smaps_rollup_rss_bytes", sample.smaps_rollup_rss_bytes},
                    {"smaps_rollup_pss_bytes", sample.smaps_rollup_pss_bytes},
                    {"smaps_rollup_anonymous_bytes", sample.smaps_rollup_anonymous_bytes},
                    {"smaps_rollup_anon_huge_pages_bytes", sample.smaps_rollup_anon_huge_pages_bytes},
                    {"smaps_rollup_file_pmd_mapped_bytes", sample.smaps_rollup_file_pmd_mapped_bytes}};
    };
    const Json metrics{
        {"binary", binary.string()}, {"direction", workload.upload ? "upload" : "download"},
        {"streams", workload.streams}, {"workers", Workers}, {"chunk_bytes", ChunkBytes},
        {"warmup_bytes_per_stream", WarmupBytes}, {"measured_bytes_per_stream", MeasuredBytes},
        {"measured_bytes_total", total_bytes}, {"elapsed_seconds", elapsed},
        {"throughput_mib_per_second", static_cast<double>(total_bytes) / MiB / elapsed},
        {"elapsed_scope", "start_gate_to_last_verified_payload_and_target_completion_marker"},
        {"daemon_lifetime_wall_seconds", lifetime}, {"daemon_lifetime_user_cpu_seconds", user_cpu},
        {"daemon_lifetime_system_cpu_seconds", system_cpu},
        {"daemon_lifetime_cpu_seconds", user_cpu + system_cpu},
        {"cpu_scope", "RUSAGE_CHILDREN_delta_spawn_through_reap_including_startup_handshake_warmup_transfer_shutdown"},
        {"memory", {
            {"source", "/proc/<child_pid>/status"}, {"unit", "bytes"},
            {"smaps_rollup_source", "/proc/<child_pid>/smaps_rollup"},
            {"process_scope", "single_daemon_process_excluding_harness_and_descendants"},
            {"vm_rss_scope", "resident_memory_at_each_sample_including_shared_pages"},
            {"vm_hwm_scope", "process_lifetime_high_water_mark_through_each_sample_not_transfer_only_or_post_shutdown"},
            {"smaps_rollup_scope", "per_mapping_accounting_summed_at_each_sample_not_peak"},
            {"smaps_rollup_pss_scope", "resident_pages_with_shared_pages_proportionally_attributed"},
            {"limitations", "status_RSS_estimates_rollup_walks_mappings_sequentially_sources_not_atomic_no_continuous_sampling"},
            {"samples", Json::array({
                memory_sample("server_started", startup_memory),
                memory_sample("warmup_complete_waiting_for_M", warmup_memory),
                memory_sample("measured_transfer_complete_connections_open", measured_memory)})}}}};
    std::cout << "TLS_THROUGHPUT " << metrics.dump() << '\n';
    RecordProperty("tls_throughput", metrics.dump());
}

INSTANTIATE_TEST_SUITE_P(Streams, TlsThroughputBenchmark,
    testing::Values(Workload{1, false}, Workload{8, false}, Workload{1, true}, Workload{8, true}),
    [](const testing::TestParamInfo<Workload>& info) {
        return std::string(info.param.upload ? "Upload" : "Download") + std::to_string(info.param.streams);
    });
} // namespace
} // namespace cnode::e2e
