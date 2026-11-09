#include "quic_peer.hpp"

#include <condition_variable>
#include <cstdlib>
#include <iostream>
#include <sys/resource.h>

namespace cnode::e2e {
namespace {
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
constexpr size_t KiB = 1024;
constexpr size_t MiB = 1024 * KiB;
constexpr size_t WarmupBytes = 16 * KiB;
constexpr size_t MeasuredBytes = 256 * KiB;
constexpr size_t ChunkBytes = 64 * KiB;
constexpr unsigned Workers = 4;
constexpr auto IdleTimeout = 10s;

void Require(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

Milliseconds Remaining(Deadline deadline) {
    Require(Clock::now() < deadline, "HY2 benchmark deadline expired");
    return std::max(1ms, std::chrono::ceil<Milliseconds>(deadline - Clock::now()));
}

std::filesystem::path BenchmarkBinary() {
    if (const char* path = std::getenv("CNODE_BENCHMARK_BINARY")) {
        Require(*path != '\0', "CNODE_BENCHMARK_BINARY must not be empty when set");
        return std::filesystem::absolute(path);
    }
    return Binary();
}

std::string Payload() {
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

// Targets intentionally does not fit this benchmark: it starts one thread per
// accepted socket. This real TCP target instead advances every socket from the
// same nonblocking driver that pumps QUIC, with bounded work per socket/tick.
class TcpTarget {
    enum class State { Begin, Command, Upload, Download, Reply, Eof };
    struct Connection {
        Socket socket;
        State state = State::Begin;
        size_t offset = 0;
        size_t bytes = 0;
        unsigned phases = 0;
        char reply = 'R';
    };
    Socket listener_ = Socket::Listen();
    std::vector<Connection> connections_;
    const std::string& payload_;
    const bool upload_;
    const size_t expected_;
    size_t completed_ = 0;
    uint64_t verified_ = 0;

    static bool Pending() {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return true;
        throw std::system_error(errno, std::generic_category(), "HY2 benchmark TCP I/O");
    }

public:
    TcpTarget(const std::string& payload, bool upload, size_t expected)
        : payload_(payload), upload_(upload), expected_(expected) {
        connections_.reserve(expected);
    }
    uint16_t Port() const { return listener_.Port(); }
    size_t Accepted() const { return connections_.size(); }
    size_t Completed() const { return completed_; }
    uint64_t Verified() const { return verified_; }

    void Tick() {
        for (size_t accepted = 0; accepted < 32; ++accepted) {
            pollfd descriptor{listener_.Fd(), POLLIN, 0};
            const int result = ::poll(&descriptor, 1, 0);
            if (result < 0) { if (Pending()) break; }
            if (result == 0) break;
            Require((descriptor.revents & POLLIN) != 0, "TCP target listener failed");
            Require(connections_.size() < expected_, "too many real TCP targets");
            connections_.push_back({listener_.Accept(100ms)});
        }
        std::array<char, ChunkBytes> buffer{};
        for (auto& connection : connections_) {
            if (connection.socket.Fd() < 0) continue;
            auto& state = connection.state;
            if (state == State::Download || state == State::Reply) {
                const auto bytes = state == State::Reply
                    ? std::string_view(&connection.reply, 1)
                    : std::string_view(payload_).substr(connection.offset,
                        std::min(ChunkBytes, connection.bytes - connection.offset));
                const auto count = ::send(connection.socket.Fd(), bytes.data(), bytes.size(),
                    MSG_DONTWAIT | MSG_NOSIGNAL);
                if (count < 0) { if (Pending()) continue; }
                Require(count > 0, "TCP target zero-length write");
                if (state == State::Reply) state = State::Command;
                else {
                    connection.offset += static_cast<size_t>(count);
                    if (connection.offset == connection.bytes) {
                        state = State::Reply;
                        connection.reply = 'F';
                        ++connection.phases;
                    }
                }
                continue;
            }
            const size_t capacity = state == State::Upload
                ? std::min(ChunkBytes, connection.bytes - connection.offset) : 1;
            const auto count = ::recv(connection.socket.Fd(), buffer.data(), capacity, MSG_DONTWAIT);
            if (count < 0) { if (Pending()) continue; }
            if (state == State::Eof) {
                Require(count == 0, "unexpected target bytes after shutdown marker");
                connection.socket.ShutdownWrite();
                connection.socket.Close();
                ++completed_;
                continue;
            }
            Require(count > 0, "premature TCP target EOF");
            if (state == State::Upload) {
                Require(std::string_view(buffer.data(), static_cast<size_t>(count)) ==
                    std::string_view(payload_).substr(connection.offset, static_cast<size_t>(count)),
                    "TCP target upload payload mismatch");
                connection.offset += static_cast<size_t>(count);
                verified_ += static_cast<uint64_t>(count);
                if (connection.offset == connection.bytes) {
                    state = State::Reply;
                    connection.reply = 'F';
                    ++connection.phases;
                }
            } else if (state == State::Begin) {
                Require(buffer[0] == 'B', "missing TCP target readiness request");
                state = State::Reply;
            } else if (buffer[0] == 'P') {
                // Keep established sessions alive while other clients perform
                // their blocking TLS/auth handshakes. No application reply is
                // generated; QUIC ACKs still prove transport liveness.
            } else if (buffer[0] == 'D') {
                Require(connection.phases == 2, "target closed before both transfers");
                state = State::Eof;
            } else {
                Require(connection.phases < 2 &&
                    buffer[0] == (connection.phases == 0 ? 'W' : 'M'), "unexpected target phase");
                connection.bytes = connection.phases == 0 ? WarmupBytes : MeasuredBytes;
                connection.offset = 0;
                state = upload_ ? State::Upload : State::Download;
            }
        }
    }
};

// Peer construction is synchronous. Exactly one handshake thread hands off
// each authenticated peer before constructing the next; the driver continues
// pumping all earlier peers and TCP targets throughout. No Peer is accessed
// concurrently. jthread always stops/joins on failure (constructor <= 10 s).
class Handshakes {
    std::mutex mutex_;
    std::condition_variable changed_;
    std::unique_ptr<quic::Peer> pending_;
    std::exception_ptr error_;
    std::jthread thread_;
public:
    Handshakes(uint16_t port, unsigned count, Deadline deadline)
        : thread_([this, port, count, deadline](std::stop_token stop) {
            try {
                for (unsigned index = 0; index < count && !stop.stop_requested(); ++index) {
                    Remaining(deadline);
                    auto peer = std::make_unique<quic::Peer>(port);
                    std::unique_lock lock(mutex_);
                    pending_ = std::move(peer);
                    while (pending_ && !stop.stop_requested()) changed_.wait_for(lock, 10ms);
                }
            } catch (...) {
                std::lock_guard lock(mutex_);
                error_ = std::current_exception();
            }
        }) {}
    ~Handshakes() {
        thread_.request_stop();
        changed_.notify_all();
        thread_.join();
    }
    std::unique_ptr<quic::Peer> Take() {
        std::lock_guard lock(mutex_);
        if (error_) std::rethrow_exception(error_);
        auto peer = std::move(pending_);
        changed_.notify_all();
        return peer;
    }
};

struct Stream {
    int64_t id;
    size_t header_bytes = 0;
    bool ready = false;
    bool verified = false;
};
struct Client {
    std::unique_ptr<quic::Peer> peer;
    std::vector<Stream> streams;
    Deadline heartbeat = Clock::now() + 2s;
};

class Driver {
    TcpTarget& target_;
public:
    std::vector<Client> clients;
    uint64_t heartbeat_bytes = 0;
    explicit Driver(TcpTarget& target, unsigned count) : target_(target) { clients.reserve(count); }
    void Tick(Deadline deadline, bool heartbeat = true, bool allow_closed = false) {
        Remaining(deadline);
        target_.Tick();
        for (auto& client : clients) {
            client.peer->Pump(0ms);
            if (!allow_closed) Require(!client.peer->Closed(), "physical QUIC session closed early");
            if (heartbeat && Clock::now() >= client.heartbeat) {
                // Logical TCP streams have independent inactivity budgets;
                // keeping only the physical connection active is insufficient.
                for (const auto& stream : client.streams) {
                    client.peer->Send(stream.id, "P");
                    ++heartbeat_bytes;
                }
                client.heartbeat = Clock::now() + 2s;
            }
        }
    }
    void Idle(Milliseconds duration, Deadline deadline) {
        const auto end = Clock::now() + duration;
        while (Clock::now() < end) {
            Tick(deadline);
            std::this_thread::sleep_for(1ms);
        }
    }
};

Json Memory(std::string_view stage, const Child::MemorySnapshot& sample) {
    return {{"stage", stage}, {"vm_rss_bytes", sample.vm_rss_bytes},
        {"vm_hwm_bytes", sample.vm_hwm_bytes},
        {"smaps_rollup_rss_bytes", sample.smaps_rollup_rss_bytes},
        {"smaps_rollup_pss_bytes", sample.smaps_rollup_pss_bytes},
        {"smaps_rollup_anonymous_bytes", sample.smaps_rollup_anonymous_bytes},
        {"smaps_rollup_anon_huge_pages_bytes", sample.smaps_rollup_anon_huge_pages_bytes},
        {"smaps_rollup_file_pmd_mapped_bytes", sample.smaps_rollup_file_pmd_mapped_bytes}};
}

struct LoadMemory {
    size_t samples = 0;
    uint64_t maximum_rss = 0;
    uint64_t maximum_rollup_rss = 0;
    Deadline next{};
    void Sample(Child& child) {
        if (Clock::now() < next) return;
        const auto sample = child.ReadMemorySnapshot();
        ++samples;
        maximum_rss = std::max(maximum_rss, sample.vm_rss_bytes);
        maximum_rollup_rss = std::max(maximum_rollup_rss, sample.smaps_rollup_rss_bytes);
        next = Clock::now() + 100ms;
    }
};

// All physical sessions and logical streams already exist. Timing includes
// command dispatch, pumping, byte verification and /proc sampling, and stops
// only once every target completion marker has been received and checked.
// Peer retains received bytes: cap total download/connection below its 64 MiB
// budget, and compare the retained prefix once, not on every packet.
double Transfer(Driver& driver, Child& child, bool upload, std::string_view payload,
                std::string_view command, std::string_view expected, Deadline deadline,
                LoadMemory* load = nullptr) {
    for (auto& client : driver.clients)
        for (auto& stream : client.streams) stream.verified = false;
    const auto started = Clock::now();
    for (auto& client : driver.clients) {
        for (const auto& stream : client.streams) {
            client.peer->Send(stream.id, command);
            if (upload) client.peer->Send(stream.id, payload);
        }
        driver.Tick(deadline);
        if (load) load->Sample(child);
    }
    for (;;) {
        driver.Tick(deadline);
        bool complete = true;
        for (auto& client : driver.clients) {
            for (auto& stream : client.streams) {
                if (stream.verified) continue;
                if (client.peer->Received(stream.id) >= stream.header_bytes + expected.size()) {
                    Require(client.peer->PayloadEquals(stream.id, expected),
                        "HY2 client payload or target completion marker mismatch");
                    stream.verified = true;
                } else {
                    Require(!client.peer->StreamClosed(stream.id), "HY2 stream closed before completion");
                    complete = false;
                }
            }
        }
        if (complete) return std::chrono::duration<double>(Clock::now() - started).count();
        if (load) load->Sample(child);
    }
}

rusage ChildrenUsage() {
    rusage usage{};
    Require(::getrusage(RUSAGE_CHILDREN, &usage) == 0, "getrusage(RUSAGE_CHILDREN) failed");
    return usage;
}
double Seconds(timeval value) {
    return static_cast<double>(value.tv_sec) + static_cast<double>(value.tv_usec) / 1000000.0;
}

struct Workload { unsigned connections; unsigned streams; bool upload; };
class HysteriaThroughputBenchmark : public testing::TestWithParam<Workload> {};

TEST_P(HysteriaThroughputBenchmark, VerifiedTcpTransfer) {
    const auto workload = GetParam();
    const size_t streams = static_cast<size_t>(workload.connections) * workload.streams;
    rlimit descriptors{};
    Require(::getrlimit(RLIMIT_NOFILE, &descriptors) == 0, "getrlimit(RLIMIT_NOFILE) failed");
    Require(descriptors.rlim_cur >= streams + workload.connections + 64,
        "raise RLIMIT_NOFILE before benchmark (1024 physical case needs at least 2112)");
    const auto binary = BenchmarkBinary();
    const auto payload = Payload();
    const auto deadline = Clock::now() + 150s;
    TempDir root;
    TcpTarget target(payload, workload.upload, streams);
    auto reservation = Socket::BindUdp();
    const auto port = reservation.Port();
    auto inbound = quic::HysteriaInbound(port);
    // Do not inherit the fixture's 100 Mbit/s cap when studying throughput.
    inbound["settings"]["upMbps"] = 10000;
    inbound["settings"]["downMbps"] = 10000;
    Configure(root.Path(), std::move(inbound),
        {{"protocol", "freedom"}, {"settings", Json::object()}}, Workers);
    WriteJson(root.Path(), "config.json", {{"workers", Workers},
        {"timeouts", {{"handshake", 10}, {"connIdle", IdleTimeout.count()},
            {"write", 120}, {"uplinkOnly", 10}, {"downlinkOnly", 10}}},
        {"log", {{"enable", false}, {"logDir", (root.Path() / "logs").string()}}}});
    reservation.Close();

    // There is exactly one child process and no other child is reaped here.
    // The difference is daemon-only CPU over its COMPLETE lifetime, not the
    // measured transfer. ru_maxrss is intentionally not used (cumulative max).
    const auto usage_before = ChildrenUsage();
    const auto lifetime_started = Clock::now();
    Child child({binary.string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started", Remaining(deadline));
    Json memory = Json::array({Memory("startup", child.ReadMemorySnapshot())});
    Driver driver(target, workload.connections);
    const auto address = "127.0.0.1:" + std::to_string(target.Port());
    const auto establishment_started = Clock::now();
    {
        Handshakes handshakes(port, workload.connections, deadline);
        size_t ready = 0;
        while (ready != streams) {
            if (auto peer = handshakes.Take()) {
                Client client;
                client.peer = std::move(peer);
                client.streams.reserve(workload.streams);
                for (unsigned index = 0; index < workload.streams; ++index)
                    client.streams.push_back({client.peer->Open(address, "B")});
                driver.clients.push_back(std::move(client));
            }
            driver.Tick(deadline);
            for (auto& client : driver.clients) {
                for (auto& stream : client.streams) {
                    if (!stream.ready && client.peer->PayloadEquals(stream.id, "R")) {
                        stream.ready = true;
                        stream.header_bytes = client.peer->Received(stream.id) - 1;
                        ++ready;
                    }
                }
            }
        }
    }
    Require(driver.clients.size() == workload.connections && target.Accepted() == streams,
        "physical connection/logical stream establishment count mismatch");
    const double establishment = std::chrono::duration<double>(Clock::now() - establishment_started).count();
    memory.push_back(Memory("all_sessions_and_tcp_targets_ready", child.ReadMemorySnapshot()));
    std::string expected = "R";
    if (!workload.upload) expected.append(payload, 0, WarmupBytes);
    expected += 'F';
    const double warmup = Transfer(driver, child, workload.upload,
        std::string_view(payload).substr(0, WarmupBytes), "W", expected, deadline);
    memory.push_back(Memory("warmup_complete_connections_open", child.ReadMemorySnapshot()));
    if (!workload.upload) expected += payload;
    expected += 'F';
    LoadMemory load;
    const double elapsed = Transfer(driver, child, workload.upload, payload, "M", expected, deadline, &load);
    if (workload.upload)
        Require(target.Verified() == streams * (WarmupBytes + MeasuredBytes), "target verified byte count mismatch");
    memory.push_back(Memory("loaded_transfer_complete_connections_open", child.ReadMemorySnapshot()));
    driver.Idle(2s, deadline);
    memory.push_back(Memory("idle_connections_open_after_2_seconds", child.ReadMemorySnapshot()));

    for (auto& client : driver.clients)
        for (const auto& stream : client.streams) client.peer->Send(stream.id, "D", true);
    for (;;) {
        driver.Tick(deadline, false);
        bool closed = target.Completed() == streams;
        for (auto& client : driver.clients)
            for (const auto& stream : client.streams)
                closed &= client.peer->StreamClosed(stream.id);
        if (closed) break;
    }
    memory.push_back(Memory("tcp_streams_closed_quic_sessions_open", child.ReadMemorySnapshot()));
    // Peer has no CONNECTION_CLOSE API. Keep pumping until the negotiated idle
    // timeout actually closes EVERY physical QUIC session; do not label mere
    // destruction of client sockets as daemon session reclamation.
    const auto reclaim_started = Clock::now();
    const auto reclaim_deadline = std::min(deadline, reclaim_started + 30s);
    for (;;) {
        driver.Tick(reclaim_deadline, false, true);
        const bool closed = std::all_of(driver.clients.begin(), driver.clients.end(),
            [](const auto& client) { return client.peer->Closed(); });
        if (closed) break;
        std::this_thread::sleep_for(1ms);
    }
    driver.clients.clear();
    // Let daemon timer cleanup and allocator retirement settle after the peers'
    // local idle timers. RSS is a timed observation, not proof of zero live objects.
    for (const auto settle = Clock::now() + 2s; Clock::now() < settle;) {
        Remaining(deadline);
        Require(child.Running(), "daemon exited during reclamation");
        std::this_thread::sleep_for(10ms);
    }
    const double reclaim = std::chrono::duration<double>(Clock::now() - reclaim_started).count();
    memory.push_back(Memory("all_quic_peers_idle_closed_plus_2_seconds", child.ReadMemorySnapshot()));
    Require(child.Running(), "daemon exited before graceful stop");
    const int status = child.Stop(5s);
    const auto usage_after = ChildrenUsage();
    const double lifetime = std::chrono::duration<double>(Clock::now() - lifetime_started).count();
    const double user_cpu = Seconds(usage_after.ru_utime) - Seconds(usage_before.ru_utime);
    const double system_cpu = Seconds(usage_after.ru_stime) - Seconds(usage_before.ru_stime);
    const uint64_t total_bytes = streams * MeasuredBytes;
    const Json metrics{
        {"protocol", "hysteria2"}, {"transport", "tcp"}, {"binary", binary.string()},
        {"direction", workload.upload ? "upload" : "download"}, {"workers", Workers},
        {"physical_quic_connections", workload.connections}, {"tcp_streams_per_connection", workload.streams},
        {"tcp_streams_total", streams}, {"established_real_tcp_targets", target.Accepted()},
        {"completed_real_tcp_targets", target.Completed()}, {"driver_threads", 1},
        {"additional_handshake_threads_max", 1}, {"target_threads", 0},
        {"warmup_bytes_per_stream", WarmupBytes}, {"measured_bytes_per_stream", MeasuredBytes},
        {"verified_warmup_bytes", streams * WarmupBytes}, {"verified_measured_bytes", total_bytes},
        {"verification_endpoint", workload.upload ? "real_tcp_target" : "independent_quic_peer"},
        {"heartbeat_application_bytes", driver.heartbeat_bytes}, {"target_io_chunk_bytes", ChunkBytes},
        {"establishment_seconds", establishment}, {"warmup_seconds", warmup},
        {"transfer_wall_seconds", elapsed}, {"throughput_mib_per_second", total_bytes / double(MiB) / elapsed},
        {"transfer_scope", "first_phase_command_to_all_verified_payloads_and_target_completion_markers_including_driver_and_proc_sampling"},
        {"daemon_lifetime_wall_seconds", lifetime}, {"daemon_lifetime_user_cpu_seconds", user_cpu},
        {"daemon_lifetime_system_cpu_seconds", system_cpu}, {"daemon_lifetime_cpu_seconds", user_cpu + system_cpu},
        {"daemon_cpu_scope", "RUSAGE_CHILDREN_delta_one_child_after_reap_startup_handshakes_warmup_transfer_idle_reclamation_stop"},
        {"daemon_graceful_exit_code", status}, {"idle_timeout_seconds", IdleTimeout.count()},
        {"reclamation_wait_seconds", reclaim}, {"lifecycle_cycles", 1},
        {"memory", {{"scope", "daemon_pid_only_proc_status_and_smaps_rollup_non_atomic"},
            {"snapshots", memory}, {"during_load_sample_interval_ms", 100},
            {"during_load_samples", load.samples}, {"during_load_max_sampled_vm_rss_bytes", load.maximum_rss},
            {"during_load_max_sampled_rollup_rss_bytes", load.maximum_rollup_rss}}},
        {"limitations", Json::array({"single_driver_can_limit_throughput_not_daemon_capacity",
            "peer_retains_download_bytes_bounded_per_connection",
            "quic_reclamation_observed_after_idle_timeout_not_explicit_connection_close",
            "udp_datagram_throughput_not_covered", "no_migration_or_port_hopping_in_this_benchmark"})}};
    std::cout << "HY2_BENCHMARK " << metrics.dump() << '\n';
    EXPECT_EQ(status, 0) << ReadFile(child.LogPath());
}

INSTANTIATE_TEST_SUITE_P(Concurrency, HysteriaThroughputBenchmark,
    testing::Values(Workload{64, 1, true}, Workload{64, 1, false},
        Workload{256, 1, true}, Workload{256, 1, false},
        Workload{1024, 1, true}, Workload{1024, 1, false},
        Workload{1, 64, true}, Workload{1, 64, false},
        Workload{16, 64, true}, Workload{16, 64, false}),
    [](const auto& info) {
        return std::string(info.param.upload ? "Upload_" : "Download_") +
            std::to_string(info.param.connections) + "Connections_" +
            std::to_string(info.param.streams) + "StreamsEach";
    });
} // namespace
} // namespace cnode::e2e
