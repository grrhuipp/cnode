// 全协议真实进程端到端吞吐基准：覆盖 Freedom、VMess（AES-128-GCM / ChaCha20-Poly1305 / None）、
// VLESS（TCP / TLS / Vision / REALITY / WS / HTTPUpgrade / gRPC / H2 / XHTTP）、Trojan（TLS）、
// Shadowsocks（AES-256-GCM / ChaCha20-Poly1305 / 2022-AES-128 / 2022-AES-256 / 2022-ChaCha20）、
// AnyTLS（TLS 会话池）的 TCP 上传/下载吞吐，以及 Freedom、VMess、VLESS（XUDP）、Trojan、
// Shadowsocks（原生 UDP / 2022 原生 UDP / UoT）、AnyTLS（UoT）、Hysteria2（QUIC Datagram）的 UDP 吞吐。
// 输出与 tls_throughput_benchmark 一致的完整生命周期 CPU、吞吐及 /proc 驻留内存快照。

#include "quic_peer.hpp"
#include "tls_wire.hpp"
#include "udp_wire.hpp"

#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/mldsa.h>

#include <algorithm>
#include <atomic>
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
constexpr size_t TcpWarmupBytes = 512 * KiB;
constexpr size_t TcpMeasuredBytes = 4 * MiB;
constexpr size_t TcpChunkBytes = 64 * KiB;
constexpr size_t UdpPayloadBytes = 1024;
constexpr size_t UdpWarmupPackets = 32;
constexpr size_t UdpMeasuredPackets = 256;
constexpr unsigned Workers = 1;

constexpr std::string_view kRealityPrivateKey = "6Epi9xRmv1RL-Kiqrj6Fl523a9eagFMTc-oyzGC5IU8";
constexpr std::string_view kRealityPublicKey = "VPI8d_RKeP4K4eF69AY-QjrV325NaSe03p-a0zkcH3Q";
constexpr std::string_view kRealityShortId = "0123456789abcdef";

Milliseconds Remaining(Deadline deadline) {
    Require(Clock::now() < deadline, "protocol benchmark deadline expired");
    return std::max(1ms, std::chrono::ceil<Milliseconds>(deadline - Clock::now()));
}

std::filesystem::path BenchmarkBinary() {
    if (const char* path = std::getenv("CNODE_BENCHMARK_BINARY")) {
        Require(*path != '\0', "CNODE_BENCHMARK_BINARY must not be empty when set");
        return std::filesystem::absolute(path);
    }
    return Binary();
}

std::string Payload(size_t size) {
    std::string bytes(size, '\0');
    uint32_t state = 0x6d2b79f5U;
    for (char& ch : bytes) {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        ch = static_cast<char>(state & 0xff);
    }
    return bytes;
}

template <class Stream>
void ReceiveVerified(Stream& stream, std::string_view expected, Deadline deadline) {
    for (size_t offset = 0; offset < expected.size(); offset += TcpChunkBytes) {
        const size_t size = std::min(TcpChunkBytes, expected.size() - offset);
        const auto actual = stream.ReadExact(size, Remaining(deadline));
        Require(actual == expected.substr(offset, size), "protocol benchmark payload mismatch");
    }
}

template <class Stream>
void SendPayload(Stream& stream, std::string_view payload, Deadline deadline) {
    for (size_t offset = 0; offset < payload.size(); offset += TcpChunkBytes) {
        stream.Write(payload.substr(offset, std::min(TcpChunkBytes, payload.size() - offset)),
                     Remaining(deadline));
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

Json MemorySample(std::string_view stage, const Child::MemorySnapshot& sample) {
    return Json{{"stage", stage},
                {"vm_rss_bytes", sample.vm_rss_bytes},
                {"vm_hwm_bytes", sample.vm_hwm_bytes},
                {"smaps_rollup_rss_bytes", sample.smaps_rollup_rss_bytes},
                {"smaps_rollup_pss_bytes", sample.smaps_rollup_pss_bytes},
                {"smaps_rollup_anonymous_bytes", sample.smaps_rollup_anonymous_bytes}};
}

struct TcpProtocolCase {
    std::string_view name;
    std::string_view protocol;
    std::string_view variant;
    bool upload;
};

struct HopTopology {
    Json inbounds = Json::array();
    Json outbounds = Json::array();
};

HopTopology BuildProtocolHop(std::string_view protocol,
                             std::string_view variant,
                             uint16_t entry_port,
                             uint16_t hop_port,
                             uint16_t fallback_port) {
    HopTopology topo;
    if (protocol == "freedom") {
        topo.inbounds.push_back({{"tag", "entry"},
                                 {"protocol", "vless"},
                                 {"listen", "127.0.0.1"},
                                 {"port", entry_port},
                                 {"outboundTag", "direct"},
                                 {"settings", {{"clients", {{{"id", UserId}}}}}},
                                 {"sniffing", {{"enabled", false}}}});
        topo.outbounds.push_back(tls::Direct());
        return topo;
    }

    topo.inbounds.push_back({{"tag", "entry"},
                             {"protocol", "vless"},
                             {"listen", "127.0.0.1"},
                             {"port", entry_port},
                             {"outboundTag", "proto-out"},
                             {"settings", {{"clients", {{{"id", UserId}}}}}},
                             {"sniffing", {{"enabled", false}}}});

    Json server_stream = {{"network", "tcp"}, {"security", "none"}};
    Json client_stream = {{"network", "tcp"}, {"security", "none"}};

    if (variant == "tls" || variant == "vision" || protocol == "trojan" || protocol == "anytls") {
        server_stream = TlsSettings(true);
        client_stream = TlsSettings(false);
    } else if (variant == "reality") {
        server_stream = {
            {"network", "tcp"},
            {"security", "reality"},
            {"realitySettings",
             {{"dest", "127.0.0.1:" + std::to_string(fallback_port)},
              {"xver", 0},
              {"serverNames", {"example.com"}},
              {"privateKey", kRealityPrivateKey},
              {"shortIds", {kRealityShortId}}}}};
        client_stream = {
            {"network", "tcp"},
            {"security", "reality"},
            {"realitySettings",
             {{"serverName", "example.com"},
              {"publicKey", kRealityPublicKey},
              {"shortId", kRealityShortId},
              {"fingerprint", "chrome"}}}};
    } else if (variant == "ws") {
        server_stream = {{"network", "ws"}, {"security", "none"}, {"wsSettings", {{"path", "/ws"}}}};
        client_stream = {{"network", "ws"}, {"security", "none"}, {"wsSettings", {{"path", "/ws"}}}};
    } else if (variant == "httpupgrade") {
        server_stream = {{"network", "httpupgrade"},
                         {"security", "none"},
                         {"httpupgradeSettings", {{"path", "/up"}}}};
        client_stream = {{"network", "httpupgrade"},
                         {"security", "none"},
                         {"httpupgradeSettings", {{"path", "/up"}}}};
    } else if (variant == "grpc") {
        server_stream = {{"network", "grpc"},
                         {"security", "none"},
                         {"grpcSettings", {{"serviceName", "bench"}}}};
        client_stream = {{"network", "grpc"},
                         {"security", "none"},
                         {"grpcSettings", {{"serviceName", "bench"}}}};
    } else if (variant == "h2") {
        server_stream = TlsSettings(true);
        server_stream["network"] = "h2";
        server_stream["httpSettings"] = {{"path", "/h2"}};
        client_stream = TlsSettings(false);
        client_stream["network"] = "h2";
        client_stream["httpSettings"] = {{"path", "/h2"}};
    } else if (variant == "xhttp") {
        server_stream = TlsSettings(true);
        server_stream["network"] = "xhttp";
        server_stream["xhttpSettings"] = {{"path", "/xhttp"}, {"mode", "stream-one"}};
        client_stream = TlsSettings(false);
        client_stream["network"] = "xhttp";
        client_stream["xhttpSettings"] = {{"path", "/xhttp"}, {"mode", "stream-one"}};
    }

    Json proto_in = {{"tag", "proto-in"},
                     {"protocol", protocol},
                     {"listen", "127.0.0.1"},
                     {"port", hop_port},
                     {"outboundTag", "direct"},
                     {"sniffing", {{"enabled", false}}},
                     {"streamSettings", server_stream}};
    Json proto_out = {{"tag", "proto-out"},
                      {"protocol", protocol},
                      {"streamSettings", client_stream}};

    if (protocol == "vmess") {
        proto_in["settings"] = {{"clients", {{{"id", UserId}}}}};
        proto_out["settings"] = {{"address", "127.0.0.1"},
                                 {"port", hop_port},
                                 {"id", UserId},
                                 {"security", variant}};
    } else if (protocol == "vless") {
        const std::string flow = variant == "vision" ? "xtls-rprx-vision" : "";
        Json client_entry = {{"id", UserId}};
        if (!flow.empty()) client_entry["flow"] = flow;
        std::string decryption = "none";
        std::string encryption = "none";
        if (variant == "encryption") {
            auto fixture_key = [](std::string_view hex) {
                std::string bytes;
                for (size_t offset = 0; offset < hex.size(); offset += 2)
                    bytes += static_cast<char>(std::stoul(std::string(hex.substr(offset, 2)), nullptr, 16));
                std::string encoded = udp::Base64(bytes);
                while (encoded.ends_with('=')) encoded.pop_back();
                std::replace(encoded.begin(), encoded.end(), '+', '-');
                std::replace(encoded.begin(), encoded.end(), '/', '_');
                return encoded;
            };
            decryption = "mlkem768x25519plus.native.600s." +
                fixture_key("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            encryption = "mlkem768x25519plus.native.0rtt." +
                fixture_key("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        }
        proto_in["settings"] = {{"clients", Json::array({client_entry})}, {"decryption", decryption}};
        proto_out["settings"] = {{"address", "127.0.0.1"},
                                 {"port", hop_port},
                                 {"id", UserId},
                                 {"encryption", encryption}};
        if (!flow.empty()) proto_out["settings"]["flow"] = flow;
    } else if (protocol == "trojan") {
        proto_in["settings"] = {{"clients", {{{"password", "secret"}}}}};
        proto_out["settings"] = {{"address", "127.0.0.1"},
                                 {"port", hop_port},
                                 {"password", "secret"}};
    } else if (protocol == "shadowsocks") {
        std::string method(variant);
        bool uot = false;
        if (variant == "uot") {
            method = "aes-256-gcm";
            uot = true;
        }
        std::string password = "secret-password";
        if (method.starts_with("2022-")) {
            const size_t key_len = method.find("128") != std::string::npos ? 16 : 32;
            password = udp::Base64(udp::Sequence(key_len, 1));
        }
        proto_in["settings"] = {{"method", method},
                                {"clients", {{{"password", password}}}}};
        proto_out["settings"] = {{"address", "127.0.0.1"},
                                 {"port", hop_port},
                                 {"method", method},
                                 {"password", password}};
        if (uot) proto_out["settings"]["uot"] = true;
    } else if (protocol == "anytls") {
        proto_in["settings"] = {{"clients", {{{"password", "secret"}}}}};
        proto_out["settings"] = {{"address", "127.0.0.1"},
                                 {"port", hop_port},
                                 {"password", "secret"}};
    }

    topo.inbounds.push_back(std::move(proto_in));
    topo.outbounds.push_back(std::move(proto_out));
    topo.outbounds.push_back(tls::Direct());
    return topo;
}

class ProtocolTcpThroughputBenchmark : public testing::TestWithParam<TcpProtocolCase> {};

TEST_P(ProtocolTcpThroughputBenchmark, VerifiedTransfer) {
    const auto tc = GetParam();
    const auto binary = BenchmarkBinary();
    const auto payload = Payload(TcpMeasuredBytes);
    const auto deadline = Clock::now() + 90s;
    TempDir root;
    std::atomic<unsigned> completed{0};

    Targets target([&](Socket& socket) {
        Require(socket.ReadExact(1, Remaining(deadline)) == "B", "missing target request");
        socket.Write("R", Remaining(deadline));
        for (const auto command : {std::string_view("W"), std::string_view("M")}) {
            Require(socket.ReadExact(1, Remaining(deadline)) == command, "unexpected target phase");
            const auto bytes = std::string_view(payload).substr(
                0, command == "W" ? TcpWarmupBytes : TcpMeasuredBytes);
            if (tc.upload) ReceiveVerified(socket, bytes, deadline);
            else SendPayload(socket, bytes, deadline);
            socket.Write("F", Remaining(deadline));
        }
        Require(socket.ReadExact(1, Remaining(deadline)) == "D", "missing target shutdown marker");
        Require(socket.Read(1, Remaining(deadline)).empty(), "unexpected bytes after transfer");
        socket.ShutdownWrite();
        ++completed;
    });

    auto entry_res = Socket::ReserveTcp();
    auto hop_res = Socket::ReserveTcp();
    auto fallback_listener = Socket::Listen();
    const auto topo = BuildProtocolHop(
        tc.protocol, tc.variant, entry_res.Port(), hop_res.Port(), fallback_listener.Port());

    tls::Config(root.Path(), topo.inbounds, topo.outbounds,
                {{"log", {{"loglevel", "info"}}},
                 {"timeouts", {{"handshake", 10}, {"connIdle", 60}, {"write", 60},
                               {"uplinkOnly", 10}, {"downlinkOnly", 10}}}});

    const auto usage_before = ChildrenUsage();
    const auto lifetime_started = Clock::now();
    Child child({binary.string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started", Remaining(deadline));
    const auto startup_memory = child.ReadMemorySnapshot();

    auto client = Socket::Connect(entry_res.Port(), "127.0.0.1", Remaining(deadline));
    client.Write(VlessRequest(target.Port(), "B"), Remaining(deadline));
    Require(client.ReadExact(3, Remaining(deadline)) == std::string("\0\0R", 3),
            "invalid entry VLESS response or target readiness marker");

    auto run_phase = [&](std::string_view cmd, std::string_view phase_payload) {
        const auto started = Clock::now();
        client.Write(cmd, Remaining(deadline));
        if (tc.upload) SendPayload(client, phase_payload, deadline);
        else ReceiveVerified(client, phase_payload, deadline);
        Require(client.ReadExact(1, Remaining(deadline)) == "F", "missing completion marker");
        return std::chrono::duration<double>(Clock::now() - started).count();
    };

    run_phase("W", std::string_view(payload).substr(0, TcpWarmupBytes));
    const auto warmup_memory = child.ReadMemorySnapshot();
    const double elapsed = run_phase("M", payload);
    const auto measured_memory = child.ReadMemorySnapshot();

    client.Write("D", Remaining(deadline));
    client.ShutdownWrite();
    Require(client.Read(1, Remaining(deadline)).empty(), "unexpected trailing bytes");
    client.Close();

    Until([&] { return completed.load() == 1u; }, Remaining(deadline));
    target.Join();
    const int status = child.Stop(5s);
    const auto usage_after = ChildrenUsage();
    const double lifetime = std::chrono::duration<double>(Clock::now() - lifetime_started).count();
    ASSERT_EQ(status, 0) << ReadFile(child.LogPath());

    const double user_cpu = Seconds(usage_after.ru_utime) - Seconds(usage_before.ru_utime);
    const double system_cpu = Seconds(usage_after.ru_stime) - Seconds(usage_before.ru_stime);
    const Json metrics{
        {"case", tc.name},
        {"protocol", tc.protocol},
        {"variant", tc.variant},
        {"transport", "tcp"},
        {"direction", tc.upload ? "upload" : "download"},
        {"measured_bytes_total", TcpMeasuredBytes},
        {"elapsed_seconds", elapsed},
        {"throughput_mib_per_second", static_cast<double>(TcpMeasuredBytes) / MiB / elapsed},
        {"daemon_lifetime_wall_seconds", lifetime},
        {"daemon_lifetime_user_cpu_seconds", user_cpu},
        {"daemon_lifetime_system_cpu_seconds", system_cpu},
        {"daemon_lifetime_cpu_seconds", user_cpu + system_cpu},
        {"memory", Json::array({
            MemorySample("server_started", startup_memory),
            MemorySample("warmup_complete", warmup_memory),
            MemorySample("measured_complete", measured_memory)})}};
    std::cout << "PROTOCOL_TCP_BENCHMARK " << metrics.dump() << '\n';
}

constexpr TcpProtocolCase kTcpCases[] = {
    {"Freedom_Upload", "freedom", "direct", true},
    {"Freedom_Download", "freedom", "direct", false},
    {"Vmess_Aes128Gcm_Upload", "vmess", "aes-128-gcm", true},
    {"Vmess_Aes128Gcm_Download", "vmess", "aes-128-gcm", false},
    {"Vmess_Chacha20Poly1305_Upload", "vmess", "chacha20-poly1305", true},
    {"Vmess_Chacha20Poly1305_Download", "vmess", "chacha20-poly1305", false},
    {"Vmess_None_Upload", "vmess", "none", true},
    {"Vmess_None_Download", "vmess", "none", false},
    {"Vless_Plain_Upload", "vless", "plain", true},
    {"Vless_Plain_Download", "vless", "plain", false},
    {"Vless_Tls_Upload", "vless", "tls", true},
    {"Vless_Tls_Download", "vless", "tls", false},
    {"Vless_Vision_Upload", "vless", "vision", true},
    {"Vless_Vision_Download", "vless", "vision", false},
    {"Vless_Encryption_Upload", "vless", "encryption", true},
    {"Vless_Encryption_Download", "vless", "encryption", false},
    {"Vless_Reality_Upload", "vless", "reality", true},
    {"Vless_Reality_Download", "vless", "reality", false},
    {"Vless_Ws_Upload", "vless", "ws", true},
    {"Vless_Ws_Download", "vless", "ws", false},
    {"Vless_HttpUpgrade_Upload", "vless", "httpupgrade", true},
    {"Vless_HttpUpgrade_Download", "vless", "httpupgrade", false},
    {"Vless_Grpc_Upload", "vless", "grpc", true},
    {"Vless_Grpc_Download", "vless", "grpc", false},
    {"Vless_H2_Upload", "vless", "h2", true},
    {"Vless_H2_Download", "vless", "h2", false},
    {"Vless_XHttp_Upload", "vless", "xhttp", true},
    {"Vless_XHttp_Download", "vless", "xhttp", false},
    {"Trojan_Tls_Upload", "trojan", "tls", true},
    {"Trojan_Tls_Download", "trojan", "tls", false},
    {"Shadowsocks_Aes256Gcm_Upload", "shadowsocks", "aes-256-gcm", true},
    {"Shadowsocks_Aes256Gcm_Download", "shadowsocks", "aes-256-gcm", false},
    {"Shadowsocks_Chacha20Poly1305_Upload", "shadowsocks", "chacha20-ietf-poly1305", true},
    {"Shadowsocks_Chacha20Poly1305_Download", "shadowsocks", "chacha20-ietf-poly1305", false},
    {"Shadowsocks_2022Aes128Gcm_Upload", "shadowsocks", "2022-blake3-aes-128-gcm", true},
    {"Shadowsocks_2022Aes128Gcm_Download", "shadowsocks", "2022-blake3-aes-128-gcm", false},
    {"Shadowsocks_2022Aes256Gcm_Upload", "shadowsocks", "2022-blake3-aes-256-gcm", true},
    {"Shadowsocks_2022Aes256Gcm_Download", "shadowsocks", "2022-blake3-aes-256-gcm", false},
    {"Shadowsocks_2022Chacha20Poly1305_Upload", "shadowsocks", "2022-blake3-chacha20-poly1305", true},
    {"Shadowsocks_2022Chacha20Poly1305_Download", "shadowsocks", "2022-blake3-chacha20-poly1305", false},
    {"AnyTls_Tls_Upload", "anytls", "tls", true},
    {"AnyTls_Tls_Download", "anytls", "tls", false},
};

INSTANTIATE_TEST_SUITE_P(
    AllProtocolsTcp,
    ProtocolTcpThroughputBenchmark,
    testing::ValuesIn(kTcpCases),
    [](const testing::TestParamInfo<TcpProtocolCase>& info) {
        return std::string(info.param.name);
    });

struct UdpProtocolCase {
    std::string_view name;
    std::string_view protocol;
    std::string_view variant;
};

class ProtocolUdpThroughputBenchmark : public testing::TestWithParam<UdpProtocolCase> {};

TEST_P(ProtocolUdpThroughputBenchmark, VerifiedDatagramTransfer) {
    const auto uc = GetParam();
    const auto binary = BenchmarkBinary();
    const auto datagram_payload = Payload(UdpPayloadBytes);
    const auto deadline = Clock::now() + 90s;
    TempDir root;
    Socket echo_peer = Socket::BindUdp();
    std::atomic<bool> stop_echo{false};

    PeerThread echo_thread([&] {
        while (!stop_echo.load(std::memory_order_relaxed)) {
            if (!udp::Readable(echo_peer.Fd(), 25ms)) continue;
            auto pkt = udp::Receive(echo_peer, 1s);
            udp::Reply(echo_peer, pkt, pkt.payload);
        }
    });
    struct JoinEcho {
        std::atomic<bool>& stop;
        PeerThread& thread;
        ~JoinEcho() {
            stop.store(true, std::memory_order_relaxed);
            try { thread.Join(); } catch (...) {}
        }
    } join_echo{stop_echo, echo_thread};

    if (uc.protocol == "hysteria2") {
        auto reservation = Socket::BindUdp();
        const uint16_t hy2_port = reservation.Port();
        auto inbound = quic::HysteriaInbound(hy2_port);
        inbound["settings"]["upMbps"] = 10000;
        inbound["settings"]["downMbps"] = 10000;
        Configure(root.Path(), std::move(inbound),
                  {{"protocol", "freedom"}, {"settings", Json::object()}}, Workers);
        reservation.Close();

        const auto usage_before = ChildrenUsage();
        const auto lifetime_started = Clock::now();
        Child child({binary.string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
        child.WaitForLog("server started", Remaining(deadline));
        const auto startup_memory = child.ReadMemorySnapshot();

        quic::Peer peer(hy2_port, "smoke-secret");
        const std::string target_str = "127.0.0.1:" + std::to_string(echo_peer.Port());
        auto make_hy2_udp = [&](uint16_t pkt_id) {
            return BigEndian(0x10203040U, 4) + BigEndian(pkt_id, 2) +
                   static_cast<char>(0) + static_cast<char>(1) +
                   static_cast<char>(target_str.size()) + target_str + datagram_payload;
        };

        for (size_t i = 0; i < UdpWarmupPackets; ++i) {
            peer.SendDatagram(make_hy2_udp(static_cast<uint16_t>(i + 1)));
            const auto reply = peer.ReadDatagram(Remaining(deadline));
            Require(reply.size() > 9 + target_str.size(), "short HY2 UDP reply");
        }
        const auto warmup_memory = child.ReadMemorySnapshot();
        const auto started = Clock::now();
        for (size_t i = 0; i < UdpMeasuredPackets; ++i) {
            peer.SendDatagram(make_hy2_udp(static_cast<uint16_t>(UdpWarmupPackets + i + 1)));
            const auto reply = peer.ReadDatagram(Remaining(deadline));
            Require(reply.size() > 9 + target_str.size(), "short HY2 UDP reply");
        }
        const double elapsed = std::chrono::duration<double>(Clock::now() - started).count();
        const auto measured_memory = child.ReadMemorySnapshot();

        const int status = child.Stop(5s);
        const auto usage_after = ChildrenUsage();
        const double lifetime = std::chrono::duration<double>(Clock::now() - lifetime_started).count();
        ASSERT_EQ(status, 0) << ReadFile(child.LogPath());

        const double total_bytes = static_cast<double>(UdpMeasuredPackets * UdpPayloadBytes * 2);
        const double user_cpu = Seconds(usage_after.ru_utime) - Seconds(usage_before.ru_utime);
        const double system_cpu = Seconds(usage_after.ru_stime) - Seconds(usage_before.ru_stime);
        const Json metrics{
            {"case", uc.name},
            {"protocol", uc.protocol},
            {"variant", uc.variant},
            {"transport", "udp"},
            {"measured_packets", UdpMeasuredPackets},
            {"measured_bytes_roundtrip", static_cast<uint64_t>(total_bytes)},
            {"elapsed_seconds", elapsed},
            {"throughput_mib_per_second", total_bytes / MiB / elapsed},
            {"daemon_lifetime_wall_seconds", lifetime},
            {"daemon_lifetime_cpu_seconds", user_cpu + system_cpu},
            {"memory", Json::array({
                MemorySample("server_started", startup_memory),
                MemorySample("warmup_complete", warmup_memory),
                MemorySample("measured_complete", measured_memory)})}};
        std::cout << "PROTOCOL_UDP_BENCHMARK " << metrics.dump() << '\n';
        return;
    }

    const bool native_ss = (uc.variant == "native_aes" || uc.variant == "native_2022_aes");
    udp::PortReservation entry_res(native_ss);
    auto hop_res = Socket::ReserveTcp();
    auto fallback_listener = Socket::Listen();

    HopTopology topo;
    if (native_ss) {
        const bool is_2022 = (uc.variant == "native_2022_aes");
        Json inbound = {
            {"tag", "ss-udp-in"},
            {"protocol", "shadowsocks"},
            {"listen", "127.0.0.1"},
            {"port", entry_res.port},
            {"outboundTag", "direct"},
            {"settings",
             {{"method", is_2022 ? "2022-blake3-aes-128-gcm" : "aes-128-gcm"},
              {"clients",
               Json::array({{{"password",
                              is_2022 ? udp::Base64(udp::Sequence(16)) : std::string("secret")}}})}}}};
        topo.inbounds.push_back(std::move(inbound));
        topo.outbounds.push_back(tls::Direct());
    } else {
        topo = BuildProtocolHop(
            uc.protocol, uc.variant, entry_res.port, hop_res.Port(), fallback_listener.Port());
    }

    tls::Config(root.Path(), topo.inbounds, topo.outbounds,
                {{"log", {{"loglevel", "info"}}},
                 {"timeouts", {{"handshake", 10}, {"connIdle", 60}, {"write", 60},
                               {"uplinkOnly", 10}, {"downlinkOnly", 10}}}});
    if (native_ss) entry_res.ReleaseUdp();

    const auto usage_before = ChildrenUsage();
    const auto lifetime_started = Clock::now();
    Child child({binary.string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started", Remaining(deadline));
    const auto startup_memory = child.ReadMemorySnapshot();

    udp::Client client(entry_res.port, echo_peer.Port(), native_ss, false, "127.0.0.1",
                       uc.variant == "native_2022_aes" ? "aes" : "");
    for (size_t i = 0; i < UdpWarmupPackets; ++i) {
        client.Send(datagram_payload);
        client.Expect(datagram_payload, Remaining(deadline));
    }
    const auto warmup_memory = child.ReadMemorySnapshot();
    const auto started = Clock::now();
    for (size_t i = 0; i < UdpMeasuredPackets; ++i) {
        client.Send(datagram_payload);
        client.Expect(datagram_payload, Remaining(deadline));
    }
    const double elapsed = std::chrono::duration<double>(Clock::now() - started).count();
    const auto measured_memory = child.ReadMemorySnapshot();
    client.Finish();

    const int status = child.Stop(5s);
    const auto usage_after = ChildrenUsage();
    const double lifetime = std::chrono::duration<double>(Clock::now() - lifetime_started).count();
    ASSERT_EQ(status, 0) << ReadFile(child.LogPath());

    const double total_bytes = static_cast<double>(UdpMeasuredPackets * UdpPayloadBytes * 2);
    const double user_cpu = Seconds(usage_after.ru_utime) - Seconds(usage_before.ru_utime);
    const double system_cpu = Seconds(usage_after.ru_stime) - Seconds(usage_before.ru_stime);
    const Json metrics{
        {"case", uc.name},
        {"protocol", uc.protocol},
        {"variant", uc.variant},
        {"transport", "udp"},
        {"measured_packets", UdpMeasuredPackets},
        {"measured_bytes_roundtrip", static_cast<uint64_t>(total_bytes)},
        {"elapsed_seconds", elapsed},
        {"throughput_mib_per_second", total_bytes / MiB / elapsed},
        {"daemon_lifetime_wall_seconds", lifetime},
        {"daemon_lifetime_cpu_seconds", user_cpu + system_cpu},
        {"memory", Json::array({
            MemorySample("server_started", startup_memory),
            MemorySample("warmup_complete", warmup_memory),
            MemorySample("measured_complete", measured_memory)})}};
    std::cout << "PROTOCOL_UDP_BENCHMARK " << metrics.dump() << '\n';
}

constexpr UdpProtocolCase kUdpCases[] = {
    {"Freedom_Udp", "freedom", "direct"},
    {"Vmess_Aes128Gcm_Udp", "vmess", "aes-128-gcm"},
    {"Vless_Xudp_Udp", "vless", "plain"},
    {"Trojan_Tls_Udp", "trojan", "tls"},
    {"Shadowsocks_NativeAes128Gcm_Udp", "shadowsocks", "native_aes"},
    {"Shadowsocks_Native2022Aes128Gcm_Udp", "shadowsocks", "native_2022_aes"},
    {"Shadowsocks_Uot_Udp", "shadowsocks", "uot"},
    {"AnyTls_Uot_Udp", "anytls", "tls"},
    {"Hysteria2_Quic_Udp", "hysteria2", "quic"},
};

INSTANTIATE_TEST_SUITE_P(
    AllProtocolsUdp,
    ProtocolUdpThroughputBenchmark,
    testing::ValuesIn(kUdpCases),
    [](const testing::TestParamInfo<UdpProtocolCase>& info) {
        return std::string(info.param.name);
    });

}  // namespace
}  // namespace cnode::e2e
