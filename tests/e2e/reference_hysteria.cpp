#include "reference_support.hpp"
#include <openssl/rand.h>
#include <csignal>

namespace cnode::e2e::reference {
namespace {
using Clock = std::chrono::steady_clock;
std::string Random(size_t count) {
    std::string result(count, '\0');
    Require(RAND_bytes(reinterpret_cast<unsigned char*>(result.data()), count) == 1, "RAND_bytes failed");
    return result;
}
std::string ReceiveDatagram(int fd, sockaddr_in& peer) {
    std::array<char, 65536> bytes{}; socklen_t size = sizeof(peer);
    const auto count = recvfrom(fd, bytes.data(), bytes.size(), MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&peer), &size);
    if (count < 0 && (errno == EAGAIN || errno == EINTR)) return {};
    Require(count >= 0, "UDP receive failed");
    return {bytes.data(), static_cast<size_t>(count)};
}
void SendDatagram(int fd, std::string_view data, const sockaddr_in& peer) {
    Require(sendto(fd, data.data(), data.size(), 0, reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) ==
        static_cast<ssize_t>(data.size()), "UDP send failed");
}
class UdpTarget {
public:
    UdpTarget() : socket_(Socket::BindUdp()), thread_([this] {
        while (!stop_) {
            pollfd fd{socket_.Fd(), POLLIN, 0};
            if (poll(&fd, 1, 50) <= 0) continue;
            sockaddr_in peer{}; auto data = ReceiveDatagram(socket_.Fd(), peer);
            if (data.empty()) continue;
            { std::lock_guard lock(mutex_); peers_.insert({peer.sin_addr.s_addr, peer.sin_port}); }
            data.append(reinterpret_cast<const char*>(&peer.sin_addr), 4);
            data.append(reinterpret_cast<const char*>(&peer.sin_port), 2);
            SendDatagram(socket_.Fd(), data, peer);
        }
    }) {}
    ~UdpTarget() { stop_ = true; }
    uint16_t Port() const { return socket_.Port(); }
    size_t Count() const { std::lock_guard lock(mutex_); return peers_.size(); }
    void Join() { stop_ = true; thread_.Join(); }
private:
    Socket socket_;
    std::atomic<bool> stop_{false};
    mutable std::mutex mutex_;
    std::set<std::pair<uint32_t, uint16_t>> peers_;
    PeerThread thread_;
};
class NatRelay {
public:
    explicit NatRelay(uint16_t server_port) : front_(Socket::BindUdp()), server_port_(server_port) {
        paths_.push_back(Socket::BindUdp());
        thread_ = std::make_unique<PeerThread>([this] {
            while (!stop_) {
                std::vector<pollfd> fds{{front_.Fd(), POLLIN, 0}};
                { std::lock_guard lock(mutex_); for (const auto& path : paths_) fds.push_back({path.Fd(), POLLIN, 0}); }
                if (poll(fds.data(), fds.size(), 30) <= 0) continue;
                for (size_t index = 0; index < fds.size(); ++index) {
                    if (!(fds[index].revents & POLLIN)) continue;
                    sockaddr_in peer{}; auto packet = ReceiveDatagram(fds[index].fd, peer);
                    if (packet.empty()) continue;
                    std::lock_guard lock(mutex_);
                    if (index == 0) {
                        client_ = peer; have_client_ = true;
                        if (!(static_cast<unsigned char>(packet[0]) & 0x80) && packet.size() >= 19) cid_ = packet.substr(1, 18);
                        paths_[active_].SendTo(packet, server_port_);
                    } else if (ntohs(peer.sin_port) == server_port_ && have_client_) {
                        if (index - 1 == blocked_) { blocked_response_ = true; continue; }
                        SendDatagram(front_.Fd(), packet, client_);
                    }
                }
            }
        });
    }
    ~NatRelay() { stop_ = true; }
    uint16_t Port() const { return front_.Port(); }
    size_t Active() const { std::lock_guard lock(mutex_); return active_; }
    size_t Add() { std::lock_guard lock(mutex_); paths_.push_back(Socket::BindUdp()); return paths_.size() - 1; }
    uint16_t Switch(size_t index) { std::lock_guard lock(mutex_); active_ = index; return paths_.at(index).Port(); }
    uint16_t PathPort(size_t index) const { std::lock_guard lock(mutex_); return paths_.at(index).Port(); }
    std::string Cid() const { std::lock_guard lock(mutex_); return cid_; }
    void Forge(size_t index) {
        std::lock_guard lock(mutex_); Require(cid_.size() == 18, "no short-header QUIC CID observed");
        paths_.at(index).SendTo(std::string(1, '\x40') + cid_ + Random(80), server_port_);
    }
    void Block(size_t index) { std::lock_guard lock(mutex_); blocked_ = index; blocked_response_ = false; }
    bool BlockedResponse() const { return blocked_response_; }
    void Join() { stop_ = true; thread_->Join(); }
private:
    Socket front_;
    uint16_t server_port_;
    std::atomic<bool> stop_{false}, blocked_response_{false};
    mutable std::mutex mutex_;
    std::vector<Socket> paths_;
    size_t active_ = 0, blocked_ = static_cast<size_t>(-1);
    sockaddr_in client_{};
    bool have_client_ = false;
    std::string cid_;
    // Destroy/join before the state used by the worker is destroyed.
    std::unique_ptr<PeerThread> thread_;
};
class ControlStream {
public:
    explicit ControlStream(Socket socket) : socket_(std::move(socket)), thread_([this] {
        while (!stop_) {
            const auto payload = "independent-session:" + BigEndian(rounds_, 8) + Random(1024);
            const auto started = Clock::now(); socket_.Write(payload, 2s);
            Require(socket_.ReadExact(payload.size(), 2s) == payload, "independent session corrupted");
            Require(Clock::now() - started < 2s, "independent session stalled");
            ++rounds_; std::this_thread::sleep_for(10ms);
        }
    }) {}
    ~ControlStream() { stop_ = true; }
    size_t Rounds() const { return rounds_; }
    void Join() { stop_ = true; thread_.Join(); }
private:
    Socket socket_;
    std::atomic<bool> stop_{false};
    std::atomic<size_t> rounds_{0};
    PeerThread thread_;
};
struct Commit { int old_owner, receiver; uint16_t port; std::string evidence; };
std::vector<Commit> Commits(const std::string& logs) {
    const std::regex pattern("QUIC passive handoff committed old_owner=(\\d+) receiving_worker=(\\d+) remote=[^\\n]*?:(\\d+) path_evidence=(challenge|reused)");
    std::vector<Commit> result;
    for (auto it = std::sregex_iterator(logs.begin(), logs.end(), pattern); it != std::sregex_iterator(); ++it)
        result.push_back({std::stoi((*it)[1]), std::stoi((*it)[2]), static_cast<uint16_t>(std::stoi((*it)[3])), (*it)[4]});
    return result;
}
std::vector<std::pair<int, uint16_t>> Rejections(const std::string& logs) {
    const std::regex pattern("QUIC passive claim rejected receiving_worker=(\\d+) remote=[^\\n]*?:(\\d+) reason=no-path-evidence");
    std::vector<std::pair<int, uint16_t>> result;
    for (auto it = std::sregex_iterator(logs.begin(), logs.end(), pattern); it != std::sregex_iterator(); ++it)
        result.emplace_back(std::stoi((*it)[1]), static_cast<uint16_t>(std::stoi((*it)[2])));
    return result;
}
void VerifyHysteria(const std::string& binary, int version) {
    const auto metadata = Command({CNODE_REFERENCE_GO, "version", "-m", binary});
    const auto expected = version == 1 ? "path\tgithub.com/apernet/hysteria/app/cmd\n" : "path\tgithub.com/apernet/hysteria/app/v2\n";
    Require(metadata.find(expected) != std::string::npos, "Hysteria reference is not the official github.com/apernet/hysteria app");
    Require(metadata.find("vcs.modified=false") != std::string::npos &&
        std::regex_search(metadata, std::regex("vcs.revision=[0-9a-f]{40}")), "Hysteria must contain clean source revision metadata");
    const auto banner = Command({binary, version == 1 ? "--version" : "version"});
    Require(std::regex_search(banner, std::regex("[vV]?" + std::to_string(version) + "\\.[0-9]+\\.[0-9]+")), "wrong Hysteria reference major version");
}

std::vector<int> ConfiguredVersions() {
#if defined(CNODE_REFERENCE_HYSTERIA1) && defined(CNODE_REFERENCE_HYSTERIA2)
    return {1, 2};
#elif defined(CNODE_REFERENCE_HYSTERIA1)
    return {1};
#elif defined(CNODE_REFERENCE_HYSTERIA2)
    return {2};
#else
#error A Hysteria reference executable must be configured
#endif
}
std::string ReferenceBinary(int version) {
#ifdef CNODE_REFERENCE_HYSTERIA1
    if (version == 1) return CNODE_REFERENCE_HYSTERIA1;
#endif
#ifdef CNODE_REFERENCE_HYSTERIA2
    if (version == 2) return CNODE_REFERENCE_HYSTERIA2;
#endif
    throw std::runtime_error("unconfigured Hysteria version registered");
}

class HysteriaReference : public testing::TestWithParam<std::tuple<int, std::string>> {};
TEST_P(HysteriaReference, AuthenticatedCrossWorkerReturnAndFailClosedShutdown) {
    const auto [version, outbound_kind] = GetParam();
    const std::string binary = ReferenceBinary(version);
    VerifyHysteria(binary, version);
    BinaryGuard binaries{Binary(), binary};
    TempDir root, upstream_root;
    const auto server_port = UdpPort(), socks_port = TcpPort(), control_port = TcpPort();
    TcpServer target([](Socket socket, size_t) {
        while (true) { auto data = socket.Read(65536, 20s); if (data.empty()) break; socket.Write(data); }
    });
    UdpTarget udp_target;
    std::unique_ptr<Child> upstream;
    std::unique_ptr<Bridge> tap;
    Json outbound = Freedom();
    if (outbound_kind != "direct") {
        const auto upstream_port = TcpPort();
        tap = std::make_unique<Bridge>(upstream_port);
        if (outbound_kind == "anytls") {
            Configure(upstream_root.Path(), {{"protocol", "anytls"}, {"listen", "127.0.0.1"}, {"port", upstream_port},
                {"settings", {{"clients", Json::array({{{"password", "secret"}}})}}}, {"streamSettings", TlsSettings(true)}}, Freedom());
            outbound = {{"protocol", "anytls"}, {"settings", {{"address", "127.0.0.1"}, {"port", tap->Port()},
                {"password", "secret"}, {"minIdleSession", 1}}}, {"streamSettings", TlsSettings(false)}};
        } else {
            Configure(upstream_root.Path(), VlessInbound(upstream_port), Freedom());
            outbound = {{"protocol", "vless"}, {"settings", {{"address", "127.0.0.1"}, {"port", tap->Port()},
                {"id", UserId}, {"encryption", "none"}}}};
        }
        upstream = std::make_unique<Child>(std::vector<std::string>{Binary().string(), "--config-dir", upstream_root.Path().string()}, upstream_root.Path() / "cnode.log");
    }
    Configure(root.Path(), {{"protocol", version == 1 ? "hysteria" : "hysteria2"}, {"listen", "127.0.0.1"},
        {"port", server_port}, {"settings", {{"upMbps", 100}, {"downMbps", 100},
        {"clients", Json::array({{{"password", "smoke-secret"}}})}}}, {"streamSettings", TlsSettings(true)}}, outbound, 4);
    DebugConfig(root.Path());
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "cnode.log");
    NatRelay relay(server_port);
    auto config = [&](std::string_view name, uint16_t remote, uint16_t local) {
        const auto path = root.Path() / (std::string(name) + (version == 1 ? ".json" : ".yaml"));
        if (version == 1) WriteJson(root.Path(), path.filename().string(), {{"server", Address(remote)}, {"protocol", "udp"},
            {"up_mbps", 100}, {"down_mbps", 100}, {"auth_str", "smoke-secret"}, {"server_name", "localhost"},
            {"insecure", true}, {"socks5", {{"listen", Address(local)}}}});
        else WriteFile(path, "server: " + Address(remote) + "\nauth: smoke-secret\ntls:\n  sni: localhost\n  insecure: true\nsocks5:\n  listen: " + Address(local) + "\n");
        return path.string();
    };
    Child client({binary, "client", "-c", config("client", relay.Port(), socks_port)}, root.Path() / "client.log");
    Child control_client({binary, "client", "-c", config("control", server_port, control_port)}, root.Path() / "control.log");
    auto tcp = Connect(socks_port); Socks(tcp, target.Port());
    auto association = Connect(socks_port); const auto udp_port = Socks(association, 0, 3);
    auto control_socket = Connect(control_port); Socks(control_socket, target.Port());
    ControlStream control(std::move(control_socket));
    Until([&] { return control.Rounds() > 0; }, 15s);
    auto udp = Socket::BindUdp();
    const auto nonce = Random(16);
    const auto udp_header = std::string("\0\0\0", 3) + SocksAddress(udp_target.Port());
    std::string udp_peer;
    size_t rounds = 0, upstream_baseline = 0;
    auto exchange = [&] {
        const auto started = Clock::now(), deadline = started + 1500ms;
        const auto payload = nonce + BigEndian(rounds, 8) + Random(4096);
        tcp.Write(payload, 1400ms);
        Require(tcp.ReadExact(payload.size(), 1400ms) == payload, "persistent TCP stream corrupted");
        const auto datagram = nonce + BigEndian(rounds, 8);
        bool received = false;
        while (Clock::now() < deadline) {
            udp.SendTo(udp_header + datagram, udp_port);
            pollfd fd{udp.Fd(), POLLIN, 0};
            const auto remaining = std::chrono::duration_cast<Milliseconds>(deadline - Clock::now()).count();
            if (poll(&fd, 1, static_cast<int>(std::clamp<int64_t>(remaining, 0, 100))) <= 0) continue;
            sockaddr_in peer{}; auto reply = ReceiveDatagram(udp.Fd(), peer);
            Require(reply.size() >= 16 && reply.substr(0, 4) == std::string("\0\0\0\1", 4), "SOCKS UDP response framing changed");
            const auto body = reply.substr(10);
            if (body.substr(0, body.size() - 6) != datagram) continue;
            if (udp_peer.empty()) udp_peer = body.substr(body.size() - 6);
            Require(body.substr(body.size() - 6) == udp_peer, "UDP egress tuple changed (redial)");
            received = true; break;
        }
        Require(received, "persistent UDP association stopped");
        Require(Clock::now() - started < 1500ms, "forged claim or migration stalled business traffic");
        EXPECT_EQ(target.Count(), 2); EXPECT_EQ(udp_target.Count(), 1);
        if (tap && upstream_baseline) EXPECT_EQ(tap->Count(), upstream_baseline) << "upstream tunnel redialed";
        ++rounds;
    };
    for (int i = 0; i != 4; ++i) exchange();
    if (tap) { upstream_baseline = tap->Count(); ASSERT_GT(upstream_baseline, 0u); }
    const auto control_before = control.Rounds();
    ASSERT_EQ(relay.Cid().size(), 18u);
    std::set<uint16_t> forged_ports;
    bool rejected = false;
    for (int attempt = 0; attempt != 32; ++attempt) {
        const auto index = relay.Add(); const auto port = relay.PathPort(index);
        forged_ports.insert(port); relay.Forge(index); std::this_thread::sleep_for(20ms); exchange();
        for (const auto& commit : Commits(Logs(root.Path()))) EXPECT_FALSE(forged_ports.contains(commit.port));
        for (const auto& [worker, source] : Rejections(Logs(root.Path()))) if (forged_ports.contains(source)) rejected = true;
        if (rejected) break;
    }
    const auto rejection_deadline = Clock::now() + 7s;
    while (!rejected && Clock::now() < rejection_deadline) {
        exchange(); std::this_thread::sleep_for(50ms);
        for (const auto& [worker, source] : Rejections(Logs(root.Path()))) if (forged_ports.contains(source)) rejected = true;
        for (const auto& commit : Commits(Logs(root.Path()))) EXPECT_FALSE(forged_ports.contains(commit.port));
    }
    ASSERT_TRUE(rejected) << "no foreign-Worker forged-CID rejection";
    bool returned = false;
    for (int attempt = 0; attempt != 32 && !returned; ++attempt) {
        const auto previous = relay.Active(); const auto path = relay.Add();
        const auto source = relay.Switch(path);
        for (int i = 0; i != 6; ++i) exchange();
        const auto return_port = relay.Switch(previous);
        for (int i = 0; i != 6; ++i) exchange();
        const auto deadline = Clock::now() + 7s;
        while (Clock::now() < deadline && !returned) {
            const auto commits = Commits(Logs(root.Path()));
            for (const auto& outward : commits) {
                if (outward.port != source || outward.old_owner == outward.receiver) continue;
                for (const auto& back : commits)
                    if (back.port == return_port && back.evidence == "reused" && back.old_owner == outward.receiver && back.receiver == outward.old_owner) returned = true;
            }
            if (!returned) { exchange(); std::this_thread::sleep_for(50ms); }
        }
    }
    ASSERT_TRUE(returned) << "no cross-Worker A -> B -> A historical-path reuse";
    for (int i = 0; i != 20; ++i) exchange();
    EXPECT_GT(control.Rounds(), control_before);
    EXPECT_TRUE(client.Running()); EXPECT_TRUE(control_client.Running()); EXPECT_TRUE(server.Running());
    // Pick a proven foreign, never-validated path, suppress PATH_RESPONSE, then stop the owned server.
    std::vector<size_t> candidates;
    for (int i = 0; i != 32; ++i) { const auto index = relay.Add(); candidates.push_back(index); relay.Forge(index); exchange(); }
    size_t chosen = static_cast<size_t>(-1); int receiving_worker = -1;
    const auto shutdown_deadline = Clock::now() + 7s;
    while (Clock::now() < shutdown_deadline && receiving_worker < 0) {
        for (const auto& [worker, port] : Rejections(Logs(root.Path())))
            for (auto index : candidates) if (relay.PathPort(index) == port) { chosen = index; receiving_worker = worker; }
        if (receiving_worker < 0) { exchange(); std::this_thread::sleep_for(20ms); }
    }
    ASSERT_GE(receiving_worker, 0) << "no fresh foreign-Worker path for shutdown";
    relay.Block(chosen); relay.Switch(chosen);
    tcp.Write(nonce + "interrupted-path-validation");
    Until([&] { return relay.BlockedResponse(); }, 1500ms);
    control.Join();
    server.Signal(SIGTERM); EXPECT_EQ(server.Wait(10s), 0);
    const auto events = Logs(root.Path());
    EXPECT_NE(events.find("QUIC passive claim abandoned receiving_worker=" + std::to_string(receiving_worker) + " reason=listener-stopped"), std::string::npos);
    EXPECT_TRUE(std::regex_search(events, std::regex("QUIC passive rollback closed connection worker=\\d+ reason=selected-path-changed")));
    tcp.Close(); association.Close(); client.Stop(); control_client.Stop();
    if (upstream) upstream->Stop();
    relay.Join(); if (tap) tap->Join(); udp_target.Join(); target.Join(); binaries.Check();
}
INSTANTIATE_TEST_SUITE_P(ProtocolsAndOutbounds, HysteriaReference,
    testing::Combine(testing::ValuesIn(ConfiguredVersions()), testing::Values("direct", "tcp", "anytls")), [](const auto& info) {
        return "V" + std::to_string(std::get<0>(info.param)) + "_" + std::get<1>(info.param);
    });
} // namespace
} // namespace cnode::e2e::reference
