#include "udp_wire.hpp"

#include <netinet/in.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <optional>
#include <vector>

// A freedom outbound reaching a dual-stack name (A 127.0.0.1, AAAA ::1)
// through the real cnode process. The IPv6 endpoint stands for a black-holed
// route: a loopback listener with a full accept queue drops every new SYN
// (tcp_abort_on_overflow=0), so a connect to it stays in SYN retransmission.
namespace cnode::e2e::udp {
namespace {
using Clock = std::chrono::steady_clock;
constexpr std::string_view Payload = "happy-eyeballs-payload";

class DualStackDns {
public:
    DualStackDns() : socket_(Socket::BindUdp()), thread_([this] { Serve(); }) {}
    ~DualStackDns() {
        stop_ = true;
        try { thread_.Join(); } catch (...) { }
    }
    uint16_t Port() const { return socket_.Port(); }
private:
    void Serve() {
        while (!stop_) {
            if (!Readable(socket_.Fd(), 100ms)) continue;
            auto packet = Receive(socket_);
            const auto& query = packet.payload;
            Require(query.size() >= 17, "short DNS question");
            size_t end = 12;
            while (end < query.size() && query[end] != 0) {
                auto size = static_cast<unsigned char>(query[end]);
                Require(size < 64 && end + size + 1 < query.size(), "invalid DNS label");
                end += size + 1;
            }
            ++end;
            Require(end + 4 <= query.size(), "truncated DNS question");
            auto kind = ReadBigEndian(std::string_view(query).substr(end, 2));
            Require(kind == 1 || kind == 28, "unexpected DNS question type");
            auto data = kind == 28 ? std::string(15, '\0') + '\1' : std::string("\x7f\0\0\1", 4);
            auto header = query.substr(0, 2) + BigEndian(0x8180, 2) + BigEndian(1, 2) + BigEndian(1, 2) + std::string(4, '\0');
            auto answer = std::string("\xc0\x0c", 2) + BigEndian(kind, 2) + BigEndian(1, 2) + BigEndian(60, 4) + BigEndian(data.size(), 2) + data;
            Reply(socket_, packet, header + query.substr(12, end + 4 - 12) + answer);
        }
    }
    Socket socket_;
    std::atomic<bool> stop_{false};
    PeerThread thread_;
};

[[nodiscard]] Socket ListenLoopback(bool v6, uint16_t port, int backlog) {
    Socket listener(::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0));
    Require(listener.Fd() >= 0, "socket failed");
    sockaddr_storage storage{};
    socklen_t size = 0;
    if (v6) {
        int enabled = 1;
        Require(setsockopt(listener.Fd(), IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) == 0, "IPV6_V6ONLY");
        auto& address = reinterpret_cast<sockaddr_in6&>(storage);
        address.sin6_family = AF_INET6;
        address.sin6_port = htons(port);
        address.sin6_addr = in6addr_loopback;
        size = sizeof(address);
    } else {
        auto& address = reinterpret_cast<sockaddr_in&>(storage);
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        size = sizeof(address);
    }
    if (::bind(listener.Fd(), reinterpret_cast<sockaddr*>(&storage), size) != 0) return Socket();
    Require(::listen(listener.Fd(), backlog) == 0, "listen failed");
    return listener;
}

// Listener plus the two established connections that fill its backlog-1
// accept queue; later SYNs are dropped while these stay open.
struct Blackhole {
    Socket listener;
    std::vector<Socket> fillers;
};

[[nodiscard]] std::optional<Blackhole> MakeBlackhole(bool v6, uint16_t port) {
    Blackhole blackhole{.listener = ListenLoopback(v6, port, 1), .fillers = {}};
    if (blackhole.listener.Fd() < 0) return std::nullopt;
    const std::string_view host = v6 ? "::1" : "127.0.0.1";
    blackhole.fillers.push_back(Socket::Connect(port, host));
    blackhole.fillers.push_back(Socket::Connect(port, host));
    Socket probe(::socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0));
    sockaddr_storage storage{};
    socklen_t storage_size = sizeof(storage);
    Require(getsockname(blackhole.listener.Fd(), reinterpret_cast<sockaddr*>(&storage), &storage_size) == 0,
            "getsockname");
    const socklen_t size = v6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
    Require(::connect(probe.Fd(), reinterpret_cast<sockaddr*>(&storage), size) != 0 && errno == EINPROGRESS,
            "accept queue did not black-hole the probe SYN");
    pollfd waiting{.fd = probe.Fd(), .events = POLLOUT, .revents = 0};
    Require(::poll(&waiting, 1, 100) == 0, "accept queue did not black-hole the probe SYN");
    return blackhole;
}

struct DualStackTarget {
    uint16_t port = 0;
    Socket v4_open;
    std::optional<Blackhole> v4_blackhole;
    std::optional<Blackhole> v6_blackhole;
};

// One port number on both loopback families: IPv6 always black-holed, IPv4
// either a live listener or black-holed too.
[[nodiscard]] DualStackTarget ReserveDualStackTarget(bool v4_reachable) {
    for (int attempt = 0; attempt < 20; ++attempt) {
        DualStackTarget target;
        target.v4_open = Socket::Listen();
        target.port = target.v4_open.Port();
        if (!v4_reachable) {
            target.v4_open.Close();
            target.v4_blackhole = MakeBlackhole(false, target.port);
            if (!target.v4_blackhole) continue;
        }
        target.v6_blackhole = MakeBlackhole(true, target.port);
        if (target.v6_blackhole) return target;
    }
    throw std::runtime_error("reserve dual-stack target port");
}

[[nodiscard]] std::unique_ptr<Child> StartNode(const TempDir& root, uint16_t inbound,
                                               uint16_t dns_port, unsigned dial_timeout) {
    Json config = {{"workers", 1}, {"log", {{"logDir", (root.Path() / "logs").string()}}},
        {"dns", {{"servers", Json::array({"127.0.0.1:" + std::to_string(dns_port)})}, {"timeout", 5}}},
        {"timeouts", {{"dial", dial_timeout}}}};
    WriteJson(root.Path(), "config.json", config);
    WriteJson(root.Path(), "inbounds.json", Json::array({
        {{"tag", "probe"}, {"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", inbound},
         {"outboundTag", "direct"}, {"settings", {{"clients", Json::array({{{"id", UserId}}})}}}}}));
    // UseIPv6v4 orders the AAAA answer first: the black-holed family leads.
    WriteJson(root.Path(), "outbounds.json", Json::array({
        {{"tag", "direct"}, {"protocol", "freedom"}, {"settings", {{"domainStrategy", "UseIPv6v4"}}}}}));
    auto child = std::make_unique<Child>(
        std::vector<std::string>{Binary().string(), "--config-dir", root.Path().string()},
        root.Path() / "child.log");
    child->WaitForServerStart();
    return child;
}

TEST(DialHappyEyeballs, BlackholedIpv6FallsBackToIpv4WithinAttemptDelay) {
    TempDir root;
    PortReservation inbound;
    DualStackDns dns;
    auto target = ReserveDualStackTarget(true);
    auto child = StartNode(root, inbound.port, dns.Port(), 10);

    for (int round = 0; round < 2; ++round) {
        PeerThread echo([&] {
            auto connection = target.v4_open.Accept(12s);
            auto data = connection.ReadExact(Payload.size());
            Require(data == Payload, "outbound TCP bytes changed");
            connection.Write(data);
        });
        auto client = Socket::Connect(inbound.port);
        const auto start = Clock::now();
        client.Write(VlessRequest(target.port, Payload, 1, "dual.test"));
        EXPECT_EQ(client.ReadExact(2 + Payload.size(), 12s), std::string(2, '\0') + std::string(Payload));
        // RFC 8305: IPv4 starts 250 ms after the stalled IPv6 attempt instead
        // of after the whole 10 s dial timeout.
        EXPECT_LT(Clock::now() - start, 3s) << "round " << round;
        echo.Join();
    }
    EXPECT_TRUE(child->Running());
    child->Stop();
}

TEST(DialHappyEyeballs, AllBlackholedFamiliesFailWithinOneDialTimeout) {
    TempDir root;
    PortReservation inbound;
    DualStackDns dns;
    auto target = ReserveDualStackTarget(false);
    auto child = StartNode(root, inbound.port, dns.Port(), 2);

    auto client = Socket::Connect(inbound.port);
    const auto start = Clock::now();
    client.Write(VlessRequest(target.port, Payload, 1, "dual.test"));
    std::string answer;
    try {
        answer = client.Read(65536, 12s);
    } catch (const std::runtime_error& error) {
        // A reset closes the request as well; only the E2E deadline is fatal.
        ASSERT_NE(std::string_view(error.what()), "E2E operation deadline exceeded");
    }
    const auto elapsed = Clock::now() - start;
    EXPECT_TRUE(answer.empty());
    // One 2 s dial deadline bounds both families; per-candidate timeouts
    // would close the request only after 4 s.
    EXPECT_GE(elapsed, 1500ms);
    EXPECT_LT(elapsed, 3500ms);
    EXPECT_TRUE(child->Running());
    child->Stop();
}

}  // namespace
}  // namespace cnode::e2e::udp
