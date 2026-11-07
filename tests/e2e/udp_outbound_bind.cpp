#include "udp_wire.hpp"

#include <atomic>

namespace cnode::e2e::udp {
namespace {
constexpr std::string_view Payload = "static-inbound-forced-outbound";
constexpr std::string_view UserA = "11111111-1111-4111-8111-111111111111";
constexpr std::string_view UserB = "22222222-2222-4222-8222-222222222222";
constexpr std::string_view RelayUser = "99999999-9999-4999-8999-999999999999";

void ConfigFiles(const TempDir& root, Json config, const Json& inbounds, const Json& outbounds) {
    config["log"]["logDir"] = (root.Path() / "logs").string();
    WriteJson(root.Path(), "config.json", config);
    WriteJson(root.Path(), "inbounds.json", inbounds);
    WriteJson(root.Path(), "outbounds.json", outbounds);
}
Json Inbound(uint16_t port, std::string_view tag = "probe", std::string_view outbound = "chosen") {
    return {{"tag", tag}, {"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", port},
        {"outboundTag", outbound}, {"settings", {{"clients", Json::array({{{"id", UserA}}})}}}};
}
Json Outbound(const Json& addresses, std::string_view strategy) {
    return {{"tag", "chosen"}, {"protocol", "freedom"}, {"settings", {{"domainStrategy", "UseIPv6v4"}}},
        {"sendThrough", addresses}, {"sendThroughStrategy", strategy}};
}
std::string PeerHost(const Socket& socket) {
    Datagram peer;
    Require(getpeername(socket.Fd(), reinterpret_cast<sockaddr*>(&peer.address), &peer.address_size) == 0, "getpeername failed");
    return peer.Host();
}
std::string Probe(uint16_t inbound, uint16_t target, std::string_view user = UserA,
                  std::string_view proxy = {}, bool domain = false) {
    auto socket = Socket::Connect(inbound);
    socket.Write(std::string(proxy) + VlessRequest(target, Payload, 1, domain ? "dual.test" : "127.0.0.1", user));
    return socket.ReadExact(2 + Payload.size(), 12s);
}

class DualStackDns {
public:
    DualStackDns() : socket_(Socket::BindUdp()), thread_([this] { Serve(); }) {}
    ~DualStackDns() {
        stop_ = true;
        try { thread_.Join(); } catch (...) { }
    }
    uint16_t Port() const { return socket_.Port(); }
    void Join() { stop_ = true; thread_.Join(); }
    unsigned Requests() const { return requests_; }
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
            ++requests_;
        }
    }
    Socket socket_;
    std::atomic<bool> stop_{false};
    std::atomic<unsigned> requests_{0};
    PeerThread thread_;
};

struct BindCase {
    std::string name;
    Json addresses;
    std::string strategy;
    bool succeeds;
    bool domain = false;
};
class OutboundBind : public testing::TestWithParam<BindCase> {};
TEST_P(OutboundBind, OrderedSameFamilySelectionAndSystemFallback) {
    const auto& item = GetParam();
    TempDir root;
    PortReservation inbound;
    Socket target, refused_v6;
    for (int attempt = 0; attempt < 20; ++attempt) {
        target = Socket::Listen();
        if (!item.domain) break;
        refused_v6 = Socket(::socket(AF_INET6, SOCK_STREAM, 0));
        Require(refused_v6.Fd() >= 0, "IPv6 socket unavailable");
        int enabled = 1;
        Require(setsockopt(refused_v6.Fd(), IPPROTO_IPV6, IPV6_V6ONLY, &enabled, sizeof(enabled)) == 0, "IPV6_V6ONLY");
        sockaddr_in6 address{};
        address.sin6_family = AF_INET6; address.sin6_port = htons(target.Port()); address.sin6_addr = in6addr_loopback;
        if (bind(refused_v6.Fd(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) break;
        Require(errno == EADDRINUSE && attempt != 19, "reserve IPv6 refusal endpoint");
        refused_v6.Close(); target.Close();
    }
    std::unique_ptr<DualStackDns> dns;
    Json config = {{"workers", 1}, {"log", {{"enable", false}}}};
    if (item.domain) {
        dns = std::make_unique<DualStackDns>();
        config["dns"] = {{"servers", Json::array({"127.0.0.1:" + std::to_string(dns->Port())})}, {"timeout", 5}};
    }
    ConfigFiles(root, config, Json::array({Inbound(inbound.port)}), Json::array({Outbound(item.addresses, item.strategy)}));
    inbound.Release();
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started");
    if (item.succeeds) {
        std::string source;
        PeerThread echo([&] {
            auto connection = target.Accept(12s);
            source = PeerHost(connection);
            auto data = connection.ReadExact(Payload.size());
            Require(data == Payload, "outbound TCP bytes changed");
            connection.Write(data);
        });
        EXPECT_EQ(Probe(inbound.port, target.Port(), UserA, {}, item.domain), std::string(2, '\0') + std::string(Payload));
        echo.Join();
        EXPECT_EQ(source, "127.0.0.1");
    } else {
        auto connection = Socket::Connect(inbound.port);
        connection.Write(VlessRequest(target.Port(), Payload, 1, "127.0.0.1", UserA));
        std::string answer;
        try { answer = connection.ReadExact(2 + Payload.size(), 12s); }
        catch (const std::runtime_error& error) {
            const std::string_view message = error.what();
            if (message != "unexpected EOF reading exact socket payload" &&
                message != "E2E operation deadline exceeded") throw;
        }
        EXPECT_TRUE(answer.empty());
        EXPECT_FALSE(Readable(target.Fd(), 100ms)) << "strict first address must not fall through";
        EXPECT_TRUE(child.Running());
    }
    if (dns) { dns->Join(); EXPECT_GT(dns->Requests(), 0u); }
    child.Stop();
}
INSTANTIATE_TEST_SUITE_P(OrderedSourceBinding, OutboundBind, testing::Values(
    BindCase{"OrderedIpHash", Json::array({"127.0.0.1/32", "192.0.2.3"}), "ip_hash", true},
    BindCase{"OrderedUserHash", Json::array({"127.0.0.1/32", "192.0.2.3"}), "user_hash", true},
    BindCase{"OrderedRandom", Json::array({"127.0.0.1/32"}), "random", true},
    BindCase{"StrictFirstIp", Json::array({"192.0.2.3", "127.0.0.1/32"}), "ip_hash", false},
    BindCase{"NoSameFamily", Json::array({"2001:db8:ffff::/64"}), "ip_hash", true},
    BindCase{"DnsV6BindFailedV4Default", Json::array({"2001:db8:ffff::/64"}), "ip_hash", true, true},
    BindCase{"DnsV6RefusedV4Default", Json::array({"::1"}), "ip_hash", true, true}),
    [](const testing::TestParamInfo<BindCase>& info) { return info.param.name; });

struct RejectedCase { std::string name; Json addresses; std::string strategy; };
class RejectedBind : public testing::TestWithParam<RejectedCase> {};
TEST_P(RejectedBind, ReportsInvalidSendThroughBeforeStartup) {
    TempDir root;
    PortReservation inbound;
    ConfigFiles(root, {{"workers", 1}, {"log", {{"enable", false}}}}, Json::array({Inbound(inbound.port)}),
        Json::array({Outbound(GetParam().addresses, GetParam().strategy)}));
    inbound.Release();
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    EXPECT_NE(child.Wait(5s), 0);
    EXPECT_NE(ReadFile(child.LogPath()).find("sendThrough"), std::string::npos);
}
INSTANTIATE_TEST_SUITE_P(InvalidSourceBinding, RejectedBind, testing::Values(
    RejectedCase{"Ipv6Prefix", Json::array({"2001:db8::/129"}), "ip_hash"},
    RejectedCase{"Ipv4Prefix", Json::array({"127.0.0.1/33"}), "ip_hash"},
    RejectedCase{"RoundRobin", Json::array({"127.0.0.1"}), "round-robin"},
    RejectedCase{"HashAlias", Json::array({"127.0.0.1"}), "hash"},
    RejectedCase{"NonStringAddress", Json::array({42}), "ip_hash"},
    RejectedCase{"EmptyAddresses", Json::array(), "ip_hash"}),
    [](const testing::TestParamInfo<RejectedCase>& info) { return info.param.name; });

class PassthroughHash : public testing::TestWithParam<bool> {};
TEST_P(PassthroughHash, PreservesOriginAcrossAnyTlsAndVlessHops) {
    const bool ip_hash = GetParam();
    TempDir root;
    PortReservation entry, entry_b, us, jp;
    auto a = Inbound(entry.port, "entry-in-a", "entry-to-us-anytls");
    auto b = Inbound(entry_b.port, "entry-in-b", "entry-to-us-anytls");
    a["proxyProtocol"] = "auto"; b["proxyProtocol"] = "auto";
    a["settings"]["clients"] = Json::array({{{"id", UserA}, {"email", "1001"}}, {{"id", UserB}, {"email", "1002"}}});
    b["settings"]["clients"] = Json::array({{{"id", UserA}, {"email", "1001"}}});
    Json tls_server = TlsSettings(true);
    Json tls_client = TlsSettings(false);
    tls_server["tlsSettings"]["serverName"] = "us.example.com";
    tls_client["tlsSettings"]["serverName"] = "us.example.com";
    tls_client["tlsSettings"]["allowInsecure"] = true;
    auto last_tag = ip_hash ? "jp-out-ip" : "jp-out-user";
    Json inbounds = Json::array({a, b,
        {{"tag", "us-anytls-in"}, {"protocol", "anytls"}, {"listen", "127.0.0.1"}, {"port", us.port}, {"outboundTag", "us-to-jp"},
         {"settings", {{"clients", Json::array({{{"password", "us-anytls-password"}, {"email", "hop1@us.example"}}})}}}, {"streamSettings", tls_server}},
        {{"tag", "jp-in"}, {"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", jp.port}, {"outboundTag", last_tag},
         {"settings", {{"clients", Json::array({{{"id", RelayUser}, {"email", "relay@jp.example"}}})}}}}});
    Json outbounds = Json::array({
        {{"tag", "entry-to-us-anytls"}, {"protocol", "anytls"}, {"passthrough", true},
         {"settings", {{"address", "127.0.0.1"}, {"port", us.port}, {"password", "us-anytls-password"}, {"minIdleSession", 1}}}, {"streamSettings", tls_client}},
        {{"tag", "us-to-jp"}, {"protocol", "vless"}, {"passthrough", true},
         {"settings", {{"address", "127.0.0.1"}, {"port", jp.port}, {"id", RelayUser}}}},
        {{"tag", last_tag}, {"protocol", "freedom"}, {"sendThrough", Json::array({"127.0.0.0/24"})}, {"sendThroughStrategy", ip_hash ? "ip_hash" : "user_hash"}}});
    ConfigFiles(root, {{"workers", 1}, {"log", {{"enable", true}, {"rotateDaily", false}, {"access", (root.Path() / "access.log").string()}}}}, inbounds, outbounds);
    entry.Release(); entry_b.Release(); us.Release(); jp.Release();
    auto target = Socket::Listen();
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started");
    std::vector<std::string> sources;
    PeerThread echo([&] {
        for (int i = 0; i < (ip_hash ? 3 : 4); ++i) {
            auto connection = target.Accept(12s);
            sources.push_back(PeerHost(connection));
            auto payload = connection.ReadExact(Payload.size());
            Require(payload == Payload, "chained TCP payload changed");
            connection.Write(payload);
        }
    });
    auto expected = std::string(2, '\0') + std::string(Payload);
    if (ip_hash) {
        EXPECT_EQ(Probe(entry.port, target.Port(), UserA, "PROXY TCP4 203.0.113.10 127.0.0.1 40001 443\r\n"), expected);
        EXPECT_EQ(Probe(entry.port, target.Port(), UserB, "PROXY TCP4 203.0.113.10 127.0.0.1 59999 443\r\n"), expected);
        EXPECT_EQ(Probe(entry.port, target.Port(), UserA, "PROXY TCP4 203.0.113.25 127.0.0.1 40001 443\r\n"), expected);
    } else {
        EXPECT_EQ(Probe(entry.port, target.Port(), UserA), expected);
        EXPECT_EQ(Probe(entry.port, target.Port(), UserA), expected);
        EXPECT_EQ(Probe(entry.port, target.Port(), UserB), expected);
        EXPECT_EQ(Probe(entry_b.port, target.Port(), UserA), expected);
    }
    echo.Join();
    ASSERT_EQ(sources.size(), ip_hash ? 3u : 4u);
    EXPECT_EQ(sources[0], sources[1]);
    EXPECT_NE(sources[0], sources[2]);
    if (!ip_hash) EXPECT_NE(sources[0], sources[3]);
    child.Stop();
    if (!ip_hash) {
        auto access = ReadFile(root.Path() / "access.log");
        EXPECT_NE(access.find("|entry-in-a|"), std::string::npos);
        EXPECT_NE(access.find("|entry-in-b|"), std::string::npos);
    }
}
INSTANTIATE_TEST_SUITE_P(OriginIdentity, PassthroughHash, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) { return info.param ? "IpHash" : "UserHash"; });
} // namespace
} // namespace cnode::e2e::udp
