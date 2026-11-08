#include "udp_wire.hpp"

#include <algorithm>
#include <regex>
#include <set>

namespace cnode::e2e::udp {
namespace {
struct Case {
    std::string protocol, mode, cipher;
};

class RelayRun {
public:
    explicit RelayRun(Case value)
        : value(std::move(value)), peer(Socket::BindUdp()), fallback(Socket::BindUdp()),
          dns(Socket::BindUdp(0, IsQuic() ? "127.0.0.1" : "127.77.0.2")) {
        PortReservation reservation(Native());
        port = reservation.port;
        bool isolated = IsIsolation() || EmptyDatagrams();
        Json inbound = {{"tag", "udp-probe"}, {"protocol", "vless"}, {"listen", "127.0.0.1"},
            {"port", port}, {"routingEnabled", true},
            {"settings", {{"clients", Json::array({{{"id", UserId}}})}}},
            {"sniffing", {{"enabled", Sniffing()}}}};
        if (isolated) inbound["settings"]["clients"].push_back({{"id", SecondUser}});
        if (Native()) {
            inbound["protocol"] = "shadowsocks";
            inbound["settings"] = {{"method", "aes-128-gcm"}, {"clients", Json::array({{{"password", "secret"}}})}};
            if (isolated) inbound["settings"]["clients"].push_back({{"password", "second-secret"}});
        }
        Json config = {{"workers", 1}, {"timeouts", {{"write", 1}, {"connIdle", 30}, {"downlinkOnly", 1}}},
            {"dns", {{"servers", Json::array({std::string(IsQuic() ? "127.0.0.1:" : "127.77.0.2:") + std::to_string(dns.Port())})}, {"timeout", 10}}},
            {"log", {{"enable", false}, {"logDir", (root.Path() / "logs").string()}}}};
        if (Native() && !this->value.cipher.empty()) {
            size_t size = this->value.cipher == "aes" ? 16 : 32;
            inbound["settings"] = {{"method", this->value.cipher == "aes" ? "2022-blake3-aes-128-gcm" : "2022-blake3-chacha20-poly1305"},
                {"clients", Json::array({{{"password", Base64(Sequence(size))}}, {{"password", Base64(Sequence(size, size))}}})}};
        }
        if (Handoff()) {
            config["workers"] = 4;
            config["log"] = {{"loglevel", "debug"}, {"logDir", root.Path().string()},
                {"error", "handoff.log"}, {"access", "access.log"}, {"rotateDaily", false}, {"gzip", false}};
        }
        Json outbound = {{"tag", "udp-out"}, {"protocol", this->value.protocol}, {"settings", Json::object()}};
        if (this->value.protocol == "shadowsocks") outbound["settings"] = SsSettings(peer.Port(), this->value.mode == "dns_timeout" ? "udp-sink.test" : "127.0.0.1");
        Json outbounds = Json::array({outbound});
        Json routing = {{"rules", Json::array({{{"type", "field"}, {"inboundTag", Json::array({"udp-probe"})}, {"outboundTag", "udp-out"}}})}};
        if (IsQuic()) {
            inbound["sniffing"]["routeOnly"] = true;
            inbound["sniffing"]["destOverride"] = Json::array({"quic"});
            outbounds.push_back({{"tag", "fallback-out"}, {"protocol", "shadowsocks"}, {"settings", SsSettings(fallback.Port())}});
            routing = {{"domainStrategy", "AsIs"}, {"rules", Json::array({
                {{"type", "field"}, {"domain", Json::array({"full:fragmented-quic.test"})}, {"outboundTag", "udp-out"}},
                {{"type", "field"}, {"inboundTag", Json::array({"udp-probe"})}, {"outboundTag", "fallback-out"}}})}};
        }
        WriteJson(root.Path(), "config.json", config);
        WriteJson(root.Path(), "inbounds.json", Json::array({inbound}));
        WriteJson(root.Path(), "outbounds.json", outbounds);
        WriteJson(root.Path(), "routing.json", routing);
        reservation.Release();
        child = std::make_unique<Child>(std::vector<std::string>{Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
        child->WaitForLog("server started");
    }
    static Json SsSettings(uint16_t port, std::string_view address = "127.0.0.1") {
        return {{"servers", Json::array({{{"address", address}, {"port", port}, {"method", "aes-128-gcm"}, {"password", "secret"}}})}};
    }
    bool Native() const { return value.mode.starts_with("native_"); }
    bool IsQuic() const { return value.mode.find("quic_") != std::string::npos; }
    bool Sniffing() const { return IsQuic() || value.mode.find("sniff_") != std::string::npos; }
    bool Handoff() const { return value.mode == "native_ss2022_isolation"; }
    bool IsIsolation() const { return value.mode.find("isolation") != std::string::npos; }
    bool EmptyDatagrams() const {
        return value.mode == "native_empty_datagrams" || value.mode == "native_empty_short_domain";
    }
    uint16_t Destination() const { return value.protocol == "shadowsocks" ? 53 : peer.Port(); }
    void Echo(Socket& endpoint, std::string_view expected, bool delayed = false) {
        auto packet = Receive(endpoint);
        std::string plain = value.protocol == "shadowsocks" ? LegacyDecrypt(packet.payload) : packet.payload;
        Require(plain == (value.protocol == "shadowsocks" ? SocksAddress(53) : std::string{}) + std::string(expected), "outbound destination, bytes or boundaries changed");
        observed.push_back(std::string(expected));
        if (delayed) std::this_thread::sleep_for(200ms);
        if (value.protocol == "shadowsocks") {
            Reply(endpoint, packet, "invalid encrypted datagram");
            Reply(endpoint, packet, LegacyEncrypt(plain));
        } else Reply(endpoint, packet, plain);
    }
    std::map<std::string, Datagram> Round(std::initializer_list<std::string> expected) {
        std::map<std::string, Datagram> result;
        for (size_t i = 0; i < expected.size(); ++i) {
            auto packet = Receive(peer);
            observed.push_back(packet.payload);
            Require(result.emplace(packet.payload, packet).second, "duplicate outbound packet");
        }
        for (const auto& payload : expected) Require(result.contains(payload), "unexpected outbound payload");
        return result;
    }
    void Rejected(std::string_view packet, Client& source, const std::vector<std::shared_ptr<Socket>>& paths) {
        source.SendRaw(packet);
        std::vector<pollfd> sockets{{peer.Fd(), POLLIN, 0}};
        for (const auto& path : paths) sockets.push_back({path->Fd(), POLLIN, 0});
        int result;
        do { result = poll(sockets.data(), sockets.size(), 300); } while (result < 0 && errno == EINTR);
        Require(result == 0, "rejected ciphertext reached target or client");
    }
    Case value;
    TempDir root;
    Socket peer, fallback, dns;
    uint16_t port = 0;
    std::unique_ptr<Child> child;
    std::vector<std::string> observed;
};

void ExerciseHandoff(RelayRun& run) {
    Client first(run.port, run.peer.Port(), true, false, "127.0.0.1", run.value.cipher);
    Client second(run.port, run.peer.Port(), true, true, "127.0.0.1", run.value.cipher);
    second.socket = first.socket;
    auto retained = first.Send("client-one-round-one");
    second.Send("client-two-round-one");
    auto initial = run.Round({"client-one-round-one", "client-two-round-one"});
    auto first_address = initial.at("client-one-round-one");
    auto second_address = initial.at("client-two-round-one");
    EXPECT_NE(first_address.Port(), second_address.Port());
    Reply(run.peer, second_address, "client-two-round-one"); second.Expect("client-two-round-one");
    Reply(run.peer, first_address, "client-one-round-one"); first.Expect("client-one-round-one");
    std::vector<std::shared_ptr<Socket>> paths{first.socket};
    std::set<uint16_t> source_ports{first.socket->Port()};
    std::vector<std::string> expected{"client-one-round-one", "client-two-round-one"};
    for (int attempt = 0; attempt < 16; ++attempt) {
        SCOPED_TRACE(attempt);
        auto old_path = first.socket;
        auto suffix = std::to_string(attempt);
        auto delayed_payload = "client-one-delayed-" + suffix;
        auto delayed = first.Encode(delayed_payload);
        first.socket = std::make_shared<Socket>(Socket::BindUdp());
        paths.push_back(first.socket);
        EXPECT_TRUE(source_ports.insert(first.socket->Port()).second);
        run.Rejected(retained, first, paths);
        auto one = "client-one-rebind-" + suffix, two = "client-two-rebind-" + suffix;
        first.Send(one); second.Send(two);
        auto observed = run.Round({one, two});
        EXPECT_TRUE(observed.at(one).SameEndpoint(first_address));
        EXPECT_TRUE(observed.at(two).SameEndpoint(second_address));
        expected.insert(expected.end(), {one, two});
        Reply(run.peer, second_address, two); second.Expect(two);
        Reply(run.peer, first_address, one); first.Expect(one);
        run.Rejected(retained, first, paths);
        auto current = first.socket;
        first.socket = old_path;
        run.Rejected(delayed, first, paths);
        first.socket = current;
        auto reply = "reply-after-stale-path-" + suffix;
        Reply(run.peer, first_address, reply); first.Expect(reply);
        first.SendRaw(delayed);
        auto reordered = run.Round({delayed_payload});
        EXPECT_TRUE(reordered.at(delayed_payload).SameEndpoint(first_address));
        expected.push_back(delayed_payload);
        Reply(run.peer, first_address, delayed_payload); first.Expect(delayed_payload);
        run.Rejected(delayed, first, paths);
    }
    first.Send("client-one-after-handoff");
    EXPECT_TRUE(run.Round({"client-one-after-handoff"}).at("client-one-after-handoff").SameEndpoint(first_address));
    Reply(run.peer, first_address, "client-one-after-handoff"); first.Expect("client-one-after-handoff");
    second.Send("client-two-after-handoff");
    EXPECT_TRUE(run.Round({"client-two-after-handoff"}).at("client-two-after-handoff").SameEndpoint(second_address));
    Reply(run.peer, second_address, "client-two-after-handoff"); second.Expect("client-two-after-handoff");
    expected.insert(expected.end(), {"client-one-after-handoff", "client-two-after-handoff"});
    // Cross-worker arrival order is unspecified; every exact payload must occur once.
    std::sort(expected.begin(), expected.end());
    auto actual = run.observed; std::sort(actual.begin(), actual.end());
    EXPECT_EQ(actual, expected);
    EXPECT_FALSE(Readable(run.peer.Fd(), 100ms));
    run.child->Stop();
    std::regex expression(R"(UDP passive handoff worker=(\d+) previous_worker=(\d+) session=(\d+)\b)");
    size_t count = 0;
    for (const auto* name : {"child.log", "handoff.log"}) {
        if (!std::filesystem::exists(run.root.Path() / name)) continue;
        auto text = ReadFile(run.root.Path() / name);
        size_t sink_count = 0;
        for (std::sregex_iterator it(text.begin(), text.end(), expression), end; it != end; ++it) {
            auto worker = std::stoul((*it)[1].str()), previous = std::stoul((*it)[2].str());
            EXPECT_LT(worker, 4u); EXPECT_LT(previous, 4u); EXPECT_NE(worker, previous);
            EXPECT_EQ(std::stoull((*it)[3].str()), ReadBigEndian(first.session));
            ++sink_count;
        }
        count = std::max(count, sink_count);
    }
    EXPECT_GE(count, 2u) << "requires actual repeated committed four-worker passive handoffs";
}

void ExerciseIsolation(RelayRun& run) {
    Client first(run.port, run.peer.Port(), run.Native());
    Client second(run.port, run.peer.Port(), run.Native(), true);
    if (run.Native()) second.socket = first.socket;
    first.Send("client-one-round-one"); second.Send("client-two-round-one");
    auto initial = run.Round({"client-one-round-one", "client-two-round-one"});
    auto one = initial.at("client-one-round-one"), two = initial.at("client-two-round-one");
    EXPECT_NE(one.Port(), two.Port());
    Reply(run.peer, two, "reply-for-client-two"); second.Expect("reply-for-client-two");
    Reply(run.peer, one, "reply-for-client-one"); first.Expect("reply-for-client-one");
    second.Send("client-two-round-two"); first.Send("client-one-round-two");
    auto next = run.Round({"client-one-round-two", "client-two-round-two"});
    EXPECT_TRUE(next.at("client-one-round-two").SameEndpoint(one));
    EXPECT_TRUE(next.at("client-two-round-two").SameEndpoint(two));
    Reply(run.peer, one, "round-two-for-client-one"); first.Expect("round-two-for-client-one");
    Reply(run.peer, two, "round-two-for-client-two"); second.Expect("round-two-for-client-two");
    if (run.value.mode == "isolation_cancel") {
        first.socket->Close();
        second.Send("client-two-after-cancel");
        EXPECT_TRUE(run.Round({"client-two-after-cancel"}).at("client-two-after-cancel").SameEndpoint(two));
        Reply(run.peer, two, "survivor-after-cancel"); second.Expect("survivor-after-cancel");
    }
    EXPECT_EQ(run.observed.size(), run.value.mode == "isolation_cancel" ? 5u : 4u);
    EXPECT_FALSE(Readable(run.peer.Fd(), 100ms));
}

void ExerciseEmptyDatagrams(RelayRun& run) {
    const std::string host = run.value.mode == "native_empty_short_domain" ? "a" : "127.0.0.1";
    Client first(run.port, run.Destination(), true, false, host, run.value.cipher);
    Client second(run.port, run.Destination(), true, true, host, run.value.cipher);
    second.socket = first.socket;
    const std::vector<std::shared_ptr<Socket>> paths{first.socket};
    run.Rejected({}, first, paths);
    run.Rejected("malformed encrypted datagram", first, paths);
    auto forged = first.Encode({});
    forged.back() ^= 1;
    run.Rejected(forged, first, paths);

    const bool encrypted = run.value.protocol == "shadowsocks";
    auto exchange = [&](Client& client, std::string_view request, std::string_view response) {
        client.Send(request);
        auto packet = Receive(run.peer);
        const auto plain = encrypted ? LegacyDecrypt(packet.payload) : packet.payload;
        const auto header = encrypted ? SocksAddress(53, host) : std::string{};
        Require(plain == header + std::string(request),
                "empty UDP changed outbound header, payload or boundary");
        run.observed.push_back(std::string(request));
        if (encrypted) {
            Reply(run.peer, packet, {});
            auto bad_tag = LegacyEncrypt(header + std::string(response));
            bad_tag.back() ^= 1;
            Reply(run.peer, packet, bad_tag);
            Reply(run.peer, packet, LegacyEncrypt(header + std::string(response)));
        } else {
            Reply(run.peer, packet, response);
        }
        client.Expect(response);
        return packet;
    };

    const auto one = exchange(first, {}, {});
    const auto two = exchange(second, {}, {});
    EXPECT_NE(one.Port(), two.Port());
    EXPECT_TRUE(exchange(first, "one-after-empty", {}).SameEndpoint(one));
    EXPECT_TRUE(exchange(second, "two-after-empty", "two-reply").SameEndpoint(two));
    run.Rejected(forged, first, paths);
    EXPECT_TRUE(exchange(first, {}, {}).SameEndpoint(one));
    EXPECT_TRUE(exchange(second, {}, {}).SameEndpoint(two));
    EXPECT_TRUE(exchange(first, "one-after-second-empty", "one-reply").SameEndpoint(one));
    EXPECT_TRUE(exchange(second, "two-after-second-empty", {}).SameEndpoint(two));
    EXPECT_EQ(run.observed, (std::vector<std::string>{
        "", "", "one-after-empty", "two-after-empty", "", "",
        "one-after-second-empty", "two-after-second-empty"}));
    EXPECT_FALSE(Readable(run.peer.Fd(), 100ms));
    EXPECT_FALSE(Readable(first.socket->Fd(), 100ms));
}

void ExerciseDns(RelayRun& run) {
    Client blocked(run.port, 53, false, false, run.value.protocol == "freedom" ? "udp-sink.test" : "127.0.0.1");
    auto start = std::chrono::steady_clock::now();
    blocked.Send("waiting-for-dns");
    std::unique_ptr<Client> survivor;
    if (run.value.mode == "shared_cancel") {
        survivor = std::make_unique<Client>(run.port, run.peer.Port(), false);
        survivor->Send("before-cancel"); run.Echo(run.peer, "before-cancel"); survivor->Expect("before-cancel");
    }
    EXPECT_TRUE(blocked.socket->Read(65536, 4s).empty());
    auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_GE(elapsed, 500ms); EXPECT_LT(elapsed, 3s);
    EXPECT_TRUE(Readable(run.dns.Fd(), 100ms));
    EXPECT_FALSE(Receive(run.dns).payload.empty());
    if (survivor) {
        auto large = LargePacket(); survivor->Send(large); run.Echo(run.peer, large); survivor->Expect(large);
        EXPECT_EQ(run.observed, (std::vector<std::string>{"before-cancel", large}));
    } else EXPECT_TRUE(run.observed.empty());
    EXPECT_FALSE(Readable(run.peer.Fd(), 100ms));
}

void ExerciseQuic(RelayRun& run, Client& client) {
    auto packets = QuicInitials();
    const bool complete = run.value.mode.ends_with("_fragmented");
    auto& selected = complete ? run.peer : run.fallback;
    auto& rejected = complete ? run.fallback : run.peer;
    std::vector<std::string> expected{packets[0]};
    auto started = std::chrono::steady_clock::now();
    client.Send(packets[0]);
    if (run.value.mode.ends_with("_missing")) {
        run.Echo(selected, packets[0]); client.Expect(packets[0], 1s);
        EXPECT_LT(std::chrono::steady_clock::now() - started, 1s);
    } else {
        std::this_thread::sleep_for(20ms);
        auto next = packets[1];
        if (run.value.mode.ends_with("_invalid")) next.back() ^= 1;
        else if (run.value.mode.ends_with("_interrupted")) next = "non-QUIC-between-CRYPTO-fragments";
        expected.push_back(next);
        auto terminal = std::chrono::steady_clock::now();
        client.Send(next);
        run.Echo(selected, packets[0]); client.Expect(packets[0], 1s);
        EXPECT_LT(std::chrono::steady_clock::now() - terminal, 1s);
        run.Echo(selected, next); client.Expect(next, 1s);
    }
    if (!complete) {
        expected.push_back(packets[1]); client.Send(packets[1]); run.Echo(selected, packets[1]); client.Expect(packets[1], 1s);
    }
    for (const auto& packet : {LargePacket(), std::string("after-QUIC-sniff")}) {
        expected.push_back(packet); client.Send(packet); run.Echo(selected, packet); client.Expect(packet, 1s);
    }
    client.Finish(); client.ExpectEof();
    EXPECT_EQ(run.observed, expected);
    EXPECT_FALSE(Readable(rejected.Fd(), 100ms));
    EXPECT_FALSE(Readable(selected.Fd(), 100ms));
    EXPECT_FALSE(Readable(run.dns.Fd(), 100ms));
}

class UdpRelay : public testing::TestWithParam<Case> {};
TEST_P(UdpRelay, PreservesProtocolDatagramsAndAssociationLifetime) {
    const auto& item = GetParam();
    SCOPED_TRACE(item.protocol + "/" + item.mode + "/" + item.cipher);
    RelayRun run(item);
    if (run.EmptyDatagrams()) { ExerciseEmptyDatagrams(run); return; }
    if (run.Handoff()) { ExerciseHandoff(run); return; }
    if (run.IsIsolation()) { ExerciseIsolation(run); return; }
    if (item.mode == "dns_timeout" || item.mode == "shared_cancel") { ExerciseDns(run); return; }
    Client client(run.port, run.Destination(), run.Native());
    if (run.IsQuic()) { ExerciseQuic(run, client); return; }
    std::vector<std::string> expected;
    if (run.Sniffing()) {
        bool burst = item.mode.ends_with("_burst");
        expected = {"first-datagram", LargePacket(), "third-datagram"};
        client.Send(expected[0]);
        if (!burst) { run.Echo(run.peer, expected[0]); client.Expect(expected[0]); }
        client.Send(expected[1]); client.Send(expected[2]);
        if (burst) { run.Echo(run.peer, expected[0]); client.Expect(expected[0]); }
        for (size_t i = 1; i < expected.size(); ++i) { run.Echo(run.peer, expected[i]); client.Expect(expected[i]); }
        client.Finish();
    } else if (item.mode == "late_reply") {
        expected = {"late"}; client.Send("late"); client.Finish();
        run.Echo(run.peer, "late", true); client.Expect("late");
    } else {
        expected = {"first-datagram", LargePacket()};
        for (const auto& packet : expected) { client.Send(packet); run.Echo(run.peer, packet); client.Expect(packet); }
        client.Finish();
    }
    client.ExpectEof();
    EXPECT_EQ(run.observed, expected);
    EXPECT_FALSE(Readable(run.peer.Fd(), 100ms));
}

std::vector<Case> Cases() {
    std::vector<Case> result{{"shadowsocks", "dns_timeout", {}}, {"freedom", "dns_timeout", {}},
        {"freedom", "shared_cancel", {}}, {"freedom", "isolation", {}}, {"freedom", "isolation_cancel", {}},
        {"freedom", "native_isolation", {}}, {"freedom", "native_ss2022_isolation", "aes"},
        {"freedom", "native_ss2022_isolation", "chacha"}};
    for (const auto* protocol : {"freedom", "shadowsocks"})
        for (const auto* mode : {"echo", "late_reply", "sniff_echo", "native_sniff_echo", "sniff_burst", "native_sniff_burst"})
            result.push_back({protocol, mode, {}});
    for (const auto* protocol : {"freedom", "shadowsocks"})
        for (const auto* cipher : {"", "aes", "chacha"})
            result.push_back({protocol, "native_empty_datagrams", cipher});
    for (const auto* cipher : {"", "aes", "chacha"})
        result.push_back({"shadowsocks", "native_empty_short_domain", cipher});
    for (const auto* prefix : {"quic_", "native_quic_"})
        for (const auto* suffix : {"fragmented", "missing", "interrupted", "invalid"})
            result.push_back({"shadowsocks", std::string(prefix) + suffix, {}});
    return result;
}
INSTANTIATE_TEST_SUITE_P(ProtocolAndOutboundMatrix, UdpRelay, testing::ValuesIn(Cases()),
    [](const testing::TestParamInfo<Case>& info) { return info.param.protocol + "_" + info.param.mode + (info.param.cipher.empty() ? "" : "_" + info.param.cipher); });
} // namespace
} // namespace cnode::e2e::udp
