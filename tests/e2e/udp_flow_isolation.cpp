#include "udp_wire.hpp"

namespace cnode::e2e::udp {
namespace {

std::string TrojanPacket(std::string_view address, std::string_view payload) {
    return std::string(address) + BigEndian(payload.size(), 2) + "\r\n" + std::string(payload);
}

// Trojan inbound and VLESS inbound behind freedom, with port 9 routed to
// blackhole and a resolver that accepts queries and never answers.
class FlowIsolationRun {
public:
    FlowIsolationRun() : resolver(Socket::BindUdp(0, "127.77.0.2")) {
        WriteJson(root.Path(), "config.json", Json{{"workers", 1},
            {"timeouts", {{"write", 1}, {"connIdle", 30}, {"downlinkOnly", 1}}},
            {"dns", {{"servers", Json::array({"127.77.0.2:" + std::to_string(resolver.Port())})},
                     {"timeout", 1}}},
            {"log", {{"logDir", (root.Path() / "logs").string()}}}});
        WriteJson(root.Path(), "inbounds.json", Json::array({
            {{"tag", "trojan-udp"}, {"protocol", "trojan"}, {"listen", "127.0.0.1"},
             {"port", trojan.port}, {"routingEnabled", true},
             {"settings", {{"clients", Json::array({{{"password", "secret"}}})}}}},
            {{"tag", "vless-udp"}, {"protocol", "vless"}, {"listen", "127.0.0.1"},
             {"port", vless.port}, {"routingEnabled", true},
             {"settings", {{"clients", Json::array({{{"id", UserId}}})}}}}}));
        WriteJson(root.Path(), "outbounds.json", Json::array({
            {{"tag", "direct"}, {"protocol", "freedom"}, {"settings", Json::object()}},
            {{"tag", "block"}, {"protocol", "blackhole"}, {"settings", Json::object()}}}));
        WriteJson(root.Path(), "routing.json", Json{{"domainStrategy", "AsIs"}, {"rules", Json::array({
            {{"type", "field"}, {"port", "9"}, {"outboundTag", "block"}},
            {{"type", "field"}, {"inboundTag", Json::array({"trojan-udp", "vless-udp"})},
             {"outboundTag", "direct"}}})}});
        child = std::make_unique<Child>(std::vector<std::string>{
            Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
        child->WaitForServerStart();
    }
    Socket OpenTrojan(std::string_view request_target) {
        auto session = Socket::Connect(trojan.port);
        session.Write(Sha224Hex("secret") + "\r\n\3" + std::string(request_target) + "\r\n");
        return session;
    }
    // A datagram to the live target crosses the session both ways.
    void ExpectAdmitted(Socket& session) {
        const auto admitted = SocksAddress(target.Port());
        session.Write(TrojanPacket(admitted, "admitted"));
        const auto request = Receive(target);
        EXPECT_EQ(request.payload, "admitted");
        Reply(target, request, "reply");
        const auto expected = TrojanPacket(admitted, "reply");
        EXPECT_EQ(session.ReadExact(expected.size(), 3s), expected)
            << "failed destinations ended the session";
    }

    TempDir root;
    PortReservation trojan, vless;
    Socket target = Socket::BindUdp();
    Socket resolver;
    std::unique_ptr<Child> child;
};

// Trojan UDP addresses every packet, like the sessions Xray serves through
// udp.Dispatcher: a destination whose route or resolution fails ends only its
// own flow, never the session other destinations use.
TEST(UdpFlowIsolation, FailedDestinationsKeepPerPacketAddressedSession) {
    FlowIsolationRun run;
    const auto unresolved = SocksAddress(53, "udp-sink.test");
    auto session = run.OpenTrojan(unresolved);
    session.Write(TrojanPacket(unresolved, "unresolved"));
    ASSERT_TRUE(Readable(run.resolver.Fd(), 3s)) << "the first destination never started resolving";
    session.Write(TrojanPacket(SocksAddress(9), "blocked"));
    // Outlast the resolver timeout: the unresolved flow ends after the
    // blocked one, leaving the session without any flow.
    std::this_thread::sleep_for(2500ms);
    run.ExpectAdmitted(session);
    EXPECT_FALSE(Readable(run.target.Fd(), 100ms));
    EXPECT_EQ(run.child->Stop(), 0);
}

// Even the first and only destination failing leaves the session open, as
// Xray's udp.Dispatcher dispatches the next packet again.
TEST(UdpFlowIsolation, FailedOnlyDestinationKeepsPerPacketAddressedSession) {
    FlowIsolationRun run;
    const auto blocked = SocksAddress(9);
    auto session = run.OpenTrojan(blocked);
    session.Write(TrojanPacket(blocked, "blocked"));
    std::this_thread::sleep_for(300ms);
    run.ExpectAdmitted(session);
    EXPECT_EQ(run.child->Stop(), 0);
}

// VLESS UDP is one Xray link: its failing destination ends the connection.
TEST(UdpFlowIsolation, FailedDestinationEndsSingleLinkSession) {
    FlowIsolationRun run;
    Client client(run.vless.port, 9, false);
    client.Send("blocked");
    EXPECT_TRUE(client.socket->Read(65536, 3s).empty()) << "a failed single link kept its connection";
    EXPECT_EQ(run.child->Stop(), 0);
}

}  // namespace
}  // namespace cnode::e2e::udp
