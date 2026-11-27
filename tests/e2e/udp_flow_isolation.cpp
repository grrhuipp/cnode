#include "udp_wire.hpp"

namespace cnode::e2e::udp {
namespace {

std::string TrojanPacket(std::string_view address, std::string_view payload) {
    return std::string(address) + BigEndian(payload.size(), 2) + "\r\n" + std::string(payload);
}

// Trojan UDP addresses every packet, like the sessions Xray serves through
// udp.Dispatcher: a destination whose route or resolution fails ends only its
// own flow, never the session other destinations use.
TEST(UdpFlowIsolation, FailedDestinationsKeepPerPacketAddressedSession) {
    TempDir root;
    PortReservation reservation;
    auto target = Socket::BindUdp();
    // Accepts the query and never answers: resolution of the first
    // destination fails only after the second destination was refused.
    auto resolver = Socket::BindUdp(0, "127.77.0.2");
    const std::string tag = "trojan-udp";
    WriteJson(root.Path(), "config.json", Json{{"workers", 1},
        {"timeouts", {{"write", 1}, {"connIdle", 30}, {"downlinkOnly", 1}}},
        {"dns", {{"servers", Json::array({"127.77.0.2:" + std::to_string(resolver.Port())})},
                 {"timeout", 1}}},
        {"log", {{"logDir", (root.Path() / "logs").string()}}}});
    WriteJson(root.Path(), "inbounds.json", Json::array({{{"tag", tag}, {"protocol", "trojan"},
        {"listen", "127.0.0.1"}, {"port", reservation.port}, {"routingEnabled", true},
        {"settings", {{"clients", Json::array({{{"password", "secret"}}})}}}}}));
    WriteJson(root.Path(), "outbounds.json", Json::array({
        {{"tag", "direct"}, {"protocol", "freedom"}, {"settings", Json::object()}},
        {{"tag", "block"}, {"protocol", "blackhole"}, {"settings", Json::object()}}}));
    WriteJson(root.Path(), "routing.json", Json{{"domainStrategy", "AsIs"}, {"rules", Json::array({
        {{"type", "field"}, {"port", "9"}, {"outboundTag", "block"}},
        {{"type", "field"}, {"inboundTag", Json::array({tag})}, {"outboundTag", "direct"}}})}});
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForServerStart();

    const auto unresolved = SocksAddress(53, "udp-sink.test");
    auto session = Socket::Connect(reservation.port);
    session.Write(Sha224Hex("secret") + "\r\n\3" + unresolved + "\r\n" +
                  TrojanPacket(unresolved, "unresolved"));
    ASSERT_TRUE(Readable(resolver.Fd(), 3s)) << "the first destination never started resolving";
    session.Write(TrojanPacket(SocksAddress(9), "blocked"));
    // Outlast the resolver timeout: the unresolved flow ends after the
    // blocked one, leaving the session without any flow.
    std::this_thread::sleep_for(2500ms);

    const auto admitted = SocksAddress(target.Port());
    session.Write(TrojanPacket(admitted, "admitted"));
    const auto request = Receive(target);
    EXPECT_EQ(request.payload, "admitted");
    Reply(target, request, "reply");
    const auto expected = TrojanPacket(admitted, "reply");
    EXPECT_EQ(session.ReadExact(expected.size(), 3s), expected)
        << "failed destinations ended the session";
    EXPECT_FALSE(Readable(target.Fd(), 100ms));
    EXPECT_EQ(child.Stop(), 0);
}

}  // namespace
}  // namespace cnode::e2e::udp
