#include "udp_wire.hpp"

namespace cnode::e2e::udp {
namespace {

// Xray refreshes a UDP association's inactivity timer in both directions: a
// native association that only receives replies outlives connIdle and keeps
// its outbound socket, so the target still sees the same source endpoint.
TEST(UdpIdleActivity, DownlinkTrafficKeepsNativeAssociation) {
    TempDir root;
    PortReservation reservation(true);
    auto target = Socket::BindUdp();
    WriteJson(root.Path(), "config.json", Json{{"workers", 1},
        {"timeouts", {{"connIdle", 2}, {"downlinkOnly", 1}}},
        {"log", {{"logDir", (root.Path() / "logs").string()}}}});
    WriteJson(root.Path(), "inbounds.json", Json::array({{{"tag", "native-ss"},
        {"protocol", "shadowsocks"}, {"listen", "127.0.0.1"}, {"port", reservation.port},
        {"settings", {{"method", "aes-128-gcm"}, {"clients", Json::array({{{"password", "secret"}}})}}}}}));
    WriteJson(root.Path(), "outbounds.json", Json::array({{{"tag", "direct"},
        {"protocol", "freedom"}, {"settings", Json::object()}}}));
    WriteJson(root.Path(), "routing.json", Json{{"rules", Json::array({{{"type", "field"},
        {"inboundTag", Json::array({"native-ss"})}, {"outboundTag", "direct"}}})}});
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForServerStart();

    Client client(reservation.port, target.Port(), true);
    client.Send("open");
    const auto first = Receive(target);
    ASSERT_EQ(first.payload, "open");
    // Replies alone for well past connIdle.
    const auto until = std::chrono::steady_clock::now() + 3500ms;
    for (int tick = 0; std::chrono::steady_clock::now() < until; ++tick) {
        const auto reply = "tick-" + std::to_string(tick);
        Reply(target, first, reply);
        client.Expect(reply, 1s);
        std::this_thread::sleep_for(250ms);
    }
    client.Send("again");
    const auto again = Receive(target);
    EXPECT_EQ(again.payload, "again");
    EXPECT_TRUE(again.SameEndpoint(first)) << "the receiving association was reclaimed as idle";
    EXPECT_EQ(child.Stop(), 0);
}

}  // namespace
}  // namespace cnode::e2e::udp
