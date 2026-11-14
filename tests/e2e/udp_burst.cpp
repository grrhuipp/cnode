#include "udp_wire.hpp"

#include <set>

namespace cnode::e2e::udp {
namespace {

// A burst larger than a route flow's queue arrives before its outbound is
// ready. Stream-carried UDP waits in its transport instead (Xray's pipes
// block the same way): every datagram arrives and the association lives on.
TEST(UdpBurst, StreamCarriedBurstArrivesWholeAndKeepsItsAssociation) {
    TempDir root;
    PortReservation reservation;
    auto target = Socket::BindUdp();
    const int buffer = 4 << 20;
    ASSERT_EQ(::setsockopt(target.Fd(), SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer)), 0);
    Configure(root.Path(),
        {{"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", reservation.port},
         {"settings", {{"clients", Json::array({{{"id", UserId}}})}}}},
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started");

    Client client(reservation.port, target.Port(), false);
    constexpr size_t kBurst = 512;
    for (size_t i = 0; i < kBurst; ++i) client.Send("burst-" + std::to_string(i));
    std::set<std::string> received;
    Datagram last;
    while (received.size() < kBurst) {
        last = Receive(target);
        received.insert(last.payload);
    }
    EXPECT_EQ(received.size(), kBurst);
    Reply(target, last, "after-burst");
    client.Expect("after-burst");
    client.Send("still-open");
    EXPECT_EQ(Receive(target).payload, "still-open");
    EXPECT_EQ(child.Stop(), 0);
}

}  // namespace
}  // namespace cnode::e2e::udp
