#include "tls_wire.hpp"

namespace cnode::e2e {
namespace {
using namespace tls;

// REALITY dest 回落拨号仍在握手期限内；进入转发后期限解除，回落连接按空闲超时
// 存活，不被 timeouts.handshake 截断。
TEST(RealityFallbackDeadline, RelayOutlivesTheHandshakeDeadline) {
    TempDir root;
    auto reservation = Socket::ReserveTcp(), destination = Socket::Listen();
    const auto port = reservation.Port();
    PeerThread fallback([&] {
        auto socket = destination.Accept();
        Require(socket.ReadExact(5) == "first", "fallback first bytes");
        std::this_thread::sleep_for(1500ms);
        socket.Write("late-1");
        Require(socket.ReadExact(6) == "second", "fallback second bytes");
        std::this_thread::sleep_for(1500ms);
        socket.Write("late-2");
    });
    Json stream{{"network", "tcp"}, {"security", "reality"},
        {"realitySettings", {{"dest", "127.0.0.1:" + std::to_string(destination.Port())}, {"xver", 0},
            {"serverNames", {"example.com"}}, {"privateKey", "6Epi9xRmv1RL-Kiqrj6Fl523a9eagFMTc-oyzGC5IU8"},
            {"shortIds", {"0123456789abcdef"}}}}};
    Config(root.Path(), Json::array({Inbound(port, stream)}), Json::array({Direct()}),
           {{"timeouts", {{"handshake", 1}, {"connIdle", 40}}}});
    auto child = Start(root.Path());
    auto socket = Socket::Connect(port);
    socket.Write("first");
    EXPECT_EQ(socket.ReadExact(6, 5s), "late-1");
    socket.Write("second");
    EXPECT_EQ(socket.ReadExact(6, 5s), "late-2");
    fallback.Join();
    EXPECT_TRUE(child->Running());
}
} // namespace
} // namespace cnode::e2e
