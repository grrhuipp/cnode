#include "anytls_sessions.hpp"
#include "reference_support.hpp"

namespace cnode::e2e::sessions {
class ReferenceFin : public testing::TestWithParam<std::tuple<bool, bool>> {};
TEST_P(ReferenceFin, PinnedUnmodifiedReferenceHasIdenticalClosureSemantics) {
    const auto [server, remote] = GetParam();
    const std::string binary = server ? CNODE_REFERENCE_ANYTLS_SERVER : CNODE_REFERENCE_ANYTLS_CLIENT;
    reference::VerifyAnyTls(binary, server ? "server" : "client");
    reference::BinaryGuard guard({Binary(), binary});
    if (server) ServerFin(remote, binary);
    else ClientFin(remote, binary);
    guard.Check();
}
INSTANTIATE_TEST_SUITE_P(All, ReferenceFin, testing::Combine(testing::Bool(), testing::Bool()));
class ReferenceSessionEnd : public testing::TestWithParam<bool> {};
TEST_P(ReferenceSessionEnd, PinnedUnmodifiedClientDeliversFinishedStreamAcrossSessionEnd) {
    const std::string binary = CNODE_REFERENCE_ANYTLS_CLIENT;
    reference::VerifyAnyTls(binary, "client");
    reference::BinaryGuard guard({Binary(), binary});
    ClientFinThenSessionEnd(GetParam(), binary);
    guard.Check();
}
INSTANTIATE_TEST_SUITE_P(All, ReferenceSessionEnd, testing::Bool(),
                         [](const auto& info) { return info.param ? "Alert" : "TransportClose"; });
class ReferenceInboundSessionEnd : public testing::TestWithParam<std::tuple<SessionEnd, bool>> {};
TEST_P(ReferenceInboundSessionEnd, PinnedUnmodifiedServerDeliversFinishedUpload) {
    const auto [end, uot] = GetParam();
    const std::string binary = CNODE_REFERENCE_ANYTLS_SERVER;
    reference::VerifyAnyTls(binary, "server");
    reference::BinaryGuard guard({Binary(), binary});
    ServerFinThenSessionEnd(end, uot, binary);
    guard.Check();
}
INSTANTIATE_TEST_SUITE_P(All, ReferenceInboundSessionEnd,
                         testing::Combine(testing::Values(SessionEnd::KeepOpen, SessionEnd::TransportClose,
                                                          SessionEnd::Alert),
                                          testing::Bool()),
                         SessionEndCase);
TEST(ReferenceRejectedFin, PinnedUnmodifiedServerAcknowledgesRejectedFinishedStream) {
    const std::string binary = CNODE_REFERENCE_ANYTLS_SERVER;
    reference::VerifyAnyTls(binary, "server");
    reference::BinaryGuard guard({Binary(), binary});
    ServerFinRejected(binary);
    guard.Check();
}
// 参考客户端与服务端之间的密文闸：hold 期间客户端→服务端的字节先攒着，放行时一次写出，让一整条流
// （SYN、地址、载荷、FIN）在同一个可读事件里到达服务端。
class BurstGate {
public:
    explicit BurstGate(uint16_t upstream)
        : upstream_(upstream), server_([this](Socket socket) { Pump(std::move(socket)); }) {}
    uint16_t Port() const { return server_.Port(); }
    void Stop() { server_.Stop(); }
    std::atomic<bool> hold = false;
    std::atomic<unsigned> connections = 0, closedByClient = 0;
    std::atomic<size_t> held = 0;

private:
    void Pump(Socket client) {
        ++connections;
        auto server = Socket::Connect(upstream_);
        std::string pending;
        while (!server_.Stopping()) {
            pollfd ready[2] = {{client.Fd(), POLLIN, 0}, {server.Fd(), POLLIN, 0}};
            Require(::poll(ready, 2, 5) >= 0 || errno == EINTR, "gate poll failed");
            if (ready[0].revents) {
                std::string bytes;
                try {
                    bytes = client.Read();
                } catch (const std::system_error&) {}
                if (bytes.empty()) {
                    ++closedByClient;
                    return;
                }
                pending += bytes;
                held = pending.size();
            }
            if (!hold && !pending.empty()) {
                server.Write(pending);
                pending.clear();
                held = 0;
            }
            if (ready[1].revents) {
                std::string bytes;
                try {
                    bytes = server.Read();
                } catch (const std::system_error&) {}
                if (bytes.empty()) return;
                try {
                    client.Write(bytes);
                } catch (const std::system_error&) {
                    ++closedByClient;
                    return;
                }
            }
        }
    }
    const uint16_t upstream_;
    Server server_;
};
// 参考客户端同一会话上的第二条流在闸后攒成一个突发：SYN、地址、载荷、FIN 同时到达服务端。v2 客户端按会话等
// SYNACK，3 秒内等不到就拆掉整条会话；服务端应答后，会话必须活过这段等待，下一个请求仍复用同一条物理连接。
inline void ReferenceClientFinishedStream(bool referenceServer) {
    using Clock = std::chrono::steady_clock;
    std::atomic<unsigned> uploads = 0, closed = 0;
    Server target([&](Socket socket) {
        EXPECT_EQ(socket.ReadExact(8), "request!");
        ++uploads;
        socket.Write("accepted");
        Drain(socket, 15s, true);
        ++closed;
    });
    Node server;
    StartServer(server, referenceServer ? std::string(CNODE_REFERENCE_ANYTLS_SERVER) : std::string{});
    BurstGate gate(server.port);
    Node client;
    StartClient(client, gate.Port(), CNODE_REFERENCE_ANYTLS_CLIENT);
    {
        auto first = ClientApplication(client, true, target.Port());
        EXPECT_EQ(first.ReadExact(8), "accepted");
    }
    Until([&] { return closed.load() == 1; });
    gate.hold = true;
    const auto opened = Clock::now();
    ClientApplication(client, true, target.Port()).Close();
    size_t settled = 0;
    for (auto since = Clock::now(); Clock::now() - since < 300ms; std::this_thread::sleep_for(10ms)) {
        if (const auto size = gate.held.load(); size != settled) {
            settled = size;
            since = Clock::now();
        }
    }
    gate.hold = false;
    Until([&] { return uploads.load() == 2; });
    std::this_thread::sleep_until(opened + 3500ms);
    EXPECT_EQ(gate.closedByClient.load(), 0u);
    auto third = ClientApplication(client, true, target.Port());
    EXPECT_EQ(third.ReadExact(8), "accepted");
    EXPECT_EQ(gate.connections.load(), 1u);
    third.Close();
    EXPECT_TRUE(server.child->Running());
    client.child->Stop();
    if (referenceServer) server.child->Stop();
    else server.Stop();
    gate.Stop();
    target.Stop();
}
class ReferenceClientSynAck : public testing::TestWithParam<bool> {};
TEST_P(ReferenceClientSynAck, PinnedUnmodifiedClientKeepsSessionAfterFinishedStream) {
    const std::string client = CNODE_REFERENCE_ANYTLS_CLIENT, server = CNODE_REFERENCE_ANYTLS_SERVER;
    reference::VerifyAnyTls(client, "client");
    reference::VerifyAnyTls(server, "server");
    reference::BinaryGuard guard({Binary(), client, server});
    ReferenceClientFinishedStream(GetParam());
    guard.Check();
}
INSTANTIATE_TEST_SUITE_P(All, ReferenceClientSynAck, testing::Bool(),
                         [](const auto& info) { return info.param ? "ReferenceServer" : "CnodeServer"; });
} // namespace cnode::e2e::sessions
