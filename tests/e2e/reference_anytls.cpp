#include "reference_support.hpp"

namespace cnode::e2e::reference {
namespace {
class AnyTlsReference : public testing::TestWithParam<std::tuple<bool, bool>> {};
TEST_P(AnyTlsReference, FinAndRecoveryReuseOnePhysicalConnection) {
    const auto [reference_client, local_eof] = GetParam();
    VerifyAnyTls(CNODE_REFERENCE_ANYTLS_CLIENT, "client");
    VerifyAnyTls(CNODE_REFERENCE_ANYTLS_SERVER, "server");
    BinaryGuard binaries{Binary(), CNODE_REFERENCE_ANYTLS_CLIENT, CNODE_REFERENCE_ANYTLS_SERVER};
    TempDir root;
    const auto response = Pattern(256 * 1024);
    std::atomic<bool> first_eof{false};
    TcpServer target([&](Socket socket, size_t number) {
        EXPECT_EQ(socket.ReadExact(8), "request!");
        socket.Write("accepted");
        if (local_eof && number == 0) {
            EXPECT_EQ(socket.Read(65536, 1s), "");
            first_eof = true;
        } else socket.Write(response);
    });
    const auto server_port = TcpPort(), front_port = TcpPort();
    Bridge bridge(server_port);
    std::unique_ptr<Child> reference;
    if (reference_client) {
        Configure(root.Path(), {{"protocol", "anytls"}, {"listen", "127.0.0.1"}, {"port", server_port},
            {"settings", {{"clients", Json::array({{{"password", "secret"}}})}}}, {"streamSettings", TlsSettings(true)}}, Freedom());
        reference = std::make_unique<Child>(std::vector<std::string>{CNODE_REFERENCE_ANYTLS_CLIENT, "-l", Address(front_port),
            "-s", Address(bridge.Port()), "-p", "secret", "-m", "1"}, root.Path() / "reference.log");
    } else {
        reference = std::make_unique<Child>(std::vector<std::string>{CNODE_REFERENCE_ANYTLS_SERVER, "-l", Address(server_port),
            "-p", "secret"}, root.Path() / "reference.log");
        Configure(root.Path(), VlessInbound(front_port), {{"protocol", "anytls"}, {"settings", {
            {"address", "127.0.0.1"}, {"port", bridge.Port()}, {"password", "secret"}, {"minIdleSession", 1}}},
            {"streamSettings", TlsSettings(false)}});
    }
    Child cnode({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "cnode.log");
    for (size_t number = 0; number != 2; ++number) {
        auto socket = Connect(front_port);
        if (reference_client) { Socks(socket, target.Port()); socket.Write("request!"); }
        else { socket.Write(VlessRequest(target.Port(), "request!")); EXPECT_EQ(socket.ReadExact(2), std::string("\0\0", 2)); }
        EXPECT_EQ(socket.ReadExact(8), "accepted");
        const auto started = std::chrono::steady_clock::now();
        if (local_eof && number == 0) socket.ShutdownWrite();
        else EXPECT_EQ(socket.ReadExact(response.size(), 1s), response);
        EXPECT_EQ(socket.Read(65536, 1s), "");
        EXPECT_LT(std::chrono::steady_clock::now() - started, 1s);
        if (local_eof && number == 0) Until([&] { return first_eof.load(); }, 1s);
        std::this_thread::sleep_for(100ms);
    }
    EXPECT_EQ(target.Count(), 2);
    EXPECT_EQ(bridge.Count(), 1);
    EXPECT_TRUE(cnode.Running());
    EXPECT_TRUE(reference->Running());
    cnode.Stop(); reference->Stop();
    bridge.Join(); target.Join();
    binaries.Check();
}
INSTANTIATE_TEST_SUITE_P(BothDirections, AnyTlsReference,
    testing::Combine(testing::Bool(), testing::Bool()), [](const auto& info) {
        return std::string(std::get<0>(info.param) ? "ReferenceClient" : "ReferenceServer") +
            (std::get<1>(info.param) ? "LocalEof" : "RemoteFin");
    });
} // namespace
} // namespace cnode::e2e::reference
