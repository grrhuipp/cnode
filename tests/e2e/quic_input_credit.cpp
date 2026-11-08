#include "quic_peer.hpp"

#include <atomic>
#include <stdexcept>

namespace cnode::e2e::quic {
namespace {

void Exchange(Peer& peer, int64_t stream, std::string_view bytes, std::string& expected) {
    expected += bytes;
    peer.Send(stream, bytes);
    peer.Wait([&] { return peer.Payload(stream) == expected; });
}

enum class Retirement { ClientReset, InputBudget };
class QuicInputCredit : public testing::TestWithParam<Retirement> {};

TEST_P(QuicInputCredit, RetiredRequestCannotExhaustUnrelatedStreams) {
    TempDir root;
    DnsBlackhole dns;
    std::atomic<unsigned> targets_opened = 0;
    Targets target([&](Socket& socket) {
        ++targets_opened;
        for (;;) {
            const auto bytes = socket.Read(65536, 30s);
            if (bytes.empty()) break;
            socket.Write(bytes);
        }
    });
    auto reservation = Socket::BindUdp();
    const auto port = reservation.Port();
    Configure(root.Path(), HysteriaInbound(port),
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    auto config = Json::parse(ReadFile(root.Path() / "config.json"));
    config["dns"] = {{"servers", Json::array({"127.77.0.2:" + std::to_string(dns.socket.Port())})},
                     {"timeout", 60}};
    config["timeouts"] = {{"handshake", 10}, {"connIdle", 120}, {"write", 10},
                           {"uplinkOnly", 1}, {"downlinkOnly", 1}};
    WriteJson(root.Path(), "config.json", config);
    reservation.Close();
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForLog("server started");
    Peer peer(port);
    const std::string target_address = "127.0.0.1:" + std::to_string(target.Port());
    const auto control = peer.Open(target_address);
    std::string expected;
    Exchange(peer, control, "control-ready", expected);

    const bool client_reset = GetParam() == Retirement::ClientReset;
    const size_t rounds = client_reset ? 272 : 40;
    const size_t size = client_reset ? 64 * 1024 : 768 * 1024;
    std::string payload(size, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i % 251);
    for (size_t round = 0; round < rounds; ++round) {
        try {
            const std::string host = "hold-" + std::to_string(round) + ".credit.test";
            const auto stream = peer.Open(host + ":443", "x");
            peer.Wait([&] { return dns.Observed(host); });
            peer.Send(stream, payload);
            if (client_reset) {
                peer.Wait([&] { return peer.AllAcknowledged(stream); }, 3s);
                peer.Reset(stream);
            }
            peer.Wait([&] { return peer.StreamClosed(stream); }, 3s);
            // This uses the original stream and QUIC connection, not a reconnect.
            Exchange(peer, control, "|" + std::to_string(round), expected);
        } catch (const std::exception& error) {
            throw std::runtime_error("QUIC credit round " + std::to_string(round) + ": " + error.what());
        }
    }
    const auto fresh = peer.Open(target_address, "new-stream-after-retirement");
    peer.Wait([&] { return peer.Payload(fresh) == "new-stream-after-retirement"; });
    EXPECT_FALSE(peer.Closed());
    EXPECT_EQ(peer.Payload(control), expected);
    EXPECT_EQ(targets_opened.load(), 2);
    peer.Reset(fresh);
    peer.Reset(control);
    peer.Wait([&] { return peer.StreamClosed(fresh) && peer.StreamClosed(control); });
    EXPECT_EQ(server.Stop(), 0);
    target.Join();
}

INSTANTIATE_TEST_SUITE_P(TerminalPaths, QuicInputCredit,
    testing::Values(Retirement::ClientReset, Retirement::InputBudget),
    [](const testing::TestParamInfo<Retirement>& info) {
        return info.param == Retirement::ClientReset ? "ClientReset" : "InputBudget";
    });

TEST(QuicInputCredit, NormalFinKeepsConnectionReusableBeyondItsInitialWindow) {
    TempDir root;
    Targets target([](Socket& socket) {
        for (;;) {
            const auto bytes = socket.Read(65536, 30s);
            if (bytes.empty()) break;
            socket.Write(bytes);
        }
    });
    auto reservation = Socket::BindUdp();
    const auto port = reservation.Port();
    Configure(root.Path(), HysteriaInbound(port),
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    reservation.Close();
    Child server({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    server.WaitForLog("server started");
    Peer peer(port);
    const std::string address = "127.0.0.1:" + std::to_string(target.Port());
    std::string payload(2 * 1024 * 1024, '\0');
    for (size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<char>(i % 251);
    for (size_t round = 0; round < 9; ++round) {
        const auto stream = peer.Open(address);
        peer.Send(stream, payload, true);
        peer.Wait([&] {
            return peer.StreamClosed(stream) && peer.Payload(stream) == payload;
        }, 10s);
        EXPECT_TRUE(peer.AllAcknowledged(stream));
    }
    const auto fresh = peer.Open(address, "after-normal-fin");
    peer.Wait([&] { return peer.Payload(fresh) == "after-normal-fin"; });
    EXPECT_FALSE(peer.Closed());
    peer.Reset(fresh);
    peer.Wait([&] { return peer.StreamClosed(fresh); });
    EXPECT_EQ(server.Stop(), 0);
    target.Join();
}

} // namespace
} // namespace cnode::e2e::quic
