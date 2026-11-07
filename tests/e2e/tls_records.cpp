#include "tls_wire.hpp"

namespace cnode::e2e {
namespace {
using namespace tls;

TEST(TlsRecords, CoalescedRecordsRemainReadableAfterIdleCollection) {
    TempDir root;
    auto reservation = Socket::Listen();
    auto port = reservation.Port();
    Config(root.Path(), Json::array({AnyInbound(port)}), Json::array({Direct()}));
    reservation.Close();
    auto child = Start(root.Path());
    TlsContext context(false);
    WireTls client(Socket::Connect(port), context);
    client.Write(Auth());
    while (Frame(client).command != 10) {}
    for (auto delay : {0s, 12s}) {
        std::this_thread::sleep_for(delay);
        const auto first = client.Encrypt(AnyTlsFrame(8, 0));
        const auto second = client.Encrypt(AnyTlsFrame(8, 0));
        client.Raw().Write(first + second);
        unsigned replies = 0;
        while (replies < 2) if (Frame(client).command == 9) ++replies;
        EXPECT_TRUE(child->Running());
    }
}

struct CancellationCase { bool partial; bool resume; bool idle; };
class TlsReadCancellation : public testing::TestWithParam<CancellationCase> {};
TEST_P(TlsReadCancellation, LogicalFinJoinsPendingReadAndEmitsCloseNotify) {
    const auto param = GetParam();
    TempDir root;
    auto listener = Socket::Listen();
    auto reservation = Socket::Listen();
    const auto port = reservation.Port();
    Json outbound{{"tag", "direct"}, {"protocol", "trojan"},
        {"settings", {{"servers", {{{"address", "127.0.0.1"}, {"port", listener.Port()}, {"password", "secret"}}}}}},
        {"streamSettings", TlsSettings(false)}};
    Config(root.Path(), Json::array({AnyInbound(port)}), Json::array({outbound}));
    std::atomic<bool> partial_sent{false}, resume{false}, peer_eof{false}, close_notify{false};
    const std::string resumed = "incomplete TLS record must never become payload";
    std::string extra;
    PeerThread peer([&] {
        TlsContext server(true);
        WireTls secured(listener.Accept(), server, true);
        const auto expected = TrojanRequest("request!");
        Require(secured.ReadExact(expected.size()) == expected, "Trojan request mismatch");
        secured.Write("accepted");
        std::string tail;
        if (param.partial) {
            auto wire = secured.Encrypt(resumed);
            Require(wire.size() > 6, "TLS record too short");
            secured.Raw().Write(std::string_view(wire).substr(0, 6));
            tail = wire.substr(6);
        }
        partial_sent = true;
        if (param.resume) {
            Until([&] { return resume.load(); }, 20s);
            secured.Raw().Write(tail);
        }
        for (;;) {
            auto data = secured.Read(65536, 20s);
            if (data.empty()) break;
            extra += data;
        }
        close_notify = secured.close_notify;
        // An incomplete server record cannot be followed by a TLS alert. TCP
        // EOF acknowledges the client's close_notify only after it was observed.
        secured.Raw().ShutdownWrite();
        Require(secured.Raw().Read(65536, 2s).empty(), "bytes after TLS shutdown");
        peer_eof = true;
    });
    reservation.Close();
    auto child = Start(root.Path());
    TlsContext context(false);
    WireTls client(Socket::Connect(port), context);
    client.Write(Auth() + AnyTlsFrame(1, 1) + AnyTlsFrame(2, 1, SocksAddress(443) + "request!"));
    std::string payload;
    unsigned fins = 0;
    auto collect = [&](const AnyTlsRecord& record) {
        if (record.stream == 1 && record.command == 2) payload += record.payload;
        if (record.stream == 1 && record.command == 3) ++fins;
    };
    while (payload.size() < 8) collect(Frame(client));
    ASSERT_EQ(payload, "accepted");
    Until([&] { return partial_sent.load(); });
    std::this_thread::sleep_for(param.idle ? 12s : 100ms);
    if (param.resume) {
        resume = true;
        while (payload.size() < 8 + resumed.size()) collect(Frame(client));
    }
    auto started = std::chrono::steady_clock::now();
    client.Write(AnyTlsFrame(3, 1));
    for (const auto& record : Barrier(client)) collect(record);
    Until([&] { return peer_eof.load(); }, 1s);
    EXPECT_LT(std::chrono::steady_clock::now() - started, 1s);
    for (const auto& record : Barrier(client)) collect(record);
    peer.Join();
    EXPECT_TRUE(close_notify.load());
    EXPECT_TRUE(extra.empty());
    EXPECT_EQ(fins, 0u);
    EXPECT_EQ(payload, "accepted" + (param.resume ? resumed : std::string{}));
    EXPECT_TRUE(child->Running());
}
INSTANTIATE_TEST_SUITE_P(ActiveAndCollected, TlsReadCancellation,
    testing::Values(CancellationCase{false, false, false}, CancellationCase{true, false, false},
                    CancellationCase{false, false, true}, CancellationCase{true, false, true},
                    CancellationCase{true, true, false}, CancellationCase{true, true, true}));

TEST(TlsRecords, BlockedCiphertextWriteSurvivesIdleCollection) {
    TempDir root;
    auto listener = Socket::Listen();
    auto reservation = Socket::Listen();
    const auto port = reservation.Port();
    Config(root.Path(), Json::array({AnyInbound(port)}), Json::array({Direct()}));
    std::string data(16 * 1024 * 1024, '\0');
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<char>(i % 256);
    std::atomic<bool> started{false}, drained{false};
    PeerThread backend([&] {
        auto socket = listener.Accept();
        Require(socket.ReadExact(8) == "request!", "backend request");
        int size = 8192;
        Require(setsockopt(socket.Fd(), SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0, "send buffer");
        started = true;
        socket.Write(data, 30s);
        drained = true;
        Require(socket.Read(1, 20s).empty(), "data after logical FIN");
    });
    reservation.Close();
    auto child = Start(root.Path());
    TlsContext context(false);
    WireTls client(Socket::Connect(port), context);
    int size = 65536;
    Require(setsockopt(client.Raw().Fd(), SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0, "receive buffer");
    client.Write(Auth() + AnyTlsFrame(1, 1) + AnyTlsFrame(2, 1, SocksAddress(listener.Port()) + "request!"));
    Until([&] { return started.load(); });
    std::this_thread::sleep_for(12s);
    EXPECT_FALSE(drained.load()) << "fixture failed to sustain ciphertext backpressure";
    EXPECT_TRUE(child->Running());
    size = 4 * 1024 * 1024;
    Require(setsockopt(client.Raw().Fd(), SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == 0, "receive buffer");
    std::string recovered;
    const auto deadline = std::chrono::steady_clock::now() + 15s;
    while (recovered.size() < data.size()) {
        Require(std::chrono::steady_clock::now() < deadline, "recovery deadline");
        auto record = Frame(client);
        if (record.command == 2 && record.stream == 1) recovered += record.payload;
    }
    EXPECT_EQ(recovered, data);
    client.Write(AnyTlsFrame(3, 1));
    Barrier(client);
    backend.Join();
    EXPECT_TRUE(child->Running());
}
} // namespace
} // namespace cnode::e2e
