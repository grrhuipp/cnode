#include "http2_peer.hpp"

namespace cnode::e2e::http2 {
namespace {
class Http2WorkerMigration : public testing::TestWithParam<std::tuple<bool, std::string>> {};
TEST_P(Http2WorkerMigration, SourceIndependentSessionsMergeAndDetachWithActiveReads) {
    auto [tls, mode] = GetParam();
    Targets target([](Socket& socket) { for (;;) { auto data = socket.Read(16384, 30s); if (data.empty()) break; socket.Write(data); } });
    Socket extra_reservation = Socket::ReserveTcp(); const auto extra = extra_reservation.Port();
    Node node; node.Setup("xhttp", tls, mode == "stream-up" || mode == "h2-stream" ? "stream-up" : "packet-up", 4);
    if (mode == "isolation") {
        auto inbounds = Json::parse(ReadFile(node.root.Path() / "inbounds.json"));
        auto second = inbounds.at(0); second["tag"] = "isolated-in"; second["port"] = extra; inbounds.push_back(second);
        WriteJson(node.root.Path(), "inbounds.json", inbounds);
        auto routing = Json::parse(ReadFile(node.root.Path() / "routing.json"));
        routing["rules"].at(0)["inboundTag"].push_back("isolated-in");
        WriteJson(node.root.Path(), "routing.json", routing);
    }
    PatchConfig(node.root.Path(), [](Json& config) {
        config["workers"] = 4; config["log"]["loglevel"] = "debug";
        config["timeouts"]["handshake"] = 15; config["timeouts"]["connIdle"] = 30;
    });
    node.Start();
    if (mode == "packet-up" || mode == "stream-up") {
        struct Session { std::string name; std::unique_ptr<Wire> down, upload; std::unique_ptr<Chunked> chunks; };
        std::vector<Session> sessions;
        for (unsigned i = 0; i < 8; ++i) {
            Session session; session.name = "h1-" + std::to_string(i);
            session.down = std::make_unique<Wire>(node.port, tls, "127.0.0." + std::to_string(i + 2), false);
            session.down->Write("GET /fixture/" + session.name + " HTTP/1.1\r\nHost: localhost\r\n\r\n");
            session.down->HttpResponse(); session.chunks = std::make_unique<Chunked>(*session.down);
            if (mode == "stream-up") {
                session.upload = std::make_unique<Wire>(node.port, tls, "127.0.0." + std::to_string(i + 40), false);
                session.upload->Write("POST /fixture/" + session.name + " HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n");
                session.upload->HttpResponse();
            }
            sessions.push_back(std::move(session));
        }
        for (unsigned sequence = 0; sequence < 5; ++sequence) {
            std::vector<std::unique_ptr<PeerThread>> exchanges;
            for (size_t i = 0; i < sessions.size(); ++i) exchanges.push_back(std::make_unique<PeerThread>([&, i, sequence] {
                auto& session = sessions[i];
                const auto payload = std::string{static_cast<char>(i), static_cast<char>(sequence)} + Pattern(251 * 7);
                const auto request = sequence ? payload : VlessRequest(target.Port(), payload);
                if (session.upload) session.upload->Write(Chunk(request));
                else H1Packet(node.port, tls, session.name, sequence, request, "127.0.0." + std::to_string(i + 60 + sequence * 8));
                const auto expected = (sequence ? std::string{} : std::string(2, '\0')) + payload;
                EXPECT_EQ(session.chunks->Exact(expected.size()), expected);
            }));
            for (auto& exchange : exchanges) exchange->Join();
        }
        node.child->Signal(SIGTERM); EXPECT_EQ(node.child->Wait(8s), 0);
    } else if (mode == "h2-relay") {
        // The downlink's Worker owns the session. Uploads on connections that
        // any Worker accepted reach it through the relay, including uploads
        // on an established connection that also serves another session.
        Peer down(node.port, tls, "xhttp", "127.0.0.7");
        down.Down(1, "relayed");
        std::string expected(2, '\0');
        unsigned sequence = 0;
        for (unsigned i = 0; i < 8; ++i, ++sequence) {
            const auto payload = "fresh-" + std::to_string(i);
            Peer upload(node.port, tls, "xhttp", "127.0.0." + std::to_string(20 + i));
            upload.Packet(1, "relayed", sequence, sequence ? payload : VlessRequest(target.Port(), payload));
            upload.Committed(1);
            EXPECT_FALSE(upload.goaway);
            expected += payload; down.Message(1, expected);
        }
        Peer mixed(node.port, tls, "xhttp", "127.0.0.40");
        mixed.Down(1, "mixed");
        for (uint32_t i = 0; i < 8; ++i, ++sequence) {
            const auto payload = "mixed-" + std::to_string(i);
            mixed.Packet(3 + 2 * i, "relayed", sequence, payload);
            mixed.Committed(3 + 2 * i);
            expected += payload; down.Message(1, expected);
        }
        EXPECT_FALSE(mixed.goaway);
        node.child->Signal(SIGTERM); EXPECT_EQ(node.child->Wait(8s), 0);
    } else if (mode == "h2-stream") {
        // A stream-up upload accepted by any Worker streams into its session
        // on the downlink's Worker within the relay window.
        for (unsigned i = 0; i < 8; ++i) {
            const auto name = "h2-stream-" + std::to_string(i);
            Peer down(node.port, tls, "xhttp", "127.0.0." + std::to_string(2 + i));
            down.Down(1, name);
            Peer up(node.port, tls, "xhttp", "127.0.0." + std::to_string(40 + i));
            up.wire.Write(Frame(1, 4, 1, Headers("xhttp", tls, "/fixture/" + name)));
            const auto payload = "stream-" + std::to_string(i);
            up.Data(1, VlessRequest(target.Port(), payload));
            std::string expected = std::string(2, '\0') + payload;
            down.Message(1, expected);
            // Several relay windows: the session must return credit as it
            // reads. Both peers are pumped, so neither direction stalls.
            const auto bulk = Pattern(3 * 1024 * 1024 + i);
            for (size_t offset = 0; offset < bulk.size(); offset += 64 * 1024) {
                const auto chunk = std::string_view(bulk).substr(offset, 64 * 1024);
                up.Data(1, chunk);
                expected += chunk;
                down.Message(1, expected);
            }
        }
        node.child->Signal(SIGTERM); EXPECT_EQ(node.child->Wait(8s), 0);
    } else {
        ASSERT_NE(extra, node.port);
        Peer first(node.port, tls, "xhttp", "127.0.0.7"), second(extra, tls, "xhttp", "127.0.0.8");
        first.Down(1, "same-id"); second.Down(1, "same-id");
        std::string expected[2]{std::string(2, '\0'), std::string(2, '\0')};
        for (unsigned sequence = 0; sequence < 4; ++sequence) for (unsigned i = 0; i < 2; ++i) {
            auto payload = "inbound-" + std::to_string(i) + "-sequence-" + std::to_string(sequence);
            H1Packet(i ? extra : node.port, tls, "same-id", sequence, sequence ? payload : VlessRequest(target.Port(), payload), "127.0.0." + std::to_string(90 + i));
            expected[i] += payload; (i ? second : first).Message(1, expected[i]);
        }
        node.child->Signal(SIGTERM); EXPECT_EQ(node.child->Wait(8s), 0);
    }
    target.Join();
}
INSTANTIATE_TEST_SUITE_P(FourWorkersTcpTls, Http2WorkerMigration, testing::Combine(testing::Bool(), testing::Values(
    std::string("packet-up"), std::string("stream-up"), std::string("isolation"),
    std::string("h2-relay"), std::string("h2-stream"))));
} // namespace
} // namespace cnode::e2e::http2
