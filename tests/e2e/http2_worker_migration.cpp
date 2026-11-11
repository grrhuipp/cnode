#include "http2_peer.hpp"

namespace cnode::e2e::http2 {
namespace {
class Http2WorkerMigration : public testing::TestWithParam<std::tuple<bool, std::string>> {};
TEST_P(Http2WorkerMigration, SourceIndependentSessionsMergeAndDetachWithActiveReads) {
    auto [tls, mode] = GetParam();
    Targets target([](Socket& socket) { for (;;) { auto data = socket.Read(16384, 30s); if (data.empty()) break; socket.Write(data); } });
    Socket extra_reservation = Socket::ReserveTcp(); const auto extra = extra_reservation.Port();
    Node node; node.Setup("xhttp", tls, mode == "stream-up" ? "stream-up" : "packet-up", 4);
    if (mode == "isolation") {
        auto inbounds = Json::parse(ReadFile(node.root.Path() / "inbounds.json"));
        auto second = inbounds.at(0); second["tag"] = "isolated-in"; second["port"] = extra; inbounds.push_back(second);
        WriteJson(node.root.Path(), "inbounds.json", inbounds);
        auto routing = Json::parse(ReadFile(node.root.Path() / "routing.json"));
        routing["rules"].at(0)["inboundTag"].push_back("isolated-in");
        WriteJson(node.root.Path(), "routing.json", routing);
    }
    PatchConfig(node.root.Path(), [](Json& config) {
        config["workers"] = 4; config["log"]["enable"] = true; config["log"]["loglevel"] = "debug";
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
    std::string("packet-up"), std::string("stream-up"), std::string("isolation"))));
} // namespace
} // namespace cnode::e2e::http2
