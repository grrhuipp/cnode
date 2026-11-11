#include "anytls_sessions.hpp"

namespace cnode::e2e::sessions {
struct NegotiationCase {
    const char* name;
    const char* settings;
    int version;
    int extra;
};
class InboundNegotiation : public testing::TestWithParam<NegotiationCase> {};
TEST_P(InboundNegotiation, SettingsAndFeatureGates) {
    const auto c = GetParam();
    SCOPED_TRACE(c.name);
    Echo target;
    PanelNode node;
    TlsContext context(false);
    TlsSocket client(node.Connect(), context, false);
    Frames frames(client);
    AnyTlsAuthenticate(client, UserId);
    client.Write(AnyTlsFrame(4, c.extra == 4 ? 7 : 0, c.settings) + AnyTlsFrame(1, 1) +
                 AnyTlsFrame(2, 1, SocksAddress(target.server.Port()) + "negotiated-user-payload"));
    if (c.version < 0) {
        frames.Await([&] { return frames.closed; }, 2s);
        EXPECT_EQ(target.Count(), 0u);
        EXPECT_TRUE(std::any_of(frames.records.begin(), frames.records.end(),
                                [](const auto& f) { return f.command == 5 && f.stream == 0 && !f.payload.empty(); }));
    } else {
        frames.Await([&] { return frames.Payload(1) == "negotiated-user-payload"; });
        EXPECT_EQ(frames.Count(10) > 0, c.version == 2);
        EXPECT_EQ(frames.Count(7, 1) > 0, c.version == 2);
        if (c.extra) {
            client.Write(c.extra == 1       ? AnyTlsFrame(4, 0, "v=1")
                             : c.extra == 2 ? AnyTlsFrame(8, 0)
                                            : AnyTlsFrame(10, 0, "v=2"));
            frames.Await([&] { return frames.closed; }, 2s);
            EXPECT_GT(frames.Count(5), 0u);
            EXPECT_EQ(target.Count(), 1u);
        } else {
            Open(client, 2, target.server.Port(), "negotiated-user-payload");
            frames.Await([&] { return frames.Payload(2) == "negotiated-user-payload"; });
            if (c.version == 2) frames.Barrier();
            EXPECT_FALSE(frames.closed);
            EXPECT_EQ(target.Count(), 2u);
            EXPECT_EQ(frames.Count(7), c.version == 2 ? 2u : 0u);
            EXPECT_EQ(frames.Count(5), 0u);
        }
    }
    client.Close();
    node.Stop();
    target.server.Stop();
}
INSTANTIATE_TEST_SUITE_P(All, InboundNegotiation,
                         testing::ValuesIn(std::vector<NegotiationCase>{
                             {"v1", "v=1", 1, 0},
                             {"v2", "v=2", 2, 0},
                             {"future", "v=3", 2, 0},
                             {"maximum", "v=4294967295", 2, 0},
                             {"missing-version", "client=test", 1, 0},
                             {"fake-version", "client=has-v=2\nnot-v=2", 1, 0},
                             {"crlf", "v=2\r\nclient=test\r\n", 2, 0},
                             {"trailing", "v=2garbage", -1, 0},
                             {"overflow", "v=4294967296", -1, 0},
                             {"duplicate-key", "v=1\nv=2", -1, 0},
                             {"zero", "v=0", -1, 0},
                             {"duplicate-frame", "v=2", 2, 1},
                             {"wrong-sid", "v=2", -1, 4},
                             {"v1-heartbeat", "v=1", 1, 2},
                             {"wrong-direction", "v=2", 2, 3}}));

// 出站协商测试的上游 AnyTLS 对端：按用例回（可能非法的）服务端设置，并按 extra 注入协议违规。
class NegotiationPeer {
public:
    explicit NegotiationPeer(const NegotiationCase& c) : case_(c) {}
    void Serve(Socket socket) {
        ++connections;
        TlsSocket tls(std::move(socket), context_, true);
        ReadAnyTlsAuthentication(tls, "secret");
        std::map<uint32_t, std::string> requests;
        AnyTlsRecord frame;
        while (Next(tls, frame)) {
            if (frame.command == kSettings) OnSettings(tls, frame);
            else if (frame.command == kSyn) OnSyn(tls, requests, frame.stream);
            else if (frame.command == kHeartResponse) ++hearts;
            else if (frame.command == kPush) OnPush(tls, requests, frame);
        }
        ++closed;
    }
    std::vector<uint32_t> Streams() {
        std::lock_guard lock(mutex_);
        return streams_;
    }
    std::atomic<unsigned> connections = 0, hearts = 0, closed = 0;

private:
    void OnSettings(TlsSocket& tls, const AnyTlsRecord& frame) {
        EXPECT_NE(frame.payload.find("v=2"), std::string::npos);
        if (case_.settings) tls.Write(AnyTlsFrame(kServerSettings, case_.extra == 4 ? 5 : 0, case_.settings));
        if (case_.extra == 2) tls.Write(AnyTlsFrame(kHeartRequest, 0));
    }
    void OnSyn(TlsSocket& tls, std::map<uint32_t, std::string>& requests, uint32_t stream) {
        {
            std::lock_guard lock(mutex_);
            streams_.push_back(stream);
        }
        requests[stream] = {};
        if (case_.extra == 1 && stream >= 2) tls.Write(AnyTlsFrame(kServerSettings, 0, "v=1"));
        else if (case_.version == 2) {
            tls.Write(AnyTlsFrame(kSynAck, stream));
            if (!case_.extra) tls.Write(AnyTlsFrame(kHeartRequest, 0));
        }
    }
    void OnPush(TlsSocket& tls, std::map<uint32_t, std::string>& requests, const AnyTlsRecord& frame) {
        auto& bytes = requests[frame.stream];
        bytes += frame.payload;
        if (bytes == SocksAddress(443) + "pool-probe" && (!case_.extra || (case_.extra == 1 && frame.stream == 1)))
            tls.Write(AnyTlsFrame(kPush, frame.stream, "anytls-pool-reply") + AnyTlsFrame(kFin, frame.stream));
    }
    const NegotiationCase case_;
    TlsContext context_{true};
    std::mutex mutex_;
    std::vector<uint32_t> streams_;
};
class OutboundNegotiation : public testing::TestWithParam<NegotiationCase> {};
TEST_P(OutboundNegotiation, RejectsInvalidSettingsAndReusesValidSessions) {
    const auto c = GetParam();
    SCOPED_TRACE(c.name);
    NegotiationPeer negotiation_peer(c);
    auto& connections = negotiation_peer.connections;
    auto& hearts = negotiation_peer.hearts;
    auto& closed = negotiation_peer.closed;
    Server peer([&](Socket socket) { negotiation_peer.Serve(std::move(socket)); });
    Node node(false, peer.Port());
    auto request = [&] {
        auto app = node.Application("pool-probe");
        return Drain(app, 4s, c.extra != 0);
    };
    const auto start = std::chrono::steady_clock::now();
    if (c.extra) {
        if (c.extra == 1) EXPECT_EQ(request(), std::string("\0\0", 2) + "anytls-pool-reply");
        EXPECT_NE(request(), std::string("\0\0", 2) + "anytls-pool-reply");
        Until([&] { return closed.load() > 0; }, 1s);
        EXPECT_LT(std::chrono::steady_clock::now() - start, 2s);
    } else {
        for (int i = 0; i < 2; ++i) EXPECT_EQ(request(), std::string("\0\0", 2) + "anytls-pool-reply");
        EXPECT_EQ(connections, 1u);
        EXPECT_EQ(negotiation_peer.Streams(), (std::vector<uint32_t>{1, 2}));
        if (c.version == 2) Until([&] { return hearts.load() == 2; });
        else EXPECT_EQ(hearts, 0u);
        EXPECT_EQ(closed, 0u);
    }
    node.Stop();
    peer.Stop();
}
INSTANTIATE_TEST_SUITE_P(All, OutboundNegotiation,
                         testing::ValuesIn(std::vector<NegotiationCase>{{"no-settings", nullptr, 1, 0},
                                                                        {"v1", "v=1", 1, 0},
                                                                        {"v2", "v=2", 2, 0},
                                                                        {"future", "v=3", 2, 0},
                                                                        {"maximum", "v=4294967295", 2, 0},
                                                                        {"fake-version", "note=v=2\nv=1", 1, 0},
                                                                        {"trailing", "v=2garbage", 1, 3},
                                                                        {"overflow", "v=4294967296", 1, 3},
                                                                        {"duplicate-key", "v=1\nv=2", 1, 3},
                                                                        {"duplicate-frame", "v=2", 2, 1},
                                                                        {"wrong-sid", "v=2", 1, 4},
                                                                        {"v1-heartbeat", "v=1", 1, 2}}));
} // namespace cnode::e2e::sessions
