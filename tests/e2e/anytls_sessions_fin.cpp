#include "anytls_sessions.hpp"

namespace cnode::e2e::sessions {
TEST(AnyTlsFin, InboundRemoteFin) {
    ServerFin(true);
}
TEST(AnyTlsFin, InboundLocalEof) {
    ServerFin(false);
}
TEST(AnyTlsFin, OutboundRemoteFin) {
    ClientFin(true);
}
TEST(AnyTlsFin, OutboundLocalEof) {
    ClientFin(false);
}
// 开流即 FIN 测试的上游 AnyTLS 对端：流 2 不回 SYNACK，收到首个 PSH 就回（可选载荷 +）FIN；
// padding 时在流 1 下发一个需要 30 MiB 以上填充的方案，并统计 FIN 之后的填充字节。
class OpeningFinPeer {
public:
    OpeningFinPeer(bool padding, std::string_view expected) : padding_(padding), expected_(expected) {}
    void Serve(Socket socket) {
        ++connections;
        TlsSocket tls(std::move(socket), context_, true);
        ReadAnyTlsAuthentication(tls, "secret");
        Session session{tls};
        AnyTlsRecord frame;
        while (Next(tls, frame)) OnFrame(session, frame);
    }
    std::vector<uint32_t> Ids() {
        std::lock_guard lock(mutex_);
        return ids_;
    }
    std::atomic<unsigned> connections = 0, fin_replies = 0, hearts = 0;
    std::atomic<size_t> padding_bytes = 0, late_payload = 0;
    std::chrono::steady_clock::time_point fin_at;

private:
    struct Session {
        TlsSocket& tls;
        std::map<uint32_t, std::string> requests;
        bool fin_sent = false;
    };
    void OnFrame(Session& session, const AnyTlsRecord& frame) {
        if (frame.command == kSettings) session.tls.Write(AnyTlsFrame(kServerSettings, 0, "v=2"));
        else if (frame.command == kSyn) OnSyn(session, frame.stream);
        else if (frame.command == kPush) OnPush(session, frame);
        else if (frame.command == kWaste && session.fin_sent) padding_bytes += frame.payload.size();
        else if (frame.command == kFin && frame.stream == 2) ++fin_replies;
        else if (frame.command == kHeartResponse) ++hearts;
        else if (frame.command == kHeartRequest) session.tls.Write(AnyTlsFrame(kHeartResponse, 0));
    }
    void OnSyn(Session& session, uint32_t stream) {
        {
            std::lock_guard lock(mutex_);
            ids_.push_back(stream);
        }
        if (stream != 2) session.tls.Write(AnyTlsFrame(kSynAck, stream));
    }
    void OnPush(Session& session, const AnyTlsRecord& frame) {
        session.requests[frame.stream] += frame.payload;
        if (frame.stream == 2) {
            if (session.fin_sent) late_payload += frame.payload.size();
            else FinishOpeningStream(session);
        } else if (session.requests[frame.stream] == SocksAddress(443) + "request!") {
            if (padding_ && frame.stream == 1) session.tls.Write(AnyTlsFrame(kUpdatePaddingScheme, 0, HeavyScheme()));
            session.tls.Write(AnyTlsFrame(kPush, frame.stream, "accepted") + AnyTlsFrame(kFin, frame.stream));
        }
    }
    void FinishOpeningStream(Session& session) {
        if (padding_) EXPECT_EQ(session.requests[2], SocksAddress(443));
        fin_at = std::chrono::steady_clock::now();
        session.fin_sent = true;
        session.tls.Write((expected_.empty() ? std::string{} : AnyTlsFrame(kPush, 2, expected_)) +
                          AnyTlsFrame(kFin, 2) + AnyTlsFrame(kHeartRequest, 0));
        if (padding_) std::this_thread::sleep_for(400ms);
    }
    static std::string HeavyScheme() {
        std::string scheme = "stop=4\n3=";
        for (int i = 0; i < 4096; ++i) {
            if (i) scheme += ',';
            scheme += "8000-8001";
        }
        scheme += '\n';
        return scheme;
    }
    const bool padding_;
    const std::string_view expected_;
    TlsContext context_{true};
    std::mutex mutex_;
    std::vector<uint32_t> ids_;
};
class OpeningFin : public testing::TestWithParam<std::tuple<bool, bool>> {};
TEST_P(OpeningFin, ClosesBeforeSynackAndPreservesOpeningWriteOrder) {
    const auto [padding, withPayload] = GetParam();
    const auto expected = withPayload ? Pattern(251 * 32) : std::string{};
    OpeningFinPeer fin_peer(padding, expected);
    Server peer([&](Socket socket) { fin_peer.Serve(std::move(socket)); });
    Node node(false, peer.Port());
    {
        auto warmup = node.Application();
        EXPECT_EQ(Drain(warmup), std::string("\0\0", 2) + "accepted");
    }
    auto app = node.Application();
    EXPECT_EQ(Drain(app, 6s), std::string("\0\0", 2) + expected);
    auto closedAt = std::chrono::steady_clock::now();
    Until([&] { return fin_peer.hearts.load() > 0; }, 2s);
    EXPECT_LT(closedAt - fin_peer.fin_at, 2s);
    if (padding) EXPECT_GE(fin_peer.padding_bytes.load(), 30u * 1024u * 1024u);
    EXPECT_EQ(fin_peer.late_payload.load(), 0u);
    EXPECT_EQ(fin_peer.fin_replies.load(), 0u);
    auto recovery = node.Application();
    EXPECT_EQ(Drain(recovery), std::string("\0\0", 2) + "accepted");
    EXPECT_EQ(fin_peer.connections.load(), 1u);
    EXPECT_EQ(fin_peer.Ids(), (std::vector<uint32_t>{1, 2, 3}));
    node.Stop();
    peer.Stop();
}
INSTANTIATE_TEST_SUITE_P(All, OpeningFin, testing::Combine(testing::Bool(), testing::Bool()));
} // namespace cnode::e2e::sessions
