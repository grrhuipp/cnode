#include "anytls_sessions.hpp"

namespace cnode::e2e::sessions {
struct PoolCase {
    const char* name;
    unsigned minimum;
    const char* mode;
    Json timeouts;
};
// 池生命周期测试的上游 AnyTLS 对端。blocked 模式在首个 PSH 上缩小接收窗并停读，
// 制造 cnode 上行写阻塞；trickle_no_fin 模式持续发小块而不 FIN。
class PoolPeer {
public:
    PoolPeer(std::string mode, bool blocked, unsigned initial)
        : mode_(std::move(mode))
        , blocked_(blocked)
        , initial_(initial) {}
    void Serve(Socket socket) {
        ++accepted;
        TlsSocket tls(std::move(socket), context_, true);
        ReadAnyTlsAuthentication(tls, "secret");
        Session session{tls};
        AnyTlsRecord frame;
        while (Receive(session, frame)) OnFrame(session, frame);
        ++closed;
    }
    std::atomic<unsigned> accepted = 0, closed = 0, finished = 0, trickles = 0;

private:
    struct Session {
        TlsSocket& tls;
        std::map<uint32_t, std::string> requests;
        bool stalled = false;
        uint32_t trickle_stream = 0;
        std::chrono::steady_clock::time_point next_trickle = std::chrono::steady_clock::now();
    };
    // 等待下一帧；涓流流存在时按 100ms 节奏插入 PSH。返回 false 表示会话结束。
    bool Receive(Session& session, AnyTlsRecord& frame) {
        for (;;) {
            if (session.trickle_stream) {
                if (std::chrono::steady_clock::now() >= session.next_trickle) {
                    session.tls.Write(AnyTlsFrame(kPush, session.trickle_stream, "trickle"));
                    ++trickles;
                    session.next_trickle = std::chrono::steady_clock::now() + 100ms;
                }
                if (!SSL_pending(session.tls.Get()) && !Ready(session.tls.Fd(), 20ms)) continue;
            }
            try {
                return Next(session.tls, frame);
            } catch (const std::system_error& error) {
                // Cancelling an in-flight frame retires the physical session abortively.
                // Only the injected blocked-write cases may terminate this read with RST.
                if (!blocked_ || !session.stalled || error.code() != std::errc::connection_reset ||
                    !std::string_view(error.what()).starts_with("SSL_read:"))
                    throw;
                return false;
            }
        }
    }
    void OnFrame(Session& session, const AnyTlsRecord& frame) {
        if (frame.command == kPush && blocked_ && !session.stalled) Stall(session, frame.stream);
        else if (frame.command == kPush && !session.stalled) OnRequestBytes(session, frame);
        else if (frame.command == kFin && frame.stream == session.trickle_stream) session.trickle_stream = 0;
        else if (frame.command == kHeartRequest) session.tls.Write(AnyTlsFrame(kHeartResponse, frame.stream));
    }
    void Stall(Session& session, uint32_t stream) {
        session.stalled = true;
        int small = 4096;
        Require(::setsockopt(session.tls.Fd(), SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)) == 0,
                "peer receive buffer");
        session.tls.Write(AnyTlsFrame(kPush, stream, "anytls-pool-reply"));
        std::this_thread::sleep_for(600ms);
        if (mode_ == "stalled_write") session.tls.Write(AnyTlsFrame(kFin, stream));
        if (mode_ == "alert_during_write")
            session.tls.Write(AnyTlsFrame(kAlert, stream, "rejected while upload is blocked"));
        std::this_thread::sleep_for(1400ms);
    }
    void OnRequestBytes(Session& session, const AnyTlsRecord& frame) {
        auto& request = session.requests[frame.stream];
        request += frame.payload;
        if (request != SocksAddress(443) + "pool-probe") return;
        ++finished;
        Until([&] { return finished.load() >= initial_; });
        session.tls.Write(AnyTlsFrame(kPush, frame.stream, "anytls-pool-reply") +
                          (mode_ == "complete" ? AnyTlsFrame(kFin, frame.stream) : std::string{}));
        if (mode_ == "trickle_no_fin") {
            session.trickle_stream = frame.stream;
            session.next_trickle = std::chrono::steady_clock::now() + 100ms;
        }
    }
    const std::string mode_;
    const bool blocked_;
    const unsigned initial_;
    TlsContext context_{true};
};
class PoolLifecycle : public testing::TestWithParam<PoolCase> {};
TEST_P(PoolLifecycle, EvictsReusesAndCancelsBlockedDirections) {
    const auto c = GetParam();
    SCOPED_TRACE(c.name);
    const std::string mode = c.mode;
    const unsigned initial = c.minimum ? 2 : 1;
    const bool blocked = mode == "stalled_write" || mode == "write_timeout" || mode == "alert_during_write";
    PoolPeer pool_peer(mode, blocked, initial);
    auto& accepted = pool_peer.accepted;
    auto& closed = pool_peer.closed;
    auto& finished = pool_peer.finished;
    auto& trickles = pool_peer.trickles;
    Server peer([&](Socket socket) { pool_peer.Serve(std::move(socket)); });
    Node node(false, peer.Port(), c.timeouts, c.minimum, 1);
    auto request = [&] {
        auto app = node.Application("pool-probe");
        EXPECT_EQ(app.ReadExact(2 + 17), std::string("\0\0", 2) + "anytls-pool-reply");
        if (mode == "trickle_no_fin") {
            std::this_thread::sleep_for(600ms);
            app.ShutdownWrite();
        }
        if (blocked) {
            std::atomic<size_t> sent = 0;
            PeerThread upload([&] {
                const std::string chunk(65536, 'x');
                try {
                    for (int i = 0; i < 1024; ++i) {
                        app.Write(chunk, 5s);
                        sent += chunk.size();
                    }
                } catch (const std::system_error& error) {
                    if (error.code().value() != ECONNRESET && error.code().value() != EPIPE) throw;
                }
            });
            Drain(app, 5s, true);
            upload.Join();
            EXPECT_LT(sent.load(), 64u * 1024u * 1024u);
        } else Drain(app, 5s);
    };
    const auto started = std::chrono::steady_clock::now();
    std::vector<std::unique_ptr<PeerThread>> clients;
    for (unsigned i = 0; i < initial; ++i) clients.push_back(std::make_unique<PeerThread>(request));
    for (auto& client : clients) client->Join();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    EXPECT_EQ(accepted.load(), initial);
    if (!blocked) EXPECT_EQ(finished.load(), initial);
    if (mode != "complete") {
        EXPECT_GE(elapsed, 500ms);
        EXPECT_LT(elapsed, 4s);
    }
    if (mode == "stalled_write" || mode == "alert_during_write") EXPECT_LT(elapsed, 1800ms);
    if (mode == "trickle_no_fin") EXPECT_GE(trickles.load(), 3u);
    // 空闲会话按 idleSessionTimeout=1s / 检查周期 1s 回收到 minIdleSession；保留会话随后由复用断言核对。
    Until([&] { return accepted.load() - closed.load() == c.minimum; }, 5s);
    if (c.minimum) {
        request();
        EXPECT_EQ(accepted.load(), initial);
    }
    node.Stop();
    peer.Stop();
}
INSTANTIATE_TEST_SUITE_P(
    All, PoolLifecycle,
    testing::ValuesIn(std::vector<PoolCase>{
        {"minimum-zero", 0, "complete", Json::object()},
        {"minimum-one", 1, "complete", Json::object()},
        {"idle-without-fin", 0, "no_fin", {{"connIdle", 1}}},
        {"local-close-during-trickle", 0, "trickle_no_fin", {{"connIdle", 10}}},
        {"remote-fin-during-write", 0, "stalled_write", {{"write", 30}, {"connIdle", 30}}},
        {"write-timeout", 0, "write_timeout", {{"write", 1}}},
        {"alert-during-write", 0, "alert_during_write", {{"write", 30}, {"connIdle", 30}}},
        {"reuse-after-deadline", 1, "complete", {{"downlinkOnly", 1}, {"connIdle", 1}, {"write", 1}}}}),
    [](const testing::TestParamInfo<PoolCase>& info) {
        std::string name = info.param.name;
        std::replace(name.begin(), name.end(), '-', '_');
        return name;
    });
} // namespace cnode::e2e::sessions
