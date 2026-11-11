#include "anytls_sessions.hpp"

namespace cnode::e2e::sessions {
struct PressureCase {
    bool udp;
    const char* action;
};
// 响应压力测试的上游 AnyTLS 对端：第一个请求回整段 payload（中途插一次心跳），之后回 recovery-probe。
// retire 场景下第一个物理会话允许被 cnode 中途终止。
class PressurePeer {
public:
    PressurePeer(std::string_view payload, bool retire) : payload_(payload), retire_(retire) {}
    void Serve(Socket socket) {
        const auto connection = ++accepted;
        TlsSocket tls(std::move(socket), context_, true);
        ReadAnyTlsAuthentication(tls, "secret");
        tls.Write(AnyTlsFrame(kServerSettings, 0, "v=2"));
        Session session{tls};
        AnyTlsRecord frame;
        try {
            while (Next(tls, frame, 15s)) OnFrame(session, frame);
        } catch (const std::exception&) {
            if (!(retire_ && connection == 1)) throw;
        }
        if (connection == 1) first_closed = std::chrono::steady_clock::now();
        ++closed;
    }
    std::atomic<unsigned> accepted = 0, requests = 0, hearts = 0, closed = 0;
    std::chrono::steady_clock::time_point first_closed;

private:
    struct Session {
        TlsSocket& tls;
        std::map<uint32_t, std::string> bytes;
        std::map<uint32_t, bool> answered;
    };
    void OnFrame(Session& session, const AnyTlsRecord& frame) {
        if (frame.command == kSyn) session.tls.Write(AnyTlsFrame(kSynAck, frame.stream));
        else if (frame.command == kPush && !session.answered[frame.stream]) OnPush(session, frame);
        else if (frame.command == kHeartRequest) session.tls.Write(AnyTlsFrame(kHeartResponse, 0));
        else if (frame.command == kHeartResponse) ++hearts;
    }
    // 攒齐 SOCKS 目标与 probe 后应答一次；UDP 请求带 UoT 长度前缀。
    void OnPush(Session& session, const AnyTlsRecord& frame) {
        auto& data = session.bytes[frame.stream];
        data += frame.payload;
        if (data.empty() || (data[0] == 3 && data.size() < 2)) return;
        const size_t header = data[0] == 1 ? 7 : 4 + static_cast<unsigned char>(data[1]);
        if (data.size() < header) return;
        const bool udp = data[0] == 3;
        const auto expected = (udp ? std::string("\1\1\x7f\0\0\1\1\xbb\0\5", 10) : std::string{}) + "probe";
        if (data.size() < header + expected.size()) return;
        EXPECT_EQ(data.substr(header), expected);
        session.answered[frame.stream] = true;
        const std::string_view response = ++requests == 1 ? payload_ : std::string_view("recovery-probe");
        for (size_t offset = 0; offset < response.size(); offset += 16384) {
            if (response.size() > 65536 && offset / 16384 == (response.size() / 2) / 16384)
                session.tls.Write(AnyTlsFrame(kHeartRequest, 0));
            session.tls.Write(AnyTlsFrame(kPush, frame.stream, response.substr(offset, 16384)), 10s);
        }
        session.tls.Write(AnyTlsFrame(kFin, frame.stream));
    }
    const std::string_view payload_;
    const bool retire_;
    TlsContext context_{true};
};
class ResponsePressure : public testing::TestWithParam<PressureCase> {};
TEST_P(ResponsePressure, PreservesDataOrRetiresCancelledPhysicalSession) {
    const auto c = GetParam();
    const std::string action = c.action;
    const bool retire = action == "cancel" || action == "timeout";
    std::string payload;
    if (c.udp)
        for (int i = 0; i < 128; ++i)
            for (size_t n : {9000u, 19999u}) payload += BigEndian(n, 2) + Pattern(n);
    else payload = Pattern((action == "fast" ? 2 : 8) * 1024 * 1024);
    PressurePeer pressure_peer(payload, retire);
    auto& accepted = pressure_peer.accepted;
    auto& hearts = pressure_peer.hearts;
    auto& closed = pressure_peer.closed;
    auto& firstClosed = pressure_peer.first_closed;
    Server peer([&](Socket socket) { pressure_peer.Serve(std::move(socket)); });
    Node node(false, peer.Port(), {{"handshake", 5}, {"connIdle", action == "timeout" ? 1 : 10}, {"write", 10}});
    auto app = Socket::Connect(node.port);
    int buffer = 65536;
    Require(::setsockopt(app.Fd(), SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer)) == 0, "client receive buffer");
    const auto started = std::chrono::steady_clock::now();
    app.Write(VlessRequest(443, (c.udp ? BigEndian(5, 2) : std::string{}) + "probe", c.udp ? 2 : 1));
    std::string received;
    std::chrono::steady_clock::time_point aborted;
    if (action == "cancel") {
        std::this_thread::sleep_for(400ms);
        aborted = std::chrono::steady_clock::now();
        app.Close();
    } else {
        if (action != "fast") std::this_thread::sleep_for(action == "timeout" ? 1400ms : 400ms);
        received = Drain(app, 15s, action == "timeout");
    }
    if (retire) {
        Until([&] { return closed.load() > 0; }, 3s);
        if (action == "cancel") {
            EXPECT_GE(firstClosed, aborted);
            EXPECT_LT(firstClosed - aborted, 3s);
        } else {
            EXPECT_GE(firstClosed - started, 700ms);
            EXPECT_LT(firstClosed - started, 2s);
            EXPECT_LT(received.size(), payload.size());
        }
    } else {
        EXPECT_EQ(received, std::string("\0\0", 2) + payload);
        Until([&] { return hearts.load() == 1; });
        if (c.udp) {
            auto remaining = std::string_view(received).substr(2);
            unsigned datagrams = 0;
            while (!remaining.empty()) {
                ASSERT_GE(remaining.size(), 2u);
                const auto length = ReadBigEndian(remaining.substr(0, 2));
                ASSERT_GE(remaining.size(), length + 2);
                EXPECT_EQ(length, datagrams % 2 ? 19999u : 9000u);
                remaining.remove_prefix(length + 2);
                ++datagrams;
            }
            EXPECT_EQ(datagrams, 256u);
        }
    }
    auto recovery = node.Application("probe");
    EXPECT_EQ(Drain(recovery), std::string("\0\0", 2) + "recovery-probe");
    EXPECT_EQ(accepted.load(), retire ? 2u : 1u);
    node.Stop();
    peer.Stop();
}
INSTANTIATE_TEST_SUITE_P(
    All, ResponsePressure,
    testing::ValuesIn(std::vector<PressureCase>{
        {false, "fast"}, {false, "pause"}, {true, "fast"}, {true, "pause"}, {false, "cancel"}, {false, "timeout"}}));
} // namespace cnode::e2e::sessions
