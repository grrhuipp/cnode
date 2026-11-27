#include "http2_peer.hpp"

#include <cstdio>

namespace cnode::e2e::http2 {
namespace {
// 先于下行到达或正文停滞的 HTTP/2 上传只在请求握手期限内等待：PING 保活的
// 物理连接不得让该流、上传槽位与会话目录记录无限期滞留。
class Http2UploadDeadline : public testing::Test {
protected:
    void SetUp() override {
        node.Setup("xhttp", false, "packet-up");
        PatchConfig(node.root.Path(), [](Json& config) {
            config["timeouts"]["handshake"] = 1;
            config["timeouts"]["connIdle"] = 30;
        });
        node.Start();
    }

    // Keeps the connection busy with PINGs until `stream` is reset or the
    // budget runs out; returns how long that took.
    static Clock::duration PingUntilReset(Peer& peer, uint32_t stream, Milliseconds budget) {
        const auto start = Clock::now();
        for (unsigned round = 0; !peer.Has(3, stream) && Clock::now() - start < budget; ++round) {
            char token[9];
            std::snprintf(token, sizeof(token), "%08u", round);
            peer.Ping(std::string_view(token, 8));
            peer.Pump(100ms);
        }
        return Clock::now() - start;
    }

    Node node;
};

TEST_F(Http2UploadDeadline, UploadBeforeDownlinkResetsAndReleasesSessionRecord) {
    Targets target([](Socket& socket) { for (;;) { auto data = socket.Read(); if (data.empty()) break; socket.Write(data); } });
    Peer peer(node.port, false, "xhttp");
    // An accepted stream ends the connection's own handshake budget.
    peer.Down(1, "live");
    peer.Packet(3, "orphan", 0, "orphan-body");
    const auto waited = PingUntilReset(peer, 3, 4s);
    ASSERT_TRUE(peer.Has(3, 3)) << "upload waiting for its downlink outlived the handshake deadline";
    EXPECT_FALSE(peer.Ended(3));
    EXPECT_GE(waited, 500ms);
    EXPECT_FALSE(peer.goaway);
    // The abandoned wait released the directory record: the id starts afresh.
    peer.Down(5, "orphan");
    peer.Packet(7, "orphan", 0, VlessRequest(target.Port(), "fresh"));
    peer.Committed(7);
    peer.Message(5, std::string(2, '\0') + "fresh");
    EXPECT_FALSE(peer.goaway);
    node.child->Signal(SIGTERM); EXPECT_EQ(node.child->Wait(8s), 0);
    target.Join();
}

TEST_F(Http2UploadDeadline, StalledUploadBodyResetsWithoutTouchingSession) {
    Targets target([](Socket& socket) { for (;;) { auto data = socket.Read(); if (data.empty()) break; socket.Write(data); } });
    Peer peer(node.port, false, "xhttp");
    peer.Down(1, "stall");
    peer.Packet(3, "stall", 0, VlessRequest(target.Port(), "first"));
    peer.Committed(3);
    std::string expected = std::string(2, '\0') + "first";
    peer.Message(1, expected);
    // The packet's body never ends.
    peer.wire.Write(Frame(1, 4, 5, Headers("xhttp", false, "/fixture/stall/1")));
    peer.Data(5, "par");
    PingUntilReset(peer, 5, 4s);
    ASSERT_TRUE(peer.Has(3, 5)) << "stalled upload body outlived the handshake deadline";
    EXPECT_FALSE(peer.Has(3, 1));
    // The reset returned its upload slot; the session takes the packet anew.
    peer.Packet(7, "stall", 1, "second");
    peer.Committed(7);
    expected += "second";
    peer.Message(1, expected);
    EXPECT_FALSE(peer.goaway);
    node.child->Signal(SIGTERM); EXPECT_EQ(node.child->Wait(8s), 0);
    target.Join();
}
} // namespace
} // namespace cnode::e2e::http2
