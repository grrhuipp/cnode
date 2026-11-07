#include "http2_peer.hpp"

namespace cnode::e2e::http2 {
namespace {
struct BridgeCase { std::string protocol, security; bool empty; };
class Http2EofBridge : public testing::TestWithParam<BridgeCase> {};
TEST_P(Http2EofBridge, EightRequestsPreserveUploadEofAndResponseTrailers) {
    auto [protocol, security, empty] = GetParam();
    const auto payload = Pattern(48001), response = empty ? std::string{} : payload;
    std::atomic<unsigned> requests = 0;
    Targets target([&](Socket& socket) { EXPECT_EQ(ReadAll(socket), payload); ++requests; socket.Write(response); });
    Node remote, local;
    Configure(remote.root.Path(), Inbound(remote.port, "grpc", true, "stream-one", protocol), Freedom());
    auto settings = Protocol(protocol, remote.port);
    if (!security.empty()) settings["security"] = security;
    Configure(local.root.Path(), Inbound(local.port, "grpc", false), {{"protocol", protocol}, {"settings", settings}, {"streamSettings", Transport("grpc", true, false)}});
    remote.Start(); local.Start();
    Peer peer(local.port, false);
    for (uint32_t stream = 1; stream < 16; stream += 2) {
        peer.Open(stream, target.Port(), payload, true);
        peer.Message(stream, std::string(2, '\0') + response);
        peer.Wait([&] {
            return std::any_of(peer.frames.begin(), peer.frames.end(), [&](const auto& frame) {
                return frame.stream == stream && frame.type == 1 && (frame.flags & 1);
            });
        });
        EXPECT_FALSE(peer.closed); EXPECT_FALSE(peer.Has(3, stream));
    }
    peer.Ping("eof-done"); EXPECT_EQ(requests.load(), 8U);
    EXPECT_TRUE(remote.child->Running()); EXPECT_TRUE(local.child->Running()); target.Join();
}
INSTANTIATE_TEST_SUITE_P(Protocols, Http2EofBridge, testing::Values(
    BridgeCase{"vless", "", false}, BridgeCase{"vmess", "", false}, BridgeCase{"trojan", "", false}, BridgeCase{"shadowsocks", "", false},
    BridgeCase{"vmess", "chacha20-poly1305", false}, BridgeCase{"vmess", "none", false}, BridgeCase{"vmess", "zero", false}, BridgeCase{"vmess", "", true}));

class Http2RawInboundEof : public testing::TestWithParam<std::tuple<bool, bool>> {};
TEST_P(Http2RawInboundEof, RawEndStreamLeavesPhysicalConnectionReusable) {
    auto [tls, empty] = GetParam();
    const auto payload = Pattern(48001), response = empty ? std::string{} : payload;
    std::atomic<unsigned> requests = 0;
    Targets target([&](Socket& socket) { EXPECT_EQ(ReadAll(socket), payload); ++requests; socket.Write(response); });
    Node node; node.Setup("h2", tls); node.Start(); Peer peer(node.port, tls, "h2");
    for (uint32_t stream = 1; stream < 16; stream += 2) {
        peer.Open(stream, target.Port(), payload, true); peer.Message(stream, std::string(2, '\0') + response);
        peer.Wait([&] { return peer.Ended(stream); }); EXPECT_FALSE(peer.closed);
    }
    peer.Ping("raw-done"); EXPECT_EQ(requests.load(), 8U); EXPECT_TRUE(node.child->Running()); target.Join();
}
INSTANTIATE_TEST_SUITE_P(TcpTlsEmptyAndPayload, Http2RawInboundEof, testing::Combine(testing::Bool(), testing::Bool()));

class Http2OutboundEof : public testing::TestWithParam<std::tuple<bool, bool>> {};
TEST_P(Http2OutboundEof, UploadContinuesAfterResponseEndStream) {
    auto [tls, raw] = GetParam();
    Socket listener = Socket::Listen(); Node node;
    Configure(node.root.Path(), {{"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", node.port}, {"settings", Protocol()}},
              {{"protocol", "vless"}, {"settings", Protocol("vless", listener.Port())}, {"streamSettings", Transport(raw ? "h2" : "grpc", tls, false)}});
    PeerThread server([&] {
        Peer peer(listener.Accept(), tls, raw);
        peer.Wait([&] { return peer.Has(1, 1); });
        peer.wire.Write(Frame(1, 4, 1, std::string(1, '\x88') + (raw ? "" : Field("content-type", "application/grpc"))));
        peer.Message(1, VlessRequest(443, Request));
        peer.Send(1, Response, raw);
        if (!raw) peer.wire.Write(Frame(1, 5, 1, Field("grpc-status", "0")));
        peer.Message(1, VlessRequest(443, Request) + Echo);
        peer.Wait([&] { return peer.closed; });
    });
    node.Start(); auto client = Socket::Connect(node.port); client.Write(VlessRequest(443, Request));
    EXPECT_EQ(ReadAll(client, 3s), Response);
    client.Write(Echo); client.Close(); server.Join(); EXPECT_TRUE(node.child->Running());
}
INSTANTIATE_TEST_SUITE_P(GrpcAndRawTcpTls, Http2OutboundEof, testing::Combine(testing::Bool(), testing::Bool()));
} // namespace
} // namespace cnode::e2e::http2
