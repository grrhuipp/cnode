#include "quic_peer.hpp"

namespace cnode::e2e::quic {
namespace {

constexpr size_t kServerStreamWindow = 512 * 1024;

std::string H3Varint(uint64_t value) {
    std::string out;
    const size_t width = value < 64 ? 1 : value < 16384 ? 2 : value < (uint64_t{1} << 30) ? 4 : 8;
    const uint8_t prefix = width == 1 ? 0 : width == 2 ? 0x40 : width == 4 ? 0x80 : 0xc0;
    for (size_t index = width; index != 0; --index)
        out.push_back(static_cast<char>(value >> ((index - 1) * 8)));
    out[0] = static_cast<char>(static_cast<uint8_t>(out[0]) | prefix);
    return out;
}

std::string H3Frame(uint64_t type, std::string_view payload) {
    return H3Varint(type) + H3Varint(payload.size()) + std::string(payload);
}

// A connection whose authentication was refused keeps its HTTP/3 session, so
// its request streams still reach the server's nghttp3 session.
struct UnauthenticatedServer {
    TempDir root;
    Socket reservation = Socket::ReserveUdp();
    std::unique_ptr<Child> server;
    UnauthenticatedServer() {
        Configure(root.Path(), HysteriaInbound(reservation.Port()),
            {{"protocol", "freedom"}, {"settings", Json::object()}});
        server = std::make_unique<Child>(
            std::vector<std::string>{Binary().string(), "--config-dir", root.Path().string()},
            root.Path() / "child.log");
        server->WaitForServerStart();
    }
    Peer Connect() { return Peer(reservation.Port(), "wrong-secret", 65535, 4 * 1024 * 1024, "404"); }
};

// HEADERS referencing dynamic-table entry 0, which the peer never inserts:
// RFC 9204 §2.1.2 blocks the stream, and nghttp3 buffers what follows without
// consuming it (nghttp3_conn_read_stream2 counts only consumed bytes).
TEST(QuicH3Credit, BlockedRequestStreamIsNotCreditedForBufferedBytes) {
    UnauthenticatedServer fixture;
    auto peer = fixture.Connect();
    // Encoded Required Insert Count 2 (= 1 with 128 entries), Delta Base 0,
    // indexed dynamic field line, relative index 0.
    const std::string blocked_headers = H3Frame(0x01, std::string("\x02\x00\x80", 3));
    const auto stream = peer.OpenRaw(blocked_headers);
    const std::string flood = Pattern(4 * 1024 * 1024);
    peer.Send(stream, flood);
    peer.WaitStream(stream, [&] {
        const bool settled = peer.Acknowledged(stream) == peer.Submitted(stream);
        return settled && (peer.Submitted(stream) == peer.Queued(stream) ||
                           peer.StreamSendCredit(stream) == 0);
    }, 10s);
    EXPECT_LT(peer.Submitted(stream), peer.Queued(stream)) << peer.DescribeStream(stream);
    EXPECT_LE(peer.Submitted(stream), kServerStreamWindow) << peer.DescribeStream(stream);
    // Credit must stay withheld, not merely lag behind.
    for (int round = 0; round < 50; ++round) peer.Pump(Milliseconds(10));
    EXPECT_LE(peer.Submitted(stream), kServerStreamWindow) << peer.DescribeStream(stream);
    EXPECT_FALSE(peer.Closed());
    EXPECT_EQ(fixture.server->Stop(), 0);
}

// A request body the server discards is consumed as soon as nghttp3 delivers
// it, so a body beyond the stream window still flows.
TEST(QuicH3Credit, DiscardedRequestBodyIsCredited) {
    UnauthenticatedServer fixture;
    auto peer = fixture.Connect();
    // Static-table :method POST, :path /, :scheme https, :authority literal.
    std::string fields("\x00\x00\xd4\xc1\xd7\x50", 6);
    fields += static_cast<char>(8);
    fields += "hysteria";
    const auto stream = peer.OpenRaw(H3Frame(0x01, fields));
    const std::string body = Pattern(2 * kServerStreamWindow);
    peer.Send(stream, H3Frame(0x00, body), true);
    peer.WaitStream(stream, [&] { return peer.AllAcknowledged(stream); }, 10s);
    EXPECT_FALSE(peer.Closed());
    EXPECT_EQ(fixture.server->Stop(), 0);
}

}  // namespace
}  // namespace cnode::e2e::quic
