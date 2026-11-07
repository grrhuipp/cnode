#include "http2_peer.hpp"

namespace cnode::e2e::http2 {
namespace {
struct ErrorCase { std::string network; bool tls; std::string mode; };
std::vector<ErrorCase> ErrorCases() {
    std::vector<ErrorCase> result;
    for (const std::string network : {"grpc", "h2", "xhttp"}) for (bool tls : {false, true}) {
        for (const std::string mode : {"backpressure", "capacity", "malformed-pseudo", "malformed-host", "initial-end", "reset-empty", "reset-long", "reset-zero", "reset-idle", "early-reset", "early-settings", "early-ping", "early-hpack"}) result.push_back({network, tls, mode});
        if (network == "xhttp") for (const std::string mode : {"packet-reset", "packet-capacity", "packet-tiny"}) result.push_back({network, tls, mode});
    }
    return result;
}
class Http2ServerErrors : public testing::TestWithParam<ErrorCase> {};
TEST_P(Http2ServerErrors, BoundedStreamsRecoverWithoutCorruptingSharedConnection) {
    const auto [network, tls, mode] = GetParam();
    std::mutex mutex; std::set<char> tags;
    std::atomic<bool> resume{false}, upload_done{false};
    std::atomic<size_t> upload_received{0};
    constexpr size_t UploadSize = 768 * 32768;
    Targets target([&](Socket& socket) {
        const auto tag = socket.ReadExact(1)[0];
        { std::lock_guard lock(mutex); tags.insert(tag); }
        socket.Write(Ready);
        if (tag == 'A') {
            Until([&] { return resume.load(); }, 15s);
            while (upload_received < UploadSize) {
                auto bytes = socket.Read(std::min<size_t>(65536, UploadSize - upload_received));
                Require(!bytes.empty(), "backpressured upload ended early");
                EXPECT_EQ(bytes, std::string(bytes.size(), 'F')); upload_received += bytes.size();
            }
            upload_done = true;
        }
        for (;;) { auto bytes = socket.Read(); if (bytes.empty()) break; socket.Write(bytes); }
    });
    auto has_tag = [&](char tag) { std::lock_guard lock(mutex); return tags.contains(tag); };
    Node node; node.Setup(network, tls, mode.starts_with("packet-") ? "packet-up" : "stream-one"); node.Start();
    auto connect_peer = [&] {
        auto peer = std::make_unique<Peer>(node.port, tls, network);
        peer->Wait([&] { return peer->Has(4, 0); }, 3s);
        auto settings = peer->Bodies(4, 0); Require(!settings.empty() && settings[0].size() % 6 == 0, "missing valid server settings");
        return peer;
    };
    auto owner = connect_peer(); auto& peer = *owner;
    if (mode == "packet-capacity") {
        peer.Down(1, "capacity"); peer.Packet(3, "capacity", 0, VlessRequest(target.Port(), "S")); peer.Message(1, Response); peer.Committed(3);
        for (uint32_t sid = 5, sequence = 1; sid < 133; sid += 2, ++sequence) peer.Packet(sid, "capacity", sequence, "q", false);
        peer.Ping("uploads!"); peer.Packet(133, "capacity", 65, "x", false); peer.Wait([&] { return peer.Has(3, 133); });
        EXPECT_FALSE(peer.closed); for (uint32_t sid = 5; sid < 133; sid += 2) EXPECT_FALSE(peer.Has(3, sid));
        peer.Reset(5); peer.Ping("rst-free"); peer.Packet(135, "capacity", 1, Echo); peer.Committed(135); peer.Message(1, Response + Echo);
        peer.Packet(137, "capacity", 65, "z", false); peer.Ping("refilled"); peer.Packet(139, "capacity", 66, "x", false);
        peer.Wait([&] { return peer.Has(3, 139); }); EXPECT_FALSE(peer.Has(3, 137));
        peer.Data(7, "", true); peer.Committed(7); peer.Message(1, Response + Echo + "q");
        peer.Packet(141, "capacity", 66, "final"); peer.Committed(141); peer.Ping("capacity");
    } else if (mode == "packet-tiny") {
        peer.Down(1, "tiny"); peer.Packet(3, "tiny", 0, VlessRequest(target.Port(), "S")); peer.Message(1, Response); peer.Committed(3);
        auto payload = Pattern(1024);
        peer.wire.Write(Frame(1, 4, 5, Headers(network, tls, "/fixture/tiny/1")));
        for (size_t i = 0; i < payload.size(); ++i) {
            peer.Data(5, std::string_view(payload).substr(i, 1), i + 1 == payload.size());
            if ((i + 1) % 64 == 0) { peer.Ping(BigEndian(i, 8)); EXPECT_FALSE(peer.Has(3, 5)); }
        }
        peer.Committed(5); peer.Message(1, Response + payload);
        peer.Packet(7, "tiny", 2, Echo); peer.Committed(7); peer.Message(1, Response + payload + Echo);
    } else if (mode == "packet-reset") {
        peer.Down(1, "victim"); peer.Packet(3, "victim", 0, VlessRequest(target.Port(), "V"), false); peer.Ping("prefix!!"); peer.Reset(3);
        peer.Down(5, "sibling"); peer.Packet(7, "sibling", 0, VlessRequest(target.Port(), "S")); peer.Message(5, Response);
        peer.Packet(9, "victim", 0, VlessRequest(target.Port(), "R")); peer.Message(1, Response);
        EXPECT_TRUE(has_tag('R')); EXPECT_FALSE(has_tag('V'));
        peer.Reset(1); peer.Packet(11, "sibling", 1, Echo); peer.Message(5, Response + Echo); peer.Ping("split-ok");
        peer.Down(13, "recovered"); peer.Packet(15, "recovered", 0, VlessRequest(target.Port(), "N")); peer.Message(13, Response); EXPECT_FALSE(has_tag('V'));
    } else if (mode.starts_with("early-") || mode.starts_with("reset-")) {
        uint32_t code = 1;
        if (!mode.starts_with("early-")) {
            peer.Open(1, target.Port(), "V"); peer.Open(3, target.Port(), "S"); peer.Message(1, Response); peer.Message(3, Response); peer.Ping("prepared");
        }
        if (mode == "early-reset") peer.Reset(1);
        else if (mode == "early-settings") { peer.wire.Write(Frame(4, 1, 0, std::string(6, '\0'))); code = 6; }
        else if (mode == "early-ping") peer.wire.Write(Frame(6, 0, 1, "bad-ping"));
        else if (mode == "early-hpack") { peer.wire.Write(Frame(1, 5, 1, std::string(1, '\x80'))); code = 9; }
        else if (mode == "reset-empty") { peer.wire.Write(Frame(3, 0, 1)); code = 6; }
        else if (mode == "reset-long") { peer.wire.Write(Frame(3, 0, 1, std::string(8, '\0'))); code = 6; }
        else if (mode == "reset-zero") peer.Reset(0);
        else peer.Reset(5);
        peer.Wait([&] { return peer.Has(7, 0); }, 3s);
        auto goaways = peer.Bodies(7, 0);
        if (mode.starts_with("early-")) EXPECT_EQ(goaways, std::vector<std::string>{BigEndian(0, 4) + BigEndian(code, 4)});
        else { ASSERT_FALSE(goaways.empty()); ASSERT_GE(goaways.back().size(), 8U); EXPECT_EQ(ReadBigEndian(std::string_view(goaways.back()).substr(4, 4)), code); }
        try { peer.Wait([&] { return peer.closed; }, 3s); }
        catch (const std::system_error& error) { EXPECT_EQ(error.code().value(), ECONNRESET); }
        auto recovered = connect_peer(); recovered->Open(1, target.Port(), "N"); recovered->Message(1, Response); recovered->Ping("recovery");
    } else if (mode == "initial-end") {
        auto block = Headers(network, tls);
        peer.wire.Write(Frame(1, 1, 1, std::string_view(block).substr(0, 3)) + Frame(9, 4, 1, std::string_view(block).substr(3)));
        peer.Open(3, target.Port(), "S"); peer.Message(3, Response); peer.Ping("survived"); peer.Wait([&] { return peer.Terminal(1); }, 3s);
        if (peer.Has(3, 1)) EXPECT_EQ(peer.Bodies(3, 1), std::vector<std::string>{BigEndian(8, 4)});
    } else {
        peer.Open(1, target.Port(), mode == "backpressure" ? "A" : "V"); peer.Open(3, target.Port(), "S");
        peer.Message(1, Response); peer.Message(3, Response); peer.Ping("prepared");
        uint32_t recovery = 5;
        if (mode == "backpressure") {
            const auto block = peer.raw ? std::string(32768, 'F') : Grpc(std::string(32768, 'F'));
            size_t index = 0, offset = 0;
            auto stable = Clock::now(), deadline = stable + 10s;
            while (Clock::now() - stable < 300ms) {
                Require(Clock::now() < deadline && index < 768, "consumer did not backpressure compliant DATA");
                auto count = peer.TryData(1, std::string_view(block).substr(offset));
                if (count) { offset += count; stable = Clock::now(); if (offset == block.size()) { ++index; offset = 0; } }
                else { peer.Pump(10ms); if (peer.Capacity(1) > 0) stable = Clock::now(); }
            }
            EXPECT_EQ(peer.stream_windows[1], 0); EXPECT_GT(peer.connection_window, 0); EXPECT_FALSE(peer.Has(3, 1));
            peer.Send(3, Echo); peer.Message(3, Response + Echo); peer.Ping("paused!!"); resume = true;
            for (; index < 768; ++index) { peer.Data(1, std::string_view(block).substr(offset)); offset = 0; }
            Until([&] { return upload_done.load(); }, 5s); EXPECT_EQ(upload_received.load(), UploadSize); EXPECT_FALSE(peer.Has(3, 1));
            peer.Send(1, Echo); peer.Message(1, Response + Echo); peer.Reset(1); peer.Ping("released");
        } else if (mode == "capacity") {
            for (uint32_t sid = 5; sid < 512; sid += 2) peer.wire.Write(Frame(1, 4, sid, Headers(network, tls)));
            peer.Ping("full256!");
            std::set<uint32_t> accepted; for (auto& frame : peer.frames) if (frame.type == 1) accepted.insert(frame.stream);
            EXPECT_EQ(accepted.size(), 256U);
            auto indexed = Field("x-fixture", "rejected"); indexed[0] = '\x40';
            peer.wire.Write(Frame(1, 4, 513, Headers(network, tls) + indexed));
            peer.Wait([&] { return peer.Has(3, 513); }); EXPECT_EQ(peer.Bodies(3, 513), std::vector<std::string>{BigEndian(7, 4)});
            peer.Reset(1); peer.Ping("freedone"); recovery = 515;
        } else {
            auto extra = mode == "malformed-pseudo" ? Field(":path", "/fixture") : Field("host", "other.example");
            peer.wire.Write(Frame(1, 4, 5, Headers(network, tls) + extra)); peer.Wait([&] { return peer.Has(3, 5); });
            EXPECT_EQ(peer.Bodies(3, 5), std::vector<std::string>{BigEndian(1, 4)}); recovery = 7;
        }
        if (mode != "backpressure") peer.Send(3, Echo);
        peer.Message(3, Response + Echo); peer.Ping("survived"); const auto barrier = peer.frames.size();
        if (mode == "capacity") { peer.wire.Write(Frame(1, 4, recovery, Headers(network, tls) + '\xbe')); peer.Send(recovery, VlessRequest(target.Port(), "N")); }
        else peer.Open(recovery, target.Port(), "N");
        peer.Message(recovery, Response); peer.Ping("recovery");
        for (size_t i = barrier; i < peer.frames.size(); ++i) EXPECT_NE(peer.frames[i].stream, 1U);
    }
    if (!mode.starts_with("early-") && !mode.starts_with("reset-")) EXPECT_FALSE(peer.closed);
    EXPECT_TRUE(node.child->Running()); target.Join();
}
INSTANTIATE_TEST_SUITE_P(GrpcH2XhttpTcpTls, Http2ServerErrors, testing::ValuesIn(ErrorCases()), [](const auto& info) {
    auto name = info.param.network + (info.param.tls ? "_tls_" : "_tcp_") + info.param.mode;
    std::replace(name.begin(), name.end(), '-', '_'); return name;
});
} // namespace
} // namespace cnode::e2e::http2
