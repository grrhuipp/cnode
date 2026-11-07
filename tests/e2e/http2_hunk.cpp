#include "http2_peer.hpp"

namespace cnode::e2e::http2 {
namespace {
constexpr size_t Limit = 4 * 1024 * 1024;
const std::vector<std::string> Valid{"fragmented", "unknown-fields", "duplicate-last", "unknown-group", "maximum"};
const std::vector<std::string> Invalid{"trailing-key-zero", "trailing-truncated-field", "overflow-key", "overflow-varint", "duplicate-empty", "truncated-body", "compressed", "oversize-prefix", "uint32-prefix"};
bool Legal(const std::string& mode) { return std::find(Valid.begin(), Valid.end(), mode) != Valid.end(); }
std::string Encode(const std::string& mode, std::string_view payload) {
    auto field = [](std::string_view value) { return std::string(1, '\x0a') + Varint(value.size()) + std::string(value); };
    auto message = field(payload);
    if (mode == "unknown-fields") message = std::string("\x10\x96\x01\x19", 4) + std::string(8, '\0') + message + '\x25' + std::string(4, '\0');
    else if (mode == "duplicate-last") message = field("wrong") + message;
    else if (mode == "unknown-group") message = std::string("\x13\x1b\x20\x01\x1c\x14", 6) + message;
    else if (mode == "trailing-key-zero") message += '\0';
    else if (mode == "trailing-truncated-field") message += std::string("\x1a\x04\0", 3);
    else if (mode == "overflow-key") message = Varint(((uint64_t{1} << 32) + 1) << 3 | 2) + Varint(payload.size()) + std::string(payload);
    else if (mode == "overflow-varint") message = std::string(1, '\x10') + std::string(9, '\xff') + '\x02' + message;
    else if (mode == "duplicate-empty") message += field("");
    else if (mode == "oversize-prefix" || mode == "uint32-prefix") return std::string(1, '\0') + BigEndian(mode == "oversize-prefix" ? Limit + 1 : 0xffffffff, 4);
    auto wire = std::string(1, mode == "compressed" ? '\1' : '\0') + BigEndian(message.size(), 4) + message;
    if (mode == "truncated-body") wire.pop_back();
    return wire;
}
void SendHunk(Peer& peer, std::string_view wire, bool fragmented, bool end) {
    if (fragmented) {
        for (size_t count : {1, 1, 1, 1, 1, 1, 1, 2}) {
            if (wire.empty()) break;
            count = std::min(count, wire.size()); peer.Data(1, wire.substr(0, count), end && count == wire.size()); wire.remove_prefix(count);
            std::this_thread::sleep_for(10ms);
        }
    }
    if (!wire.empty()) peer.Data(1, wire, end);
}
struct Case { bool outbound, tls; std::string mode; };
std::vector<Case> Cases() {
    std::vector<Case> values;
    for (bool outbound : {false, true}) for (bool tls : {false, true}) {
        for (auto& mode : Valid) values.push_back({outbound, tls, mode});
        for (auto& mode : Invalid) values.push_back({outbound, tls, mode});
    }
    return values;
}
class Http2Hunk : public testing::TestWithParam<Case> {};
TEST_P(Http2Hunk, RealDecoderRejectsAtomicallyAndRecovers) {
    const auto [outbound, tls, mode] = GetParam();
    Node node;
    if (!outbound) {
        const std::string body = mode == "maximum" ? std::string(Limit - 5 - VlessRequest(443).size(), 'z') : Request;
        std::mutex mutex;
        std::vector<std::string> requests;
        Targets target([&](Socket& socket) {
            size_t index; { std::lock_guard lock(mutex); index = requests.size(); }
            auto bytes = socket.ReadExact(index == 0 && Legal(mode) ? body.size() : Request.size());
            { std::lock_guard lock(mutex); requests.push_back(bytes); }
            socket.Write(Ready);
        });
        node.Setup("grpc", tls); node.Start();
        Peer peer(node.port, tls);
        peer.wire.Write(Frame(1, 4, 1, Headers("grpc", tls)));
        SendHunk(peer, Encode(mode, VlessRequest(target.Port(), body)), mode == "fragmented", true);
        peer.Wait([&] { return peer.Terminal(1); });
        EXPECT_FALSE(peer.closed);
        if (Legal(mode)) {
            EXPECT_FALSE(peer.Has(3, 1)); EXPECT_EQ(peer.messages[1], Response);
            std::lock_guard lock(mutex); ASSERT_EQ(requests.size(), 1U); EXPECT_EQ(requests[0], body);
        } else {
            EXPECT_TRUE(peer.messages[1].empty());
            EXPECT_EQ(peer.Bodies(3, 1), std::vector<std::string>{BigEndian(8, 4)});
            std::lock_guard lock(mutex); EXPECT_TRUE(requests.empty());
        }
        peer.Open(3, target.Port(), Request, true); peer.Message(3, Response); peer.Ping("hunk-ok!");
        { std::lock_guard lock(mutex); ASSERT_FALSE(requests.empty()); EXPECT_EQ(requests.back(), Request); }
        EXPECT_TRUE(node.child->Running()); target.Join();
    } else {
        const std::string body = mode == "maximum" ? std::string(Limit - 7, 'z') : Ready;
        Socket listener = Socket::Listen();
        Configure(node.root.Path(), {{"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", node.port}, {"settings", Protocol()}},
                  {{"protocol", "vless"}, {"settings", Protocol("vless", listener.Port())}, {"streamSettings", Transport("grpc", tls, false)}});
        PeerThread server([&] {
            for (int index = 0; index < 2; ++index) {
                Peer peer(listener.Accept(), tls, false);
                peer.wire.Write(Frame(1, 4, 1, std::string(1, '\x88') + Field("content-type", "application/grpc")));
                peer.Message(1, VlessRequest(443, Request));
                SendHunk(peer, index == 0 ? Encode(mode, std::string(2, '\0') + body) : Grpc(Response), index == 0 && mode == "fragmented", false);
                peer.wire.Write(Frame(1, 5, 1, Field("grpc-status", "0")));
                // Keep the physical peer alive until cnode has consumed the terminal trailers.
                auto deadline = Clock::now() + 5s;
                while (!peer.closed && Clock::now() < deadline) {
                    try { peer.Pump(); } catch (const std::system_error& error) {
                        if (index == 0 && !Legal(mode) && error.code().value() == ECONNRESET) { peer.closed = true; break; }
                        throw;
                    }
                }
                Require(peer.closed, "outbound Hunk connection did not close after trailers");
            }
        });
        node.Start();
        for (int index = 0; index < 2; ++index) {
            auto client = Socket::Connect(node.port); client.Write(VlessRequest(443, Request));
            std::string data;
            const auto deadline = Clock::now() + 5s;
            try {
                for (;;) {
                    Require(Clock::now() < deadline, "outbound Hunk response EOF deadline");
                    auto bytes = client.Read(65536, std::chrono::duration_cast<Milliseconds>(deadline - Clock::now()));
                    if (bytes.empty()) break;
                    data += bytes;
                }
            } catch (const std::system_error& error) {
                if (!(index == 0 && !Legal(mode) && error.code().value() == ECONNRESET)) throw;
            }
            EXPECT_EQ(data, index || Legal(mode) ? std::string(2, '\0') + (index ? Ready : body) : std::string{});
        }
        server.Join(); EXPECT_TRUE(node.child->Running());
    }
}
INSTANTIATE_TEST_SUITE_P(TcpAndTlsBothDirections, Http2Hunk, testing::ValuesIn(Cases()), [](const auto& info) {
    auto name = std::string(info.param.outbound ? "outbound_" : "inbound_") + (info.param.tls ? "tls_" : "tcp_") + info.param.mode;
    std::replace(name.begin(), name.end(), '-', '_'); return name;
});
} // namespace
} // namespace cnode::e2e::http2
