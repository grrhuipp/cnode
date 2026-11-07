#include "anytls_padding.hpp"

namespace cnode::e2e::padding {
namespace {
struct InboundCase { const char* name; bool array; bool matched; };
class AnyTlsInboundPadding : public testing::TestWithParam<InboundCase> {};
TEST_P(AnyTlsInboundPadding, SharedPreparedPolicyDistributesOriginalBytesOnlyOnDigestMismatch) {
    const auto& test = GetParam();
    std::string raw = "stop=4294967295\n4294967294=64-65\n0=45-45\n7=96-96\n";
    if (test.array) raw.pop_back();
    TempDir root;
    auto destination = Socket::Listen();
    auto reservation = Socket::Listen();
    const auto port = reservation.Port();
    Configure(root.Path(), AnyInbound(port, PolicySetting(raw, test.array)),
              {{"protocol", "freedom"}, {"settings", Json::object()}}, 2);
    std::vector<std::string> requests;
    PeerThread target([&] {
        for (unsigned i = 0; i < 8; ++i) {
            auto socket = destination.Accept();
            requests.push_back(socket.ReadExact(Request.size()));
            socket.Write(Banner);
        }
    });
    reservation.Close();
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started");
    TlsContext tls(false);
    for (unsigned connection = 0; connection < 4; ++connection) {
        SCOPED_TRACE("physical connection " + std::to_string(connection));
        TlsSocket socket(ConnectEventually(port), tls, false);
        AnyTlsAuthenticate(socket, "secret");
        socket.Write(AnyTlsFrame(4, 0, "v=2\npadding-md5=" +
                                 (test.matched ? Digest(raw, EVP_md5(), true) : "outdated")));
        std::vector<std::string> updates;
        for (uint32_t sid : {1U, 2U}) {
            socket.Write(AnyTlsFrame(1, sid) +
                         AnyTlsFrame(2, sid, SocksAddress(destination.Port()) + std::string(Request)));
            auto received = ReceiveInbound(socket, sid);
            updates.insert(updates.end(), received.begin(), received.end());
        }
        DrainBarrier(socket, updates);
        EXPECT_EQ(updates, test.matched ? std::vector<std::string>{} : std::vector<std::string>{raw});
    }
    target.Join();
    EXPECT_EQ(requests, std::vector<std::string>(8, std::string(Request)));
    EXPECT_TRUE(child.Running());
}
INSTANTIATE_TEST_SUITE_P(PreparedPolicy, AnyTlsInboundPadding, testing::Values(
    InboundCase{"TextUpdate", false, false}, InboundCase{"TextMatched", false, true},
    InboundCase{"ArrayUpdate", true, false}, InboundCase{"ArrayMatched", true, true}
), [](const testing::TestParamInfo<InboundCase>& info) { return info.param.name; });

struct OutboundCase { const char* name; const char* policy; std::vector<size_t> second; };
class AnyTlsOutboundPadding : public testing::TestWithParam<OutboundCase> {};
TEST_P(AnyTlsOutboundPadding, SparseStopAndInvalidUpdatesKeepOnePhysicalSessionUsable) {
    const auto& test = GetParam();
    TempDir root;
    auto listener = Socket::Listen();
    auto reservation = Socket::Listen();
    const auto port = reservation.Port();
    Configure(root.Path(), VlessInbound(port), AnyOutbound(listener.Port(), "secret"));
    TlsContext tls(true);
    std::atomic<unsigned> barriers{0};
    std::vector<uint32_t> streams;
    std::map<uint32_t, std::string> requests;
    std::map<uint32_t, std::vector<size_t>> waste;
    PeerThread peer([&] {
        TlsSocket socket(listener.Accept(10s), tls, true);
        EXPECT_EQ(ReadAuth(socket, "secret"), 30);
        uint32_t active = 0;
        for (size_t frames = 0; frames < 512 && barriers.load() < 3; ++frames) {
            const auto record = ReadAnyTls(socket);
            switch (record.command) {
            case 4:
                EXPECT_EQ(record.payload, Settings(Default));
                socket.Write(AnyTlsFrame(10, 0, "v=2"));
                break;
            case 1:
                active = record.stream;
                streams.push_back(active);
                waste[active] = {};
                socket.Write(AnyTlsFrame(7, active));
                break;
            case 2:
                requests[record.stream] += record.payload;
                if (requests[record.stream] == SocksAddress(443) + std::string(Request)) {
                    std::string reply;
                    if (record.stream == 1)
                        reply = AnyTlsFrame(6, 0, test.policy) + AnyTlsFrame(6, 0, "stop=0\n1=bad");
                    reply += AnyTlsFrame(2, record.stream, Banner) + AnyTlsFrame(3, record.stream) + AnyTlsFrame(8, 0);
                    socket.Write(reply);
                }
                break;
            case 0:
                EXPECT_EQ(record.payload, std::string(record.payload.size(), '\0'));
                waste[active].push_back(record.payload.size());
                break;
            case 9:
                barriers.fetch_add(1);
                break;
            default:
                break;
            }
        }
        EXPECT_EQ(barriers.load(), 3U);
    });
    reservation.Close();
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started");
    for (unsigned sid = 1; sid <= 3; ++sid) {
        Roundtrip(port);
        Until([&] { return barriers.load() == sid; });
    }
    peer.Join();
    EXPECT_EQ(streams, (std::vector<uint32_t>{1, 2, 3}));
    EXPECT_EQ(waste[2], test.second);
    EXPECT_TRUE(waste[3].empty());
    for (uint32_t sid : {1U, 2U, 3U}) EXPECT_EQ(requests[sid], SocksAddress(443) + std::string(Request));
    EXPECT_TRUE(child.Running());
}
INSTANTIATE_TEST_SUITE_P(LearnedPolicy, AnyTlsOutboundPadding, testing::Values(
    OutboundCase{"SparseInt32", "stop=4294967295\n2147483647=64-65\n3=96-96\n4=128-128\n", {68, 106}},
    OutboundCase{"SparseUint32", "stop=4294967295\n4294967294=64-65\n3=96-96\n4=128-128\n", {68, 106}},
    OutboundCase{"Stop", "stop=4\n0=128-128\n3=96-96\n", {68}}
), [](const testing::TestParamInfo<OutboundCase>& info) { return info.param.name; });
} // namespace
} // namespace cnode::e2e::padding
