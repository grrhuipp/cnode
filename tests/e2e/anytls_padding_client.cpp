#include "anytls_padding.hpp"

#include <array>

namespace cnode::e2e::padding {
namespace {
struct ClientCase { const char* name; bool shared; unsigned auth_a; };
class AnyTlsClientPadding : public testing::TestWithParam<ClientCase> {};
TEST_P(AnyTlsClientPadding, LearnedPoliciesAreScopedToOutboundClientAcrossPhysicalSessions) {
    const auto& test = GetParam();
    TempDir root;
    auto listener_a = Socket::Listen();
    auto listener_b = Socket::Listen();
    auto reserve_a = Socket::Listen();
    auto reserve_b = Socket::Listen();
    const std::array<uint16_t, 2> front{reserve_a.Port(), reserve_b.Port()};
    const std::array<uint16_t, 2> remote{listener_a.Port(), test.shared ? listener_a.Port() : listener_b.Port()};
    const std::array<std::string, 2> passwords{"secret-a", "secret-b"};
    const std::array<std::string, 2> policies{
        "stop=8\n0=" + std::to_string(test.auth_a) + "-" + std::to_string(test.auth_a) + "\n1=256-256\n2=64-64\n",
        "stop=8\n0=91-91\n1=320-320\n2=80-80\n"};
    Configure(root.Path(), VlessInbound(front[0]), AnyOutbound(remote[0], passwords[0]));
    Json inbounds = Json::array(), outbounds = Json::array(), rules = Json::array();
    for (size_t key = 0; key < 2; ++key) {
        const std::string suffix = key == 0 ? "a" : "b";
        auto inbound = VlessInbound(front[key]);
        inbound["tag"] = "client-" + suffix;
        inbound["routingEnabled"] = true;
        inbounds.push_back(inbound);
        auto outbound = AnyOutbound(remote[key], passwords[key]);
        outbound["tag"] = "peer-" + suffix;
        outbounds.push_back(outbound);
        rules.push_back({{"type", "field"}, {"inboundTag", Json::array({"client-" + suffix})},
                         {"outboundTag", "peer-" + suffix}});
    }
    WriteJson(root.Path(), "inbounds.json", inbounds);
    WriteJson(root.Path(), "outbounds.json", outbounds);
    WriteJson(root.Path(), "routing.json", {{"rules", rules}});
    TlsContext tls(true);
    constexpr std::array<size_t, 5> sequence{0, 1, 0, 1, 0};
    std::atomic<size_t> completed{0};
    std::array<unsigned, 2> connections{};
    PeerThread peer([&] {
        for (size_t index = 0; index < sequence.size(); ++index) {
            const auto key = sequence[index];
            SCOPED_TRACE("outbound " + std::to_string(key) + " physical connection " + std::to_string(index));
            auto& listener = key == 0 || test.shared ? listener_a : listener_b;
            TlsSocket socket(listener.Accept(10s), tls, true);
            const bool first = connections[key]++ == 0;
            const std::vector<std::string> updates = first
                ? std::vector<std::string>{policies[key], "stop=0\n1=bad"} : std::vector<std::string>{};
            const auto observed = Exchange(socket, passwords[key], updates);
            const auto settings = Settings(first ? Default : std::string_view(policies[key]));
            EXPECT_EQ(observed.settings, settings);
            EXPECT_EQ(observed.authentication, first ? 30U : key == 0 ? test.auth_a : 91U);
            EXPECT_EQ(observed.streams, std::vector<uint32_t>{1});
            if (!first) {
                const size_t opening = (key == 0 ? 256 : 320) - (7 + settings.size() + 7 + 7 + SocksAddress(443).size()) - 7;
                const size_t data = (key == 0 ? 64 : 80) - (7 + Request.size()) - 7;
                EXPECT_EQ(observed.waste, (std::vector<size_t>{opening, data}));
            }
            ForceReconnect(socket);
            completed.store(index + 1);
        }
    });
    reserve_a.Close();
    reserve_b.Close();
    Child child({Binary().string(), "--config-dir", root.Path().string()}, root.Path() / "child.log");
    child.WaitForLog("server started");
    for (size_t index = 0; index < sequence.size(); ++index) {
        Roundtrip(front[sequence[index]]);
        Until([&] { return completed.load() == index + 1; }, 10s);
    }
    peer.Join();
    EXPECT_EQ(connections, (std::array<unsigned, 2>{3, 2}));
    EXPECT_TRUE(child.Running());
}
INSTANTIATE_TEST_SUITE_P(CacheNamespaces, AnyTlsClientPadding, testing::Values(
    ClientCase{"DistinctEndpoints", false, 45},
    ClientCase{"SharedEndpoint", true, 45},
    ClientCase{"MaximumAuthentication", false, 65535}
), [](const testing::TestParamInfo<ClientCase>& info) { return info.param.name; });
} // namespace
} // namespace cnode::e2e::padding
