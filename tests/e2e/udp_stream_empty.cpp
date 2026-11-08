#include "tls_wire.hpp"
#include "udp_wire.hpp"

namespace cnode::e2e::udp {
namespace {
enum class StreamProtocol {
    Trojan,
    ShadowsocksUotV1,
    ShadowsocksUotV2,
    AnyTlsUotV2,
};

class StreamUdpEmpty : public testing::TestWithParam<StreamProtocol> {};

TEST_P(StreamUdpEmpty, PreservesEmptyFirstPacketRepliesAndAssociationLifetime) {
    const auto protocol = GetParam();
    const bool shadowsocks = protocol == StreamProtocol::ShadowsocksUotV1 ||
                             protocol == StreamProtocol::ShadowsocksUotV2;
    TempDir front_root;
    TempDir back_root;
    PortReservation front_port;
    PortReservation back_port(shadowsocks);
    auto destination = Socket::BindUdp();

    auto back_inbound = tls::Inbound(
        back_port.port, shadowsocks ? Json::object() : TlsSettings(true));
    back_inbound["protocol"] = shadowsocks ? "shadowsocks"
        : protocol == StreamProtocol::Trojan ? "trojan" : "anytls";
    back_inbound["settings"] = {{"clients", Json::array({{{"password", "secret"}}})}};
    if (shadowsocks) back_inbound["settings"]["method"] = "aes-128-gcm";

    Json front_outbound = {{"tag", "direct"}, {"protocol", back_inbound["protocol"]},
        {"settings", {{"address", "127.0.0.1"}, {"port", back_port.port},
                      {"password", "secret"}}}};
    if (shadowsocks) {
        front_outbound["settings"]["method"] = "aes-128-gcm";
        front_outbound["settings"]["uot"] = {
            {"enabled", true},
            {"version", protocol == StreamProtocol::ShadowsocksUotV1 ? 1 : 2}};
    } else {
        front_outbound["streamSettings"] = TlsSettings(false);
    }

    // Both hops are real proxy processes: the controlled peer is native UDP,
    // and its asymmetric replies are not a substitute proxy implementation.
    const Json config = {{"timeouts", {{"handshake", 5}, {"connIdle", 30},
        {"write", 5}, {"uplinkOnly", 1}, {"downlinkOnly", 1}}}};
    tls::Config(back_root.Path(), Json::array({back_inbound}),
                Json::array({tls::Direct()}), config);
    tls::Config(front_root.Path(), Json::array({tls::Inbound(front_port.port)}),
                Json::array({front_outbound}), config);
    back_port.Release();
    auto back = tls::Start(back_root.Path());
    front_port.Release();
    auto front = tls::Start(front_root.Path());

    Client client(front_port.port, destination.Port(), false);
    const std::array<std::string, 5> requests{
        "", "request-after-empty", "", LargePacket(), ""};
    const std::array<std::string, 5> responses{
        "", "response-after-empty", "", Sequence(20513, 7), ""};
    std::optional<Datagram> association;
    for (size_t index = 0; index < requests.size(); ++index) {
        SCOPED_TRACE(index);
        client.Send(requests[index]);
        auto packet = Receive(destination);
        ASSERT_EQ(packet.payload, requests[index]);
        ASSERT_EQ(packet.Host(), "127.0.0.1");
        ASSERT_NE(packet.Port(), 0);
        if (association) EXPECT_TRUE(packet.SameEndpoint(*association));
        else association = packet;
        Reply(destination, packet, responses[index]);
        client.Expect(responses[index]);
        EXPECT_TRUE(front->Running());
        EXPECT_TRUE(back->Running());
    }
    EXPECT_FALSE(Readable(destination.Fd(), 100ms));
    EXPECT_FALSE(Readable(client.socket->Fd(), 100ms));
    client.Finish();
    client.ExpectEof();
    EXPECT_EQ(front->Stop(), 0);
    EXPECT_EQ(back->Stop(), 0);
}

INSTANTIATE_TEST_SUITE_P(RealProxyChains, StreamUdpEmpty,
    testing::Values(StreamProtocol::Trojan, StreamProtocol::ShadowsocksUotV1,
                    StreamProtocol::ShadowsocksUotV2, StreamProtocol::AnyTlsUotV2),
    [](const testing::TestParamInfo<StreamProtocol>& info) {
        switch (info.param) {
        case StreamProtocol::Trojan: return "Trojan";
        case StreamProtocol::ShadowsocksUotV1: return "ShadowsocksUotV1";
        case StreamProtocol::ShadowsocksUotV2: return "ShadowsocksUotV2";
        case StreamProtocol::AnyTlsUotV2: return "AnyTlsUotV2Connect";
        }
        return "Unknown";
    });
} // namespace
} // namespace cnode::e2e::udp
