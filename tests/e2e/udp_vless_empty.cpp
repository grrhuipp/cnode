#include "udp_wire.hpp"

namespace cnode::e2e::udp {
namespace {

void ConfigureVlessNode(const TempDir& root, uint16_t port, const Json& outbound) {
    Configure(root.Path(),
        {{"protocol", "vless"}, {"listen", "127.0.0.1"}, {"port", port},
         {"settings", {{"clients", Json::array({{{"id", UserId}}, {{"id", SecondUser}}})}}}},
        outbound);
    auto config = Json::parse(ReadFile(root.Path() / "config.json"));
    config["timeouts"]["connIdle"] = 30;
    config["timeouts"]["downlinkOnly"] = 1;
    WriteJson(root.Path(), "config.json", config);
}

class VlessEmptyDatagrams : public testing::TestWithParam<std::string> {};

TEST_P(VlessEmptyDatagrams, TwoRealNodesPreserveEmptyMessagesTargetsAndAssociationLifetime) {
    const auto& encoding = GetParam();
    SCOPED_TRACE(encoding);
    TempDir entry_root, exit_root;
    PortReservation entry_port, exit_port;
    auto first_target = Socket::BindUdp();
    auto second_target = Socket::BindUdp(first_target.Port(), "127.0.0.2");
    ConfigureVlessNode(exit_root, exit_port.port,
        {{"protocol", "freedom"}, {"settings", Json::object()}});
    ConfigureVlessNode(entry_root, entry_port.port,
        {{"protocol", "vless"},
         {"settings", {{"address", "127.0.0.1"}, {"port", exit_port.port},
                       {"id", UserId}, {"encryption", "none"}, {"packetEncoding", encoding}}}});
    exit_port.Release();
    Child exit({Binary().string(), "--config-dir", exit_root.Path().string()},
               exit_root.Path() / "child.log");
    exit.WaitForLog("server started");
    entry_port.Release();
    Child entry({Binary().string(), "--config-dir", entry_root.Path().string()},
                entry_root.Path() / "child.log");
    entry.WaitForLog("server started");

    Client first(entry_port.port, first_target.Port(), false);
    Client second(entry_port.port, second_target.Port(), false, true, "127.0.0.2");
    size_t first_packets = 0, second_packets = 0;
    auto exchange = [&](Client& client, Socket& target, Socket& other,
                        std::string_view request, std::string_view response) {
        client.Send(request);
        auto datagram = Receive(target);
        Require(datagram.payload == request, "VLESS chain changed UDP payload or message boundary");
        Require(!Readable(other.Fd(), 20ms), "VLESS chain selected the wrong destination address");
        Reply(target, datagram, response);
        client.Expect(response);
        if (&target == &first_target) ++first_packets;
        else ++second_packets;
        return datagram;
    };

    // The two destinations share a port but not an address, so a dropped
    // PacketAddr/Mux target cannot accidentally pass as a correct relay.
    const auto first_source = exchange(first, first_target, second_target, {}, {});
    const auto second_source = exchange(second, second_target, first_target, {}, {});
    EXPECT_NE(first_source.Port(), second_source.Port());
    EXPECT_TRUE(exchange(first, first_target, second_target, "one-after-empty", {})
                    .SameEndpoint(first_source));
    EXPECT_TRUE(exchange(second, second_target, first_target, "two-after-empty", "two-nonempty-reply")
                    .SameEndpoint(second_source));
    EXPECT_TRUE(exchange(first, first_target, second_target, {}, "one-empty-request-reply")
                    .SameEndpoint(first_source));
    EXPECT_TRUE(exchange(second, second_target, first_target, {}, {})
                    .SameEndpoint(second_source));
    EXPECT_TRUE(exchange(first, first_target, second_target, "one-after-second-empty", {})
                    .SameEndpoint(first_source));
    EXPECT_TRUE(exchange(second, second_target, first_target, "two-after-second-empty", {})
                    .SameEndpoint(second_source));

    first.Finish();
    Require(first.socket->Read(1, 5s).empty(), "VLESS UDP close emitted trailing data instead of EOF");
    EXPECT_TRUE(exchange(second, second_target, first_target, "survivor-after-peer-fin", {})
                    .SameEndpoint(second_source));
    EXPECT_TRUE(exchange(second, second_target, first_target, {}, "survivor-empty-reply")
                    .SameEndpoint(second_source));
    second.Finish();
    Require(second.socket->Read(1, 5s).empty(), "VLESS UDP survivor did not close normally");
    EXPECT_EQ(first_packets, 4u);
    EXPECT_EQ(second_packets, 6u);
    EXPECT_FALSE(Readable(first_target.Fd(), 100ms));
    EXPECT_FALSE(Readable(second_target.Fd(), 100ms));

    // A cleanly closed zero-message stream must not poison the next request.
    Client recovery(entry_port.port, first_target.Port(), false);
    exchange(recovery, first_target, second_target, {}, {});
    recovery.Finish();
    Require(recovery.socket->Read(1, 5s).empty(), "VLESS UDP recovery did not reach normal EOF");
    EXPECT_TRUE(entry.Running());
    EXPECT_TRUE(exit.Running());
    EXPECT_EQ(entry.Stop(), 0);
    EXPECT_EQ(exit.Stop(), 0);
}

INSTANTIATE_TEST_SUITE_P(PacketEncoding, VlessEmptyDatagrams,
    testing::Values(std::string("none"), std::string("packetaddr"), std::string("xudp")),
    [](const testing::TestParamInfo<std::string>& info) { return info.param; });

}  // namespace
}  // namespace cnode::e2e::udp
