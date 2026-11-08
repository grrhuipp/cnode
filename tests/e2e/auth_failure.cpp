#include "tls_wire.hpp"
#include "quic_peer.hpp"

namespace cnode::e2e {
namespace {
constexpr std::string_view kInvalidUser = "11111111-1111-4111-8111-111111111111";
constexpr std::string_view kRequest = "admitted-request";
constexpr std::string_view kResponse = "destination-response";

std::string ProxyHeader(std::string_view ip) {
    return "PROXY TCP4 " + std::string(ip) + " 198.51.100.1 32100 443\r\n";
}

void ExpectClosed(Socket& socket) {
    pollfd descriptor{socket.Fd(), POLLIN, 0};
    ASSERT_GT(::poll(&descriptor, 1, 5000), 0) << "rejected connection did not close";
    char byte;
    const auto count = ::recv(socket.Fd(), &byte, 1, 0);
    EXPECT_TRUE(count == 0 || (count < 0 && errno == ECONNRESET));
}

void ExpectForwarded(uint16_t port, uint16_t target, std::string_view source = {}) {
    auto socket = Socket::Connect(port);
    const auto prefix = source.empty() ? std::string{} : ProxyHeader(source);
    socket.Write(prefix + VlessRequest(target, kRequest));
    EXPECT_EQ(socket.ReadExact(2 + kResponse.size()), std::string(2, '\0') + std::string(kResponse));
}

void UseTwoWorkers(const std::filesystem::path& root) {
    auto config = Json::parse(ReadFile(root / "config.json"));
    config["workers"] = 2;
    WriteJson(root, "config.json", config);
}

class IPBan : public testing::TestWithParam<bool> {};
TEST_P(IPBan, OptionalBanUsesTrustedSourceAndDoesNotCrossInboundTags) {
    TempDir root;
    Targets target([](Socket& socket) {
        EXPECT_EQ(socket.ReadExact(kRequest.size()), kRequest);
        socket.Write(kResponse);
    });
    auto first = Socket::Listen(), second = Socket::Listen();
    const auto first_port = first.Port(), second_port = second.Port();
    auto first_inbound = tls::Inbound(first_port);
    first_inbound["tag"] = "first";
    auto second_inbound = tls::Inbound(second_port);
    second_inbound["tag"] = "second";
    Json config{{"log", {{"loglevel", "info"}}}};
    if (GetParam()) {
        config["limits"]["ipBan"] = {{"enabled", true}, {"failureLimit", 2},
            {"windowSeconds", 60}, {"banSeconds", 180}};
    }
    tls::Config(root.Path(), Json::array({first_inbound, second_inbound}),
                Json::array({tls::Direct()}), config);
    UseTwoWorkers(root.Path());
    first.Close(); second.Close();
    auto child = tls::Start(root.Path());
    for (unsigned i = 0; i < 2; ++i) {
        auto socket = Socket::Connect(first_port);
        socket.Write(ProxyHeader("192.0.2.1") + VlessRequest(target.Port(), {}, 1, "127.0.0.1", kInvalidUser));
        ExpectClosed(socket);
    }
    if (GetParam()) {
        auto socket = Socket::Connect(first_port);
        socket.Write(ProxyHeader("192.0.2.1") + VlessRequest(target.Port(), kRequest));
        ExpectClosed(socket);
    } else {
        ExpectForwarded(first_port, target.Port(), "192.0.2.1");
    }
    ExpectForwarded(first_port, target.Port(), "192.0.2.2");
    ExpectForwarded(second_port, target.Port(), "192.0.2.1");
    // A socket peer is not an authenticated PROXY protocol source.
    for (unsigned i = 0; i < 2; ++i) {
        auto socket = Socket::Connect(first_port);
        socket.Write(VlessRequest(target.Port(), {}, 1, "127.0.0.1", kInvalidUser));
        ExpectClosed(socket);
    }
    ExpectForwarded(first_port, target.Port());
    EXPECT_TRUE(child->Running());
    EXPECT_EQ(child->Stop(), 0);
    target.Join();
}
INSTANTIATE_TEST_SUITE_P(DefaultAndEnabled, IPBan, testing::Bool());

TEST(CredentialFailureLimit, CrossIPThresholdReturns429WithoutBlockingOtherCredentialsOrTags) {
    TempDir root;
    auto first = Socket::BindUdp(), second = Socket::BindUdp();
    const auto first_port = first.Port(), second_port = second.Port();
    auto first_inbound = quic::HysteriaInbound(first_port);
    first_inbound["tag"] = "first";
    auto second_inbound = quic::HysteriaInbound(second_port);
    second_inbound["tag"] = "second";
    tls::Config(root.Path(), Json::array({first_inbound, second_inbound}),
                Json::array({tls::Direct()}), {{"log", {{"loglevel", "info"}}}});
    UseTwoWorkers(root.Path());
    first.Close(); second.Close();
    auto child = tls::Start(root.Path());
    for (unsigned i = 0; i < 10; ++i) {
        const auto address = "127.0.0." + std::to_string(i + 2);
        quic::Peer rejected(first_port, "invalid-credential", 65535, 4 * 1024 * 1024, "404", address);
    }
    {
        quic::Peer limited(first_port, "invalid-credential", 65535, 4 * 1024 * 1024, "429", "127.0.0.20");
        quic::Peer other_credential(first_port, "another-invalid-credential", 65535, 4 * 1024 * 1024, "404");
        quic::Peer other_tag(second_port, "invalid-credential", 65535, 4 * 1024 * 1024, "404");
    }
    Targets target([](Socket& socket) {
        EXPECT_EQ(socket.ReadExact(kRequest.size()), kRequest);
        socket.Write(kResponse);
    });
    {
        quic::Peer admitted(first_port);
        const auto stream = admitted.Open("127.0.0.1:" + std::to_string(target.Port()), kRequest);
        admitted.WaitPayload(stream, kResponse);
    }
    EXPECT_TRUE(child->Running());
    EXPECT_EQ(child->Stop(), 0);
    target.Join();
}
} // namespace
} // namespace cnode::e2e
