#include "tls_wire.hpp"

namespace cnode::e2e {
namespace {
using namespace tls;
constexpr std::string_view kRequest = "quota-request";
constexpr std::string_view kResponse = "quota-response";

void ExpectClosed(Socket& socket) {
    pollfd descriptor{socket.Fd(), POLLIN, 0};
    ASSERT_GT(::poll(&descriptor, 1, 5000), 0) << "rejected connection did not close";
    char byte;
    const auto count = ::recv(socket.Fd(), &byte, 1, 0);
    EXPECT_TRUE(count == 0 || (count < 0 && errno == ECONNRESET)) << "unexpected data or socket error " << errno;
}

Json QuotaConfig() {
    // 握手期限远长于断言等待，旧行为下第二条连接只会停在握手中而不会被关闭。
    return {{"limits", {{"maxConnectionsPerIP", 1}}},
            {"timeouts", {{"handshake", 30}, {"connIdle", 40}}}};
}

// 一个真实的 TLS ClientHello：发出后服务端回 ServerHello 即证明连接已过准入。
std::string ClientHello() {
    TlsContext context(false);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context.Get()), SSL_free);
    Require(ssl != nullptr, "SSL_new");
    BIO* incoming = BIO_new(BIO_s_mem());
    BIO* outgoing = BIO_new(BIO_s_mem());
    Require(incoming && outgoing, "BIO_new");
    SSL_set_bio(ssl.get(), incoming, outgoing);
    SSL_set_connect_state(ssl.get());
    Require(SSL_set_tlsext_host_name(ssl.get(), "localhost") == 1, "TLS SNI");
    const int result = SSL_do_handshake(ssl.get());
    Require(result != 1 && SSL_get_error(ssl.get(), result) == SSL_ERROR_WANT_READ, "ClientHello");
    std::string hello(BIO_ctrl_pending(outgoing), '\0');
    Require(BIO_read(outgoing, hello.data(), static_cast<int>(hello.size())) == static_cast<int>(hello.size()), "ClientHello drain");
    return hello;
}

std::string ProxyHeader(std::string_view client) {
    return "PROXY TCP4 " + std::string(client) + " 198.51.100.1 32100 443\r\n";
}

bool TlsRoundTrip(uint16_t port, uint16_t target, std::string_view prefix = {}) {
    try {
        TlsContext context(false);
        auto socket = Socket::Connect(port);
        if (!prefix.empty()) socket.Write(prefix);
        WireTls stream(std::move(socket), context);
        stream.Write(VlessRequest(target, kRequest));
        return stream.ReadExact(2 + kResponse.size()) == std::string(2, '\0') + std::string(kResponse);
    } catch (const std::exception&) {
        return false;
    }
}

// 停在 TLS 握手中的连接已按其来源地址占用按 IP 额度：同地址的新连接在握手前
// 即被拒绝；挂起连接关闭后额度归还。
TEST(HandshakeQuota, PendingTlsHandshakeHoldsTheSourceAddressSlot) {
    TempDir root;
    Targets target([](Socket& socket) {
        EXPECT_EQ(socket.ReadExact(kRequest.size()), kRequest);
        socket.Write(kResponse);
    });
    auto reservation = Socket::ReserveTcp();
    const auto port = reservation.Port();
    Config(root.Path(), Json::array({Inbound(port, TlsSettings(true))}), Json::array({Direct()}), QuotaConfig());
    auto child = Start(root.Path());
    const auto hello = ClientHello();

    auto pending = Socket::Connect(port);
    pending.Write(hello);
    EXPECT_FALSE(pending.Read(65536, 5s).empty()) << "first handshake was not admitted";

    auto second = Socket::Connect(port);
    second.Write(hello);
    ExpectClosed(second);

    pending.Close();
    Until([&] { return TlsRoundTrip(port, target.Port()); }, 5s);
    EXPECT_TRUE(child->Running());
}

Json ProxyQuotaConfig(Json limits) {
    auto config = QuotaConfig();
    config["limits"] = std::move(limits);
    return config;
}

Json ProxyInbound(uint16_t port) {
    auto inbound = Inbound(port, TlsSettings(true));
    inbound["proxyProtocol"] = "on";
    return inbound;
}

// PROXY protocol 入站：socket 对端是可信负载均衡器。读头期间连接已占全局额度，
// 一条尚未发出 PROXY 头的静默连接即可占满 maxConnections。
TEST(HandshakeQuota, SilentProxyProtocolReadCountsAgainstTheGlobalLimit) {
    TempDir root;
    Targets target([](Socket& socket) {
        EXPECT_EQ(socket.ReadExact(kRequest.size()), kRequest);
        socket.Write(kResponse);
    });
    auto reservation = Socket::ReserveTcp();
    const auto port = reservation.Port();
    Config(root.Path(), Json::array({ProxyInbound(port)}), Json::array({Direct()}),
           ProxyQuotaConfig({{"maxConnections", 1}}));
    auto child = Start(root.Path());

    auto silent = Socket::Connect(port);
    // 接受顺序之外再留出余量，使静默连接的准入先于下一条连接到达协调器。
    std::this_thread::sleep_for(200ms);
    auto second = Socket::Connect(port);
    second.Write(ProxyHeader("192.0.2.20") + ClientHello());
    ExpectClosed(second);

    silent.Close();
    Until([&] { return TlsRoundTrip(port, target.Port(), ProxyHeader("192.0.2.20")); }, 5s);
    EXPECT_TRUE(child->Running());
}

// 按 IP 额度在 PROXY 头之后、TLS 握手之前按 PROXY 提供的地址计入；负载均衡器
// 自身的 socket 地址不计入。
TEST(HandshakeQuota, ProxySuppliedAddressHoldsThePerIpSlotBeforeTls) {
    TempDir root;
    Targets target([](Socket& socket) {
        EXPECT_EQ(socket.ReadExact(kRequest.size()), kRequest);
        socket.Write(kResponse);
    });
    auto reservation = Socket::ReserveTcp();
    const auto port = reservation.Port();
    Config(root.Path(), Json::array({ProxyInbound(port)}), Json::array({Direct()}),
           ProxyQuotaConfig({{"maxConnectionsPerIP", 1}}));
    auto child = Start(root.Path());
    const auto hello = ClientHello();

    auto pending = Socket::Connect(port);
    pending.Write(ProxyHeader("192.0.2.10") + hello);
    EXPECT_FALSE(pending.Read(65536, 5s).empty()) << "first handshake was not admitted";

    EXPECT_TRUE(TlsRoundTrip(port, target.Port(), ProxyHeader("192.0.2.11")));

    auto duplicate = Socket::Connect(port);
    duplicate.Write(ProxyHeader("192.0.2.10") + hello);
    ExpectClosed(duplicate);

    pending.Close();
    Until([&] { return TlsRoundTrip(port, target.Port(), ProxyHeader("192.0.2.10")); }, 5s);
    EXPECT_TRUE(child->Running());
}

// 配置了真实 IP 头的传输：socket 端是可信前置代理，其握手中的连接不占额度；
// 握手后连接按转发地址计数。
TEST(HandshakeQuota, ForwardedAddressTransportCountsTheForwardedClient) {
    TempDir root;
    Targets target([](Socket& socket) {
        EXPECT_EQ(socket.ReadExact(kRequest.size()), kRequest);
        socket.Write(kResponse);
        EXPECT_TRUE(socket.Read(1, 10s).empty());
    });
    auto reservation = Socket::ReserveTcp();
    const auto port = reservation.Port();
    Json stream{{"network", "httpupgrade"}, {"security", "none"},
                {"httpupgradeSettings", {{"path", "/up"}, {"host", "localhost"}, {"realIpHeader", "X-Real-IP"}}}};
    Config(root.Path(), Json::array({Inbound(port, stream)}), Json::array({Direct()}), QuotaConfig());
    auto child = Start(root.Path());
    auto upgrade = [](std::string_view client) {
        std::string header = "GET /up HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n";
        if (!client.empty()) header += "X-Real-IP: " + std::string(client) + "\r\n";
        return header + "\r\n";
    };
    auto exchange = [&](Socket& socket, std::string_view client) {
        socket.Write(upgrade(client) + VlessRequest(target.Port(), kRequest));
        EXPECT_TRUE(ReadUntil(socket, "\r\n\r\n").starts_with("HTTP/1.1 101 "));
    };

    auto pending = Socket::Connect(port);
    pending.Write("GET /up HTTP/1.1\r\n");

    auto forwarded = Socket::Connect(port);
    exchange(forwarded, "198.51.100.7");
    EXPECT_EQ(forwarded.ReadExact(2 + kResponse.size()), std::string(2, '\0') + std::string(kResponse));

    auto direct = Socket::Connect(port);
    exchange(direct, {});
    EXPECT_EQ(direct.ReadExact(2 + kResponse.size()), std::string(2, '\0') + std::string(kResponse));

    auto duplicate = Socket::Connect(port);
    exchange(duplicate, "198.51.100.7");
    ExpectClosed(duplicate);
    EXPECT_TRUE(child->Running());
}
} // namespace
} // namespace cnode::e2e
