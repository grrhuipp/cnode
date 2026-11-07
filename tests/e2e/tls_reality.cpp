#include "tls_wire.hpp"
#include <openssl/bytestring.h>
#include <openssl/mem.h>
#include <openssl/mldsa.h>

namespace cnode::e2e {
namespace {
using namespace tls;
constexpr std::string_view PrivateKey = "6Epi9xRmv1RL-Kiqrj6Fl523a9eagFMTc-oyzGC5IU8";
constexpr std::string_view PublicKey = "VPI8d_RKeP4K4eF69AY-QjrV325NaSe03p-a0zkcH3Q";
constexpr std::string_view ShortId = "0123456789abcdef";
constexpr std::string_view Seed = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const std::string Payload = "reality-end-to-end-verification-payload";

std::string MldsaPublic(bool wrong = false) {
    std::array<uint8_t, 32> seed{};
    seed[0] = wrong ? 1 : 0;
    MLDSA65_private_key private_key;
    MLDSA65_public_key public_key;
    const bool valid =
        MLDSA65_private_key_from_seed(&private_key, seed.data(), seed.size()) == 1 &&
        MLDSA65_public_from_private(&public_key, &private_key) == 1;
    OPENSSL_cleanse(&private_key, sizeof(private_key));
    Require(valid, "ML-DSA-65 fixture key derivation");
    std::array<uint8_t, MLDSA65_PUBLIC_KEY_BYTES> bytes{};
    bssl::ScopedCBB public_bytes;
    CBB_init_fixed(public_bytes.get(), bytes.data(), bytes.size());
    Require(MLDSA65_marshal_public_key(public_bytes.get(), &public_key) == 1 &&
            CBB_len(public_bytes.get()) == bytes.size(), "ML-DSA-65 fixture public key");
    constexpr std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string encoded;
    uint32_t accumulator = 0;
    unsigned bits = 0;
    for (auto byte : bytes) {
        accumulator = (accumulator << 8) | byte;
        bits += 8;
        while (bits >= 6) { bits -= 6; encoded += alphabet[(accumulator >> bits) & 63]; }
    }
    if (bits) encoded += alphabet[(accumulator << (6 - bits)) & 63];
    Require(encoded.size() == 2603, "ML-DSA-65 base64url size");
    return encoded;
}
Json ServerStream(uint16_t destination, unsigned xver = 0, bool quantum = true) {
    Json settings{{"dest", "127.0.0.1:" + std::to_string(destination)}, {"xver", xver},
        {"serverNames", {"example.com"}}, {"privateKey", PrivateKey}, {"shortIds", {ShortId}}};
    if (quantum) settings["mldsa65Seed"] = Seed;
    return {{"network", "tcp"}, {"security", "reality"}, {"realitySettings", settings}};
}
Json ClientOutbound(uint16_t destination, std::string_view fingerprint = "chrome", bool quantum = true,
                    bool wrong_key = false, bool spider = false) {
    Json settings{{"serverName", "example.com"}, {"publicKey", PublicKey},
                  {"shortId", spider ? "fedcba9876543210" : std::string(ShortId)}, {"fingerprint", fingerprint}};
    if (quantum) settings["mldsa65Verify"] = MldsaPublic(wrong_key);
    if (spider) settings["spiderX"] = "/spider-probe?ok=1";
    return {{"tag", "direct"}, {"protocol", "vless"},
        {"settings", {{"address", "127.0.0.1"}, {"port", destination}, {"id", UserId}, {"encryption", "none"}}},
        {"streamSettings", {{"network", "tcp"}, {"security", "reality"}, {"realitySettings", settings}}}};
}

class RealityAuthentication : public testing::TestWithParam<std::string> {};
TEST_P(RealityAuthentication, FragmentedClientHelloPreservesAuthentication) {
    const auto mode = GetParam();
    const bool quantum = mode != "classic";
    const bool wrong = mode == "wrong-mldsa";
    TempDir server_root, client_root;
    auto server_port = Socket::Listen(), entry_port = Socket::Listen();
    const auto server_number = server_port.Port(), entry_number = entry_port.Port();
    auto destination = Socket::Listen(), target = Socket::Listen();
    const unsigned xver = mode == "firefox" ? 1 : 0;
    Config(server_root.Path(), Json::array({Inbound(server_number, ServerStream(destination.Port(), xver, quantum))}), Json::array({Direct()}));
    server_port.Close();
    auto server = Start(server_root.Path());
    FragmentingProxy proxy(server_number);
    const std::string_view fingerprint =
        wrong ? std::string_view("random") :
        mode == "classic" ? std::string_view("chrome") : std::string_view(mode);
    auto outbound = ClientOutbound(proxy.Port(), fingerprint, quantum, wrong);
    // The default case omits the field; an explicit empty value is invalid.
    if (mode.empty()) outbound["streamSettings"]["realitySettings"].erase("fingerprint");
    Config(client_root.Path(), Json::array({Inbound(entry_number)}), Json::array({outbound}));
    entry_port.Close();
    auto client = Start(client_root.Path());
    std::atomic<bool> stop_echo{false}, target_connected{false};
    PeerThread echo([&] {
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (std::chrono::steady_clock::now() < deadline) {
            pollfd fd{target.Fd(), POLLIN, 0};
            const int ready = poll(&fd, 1, 50);
            if (ready < 0 && errno == EINTR) continue;
            Require(ready >= 0, "REALITY target poll");
            if (ready == 0) {
                if (stop_echo.load()) return;
                continue;
            }
            auto accepted = target.Accept();
            target_connected = true;
            auto bytes = accepted.ReadExact(Payload.size());
            Require(bytes == Payload, "REALITY target payload");
            accepted.Write(bytes);
            return;
        }
        Require(wrong, "authenticated REALITY never reached its target");
    });
    auto socket = Socket::Connect(entry_number);
    socket.Write(VlessRequest(target.Port(), Payload));
    if (wrong) {
        std::string response;
        try { response = socket.ReadExact(2 + Payload.size()); } catch (const std::exception&) {}
        EXPECT_NE(response, std::string(2, '\0') + Payload);
    } else {
        EXPECT_EQ(socket.ReadExact(2 + Payload.size()), std::string(2, '\0') + Payload);
    }
    socket.Close();
    EXPECT_TRUE(server->Running());
    EXPECT_TRUE(client->Running());
    client->Stop();
    server->Stop();
    stop_echo = true;
    echo.Join();
    EXPECT_EQ(target_connected.load(), !wrong)
        << "a rejected ML-DSA key must never open the target connection";
    proxy.Join();
    EXPECT_TRUE(proxy.fragmented.load());
}
INSTANTIATE_TEST_SUITE_P(FingerprintsAndPostQuantum, RealityAuthentication,
                        testing::Values("chrome", "firefox", "safari", "ios", "android",
                                        "edge", "360", "qq", "random", "randomized",
                                        "auto", "", "classic", "wrong-mldsa"));

class RealityFallback : public testing::TestWithParam<unsigned> {};
TEST_P(RealityFallback, UnauthenticatedBytesAndProxyMetadataReachDestination) {
    const auto xver = GetParam();
    TempDir root;
    auto reservation = Socket::Listen(), destination = Socket::Listen();
    const auto port = reservation.Port();
    const std::string plain = xver == 2 ? std::string("\x16\x03\x01\0\x05hello", 10)
                                       : "GET /plain-http HTTP/1.1\r\nHost: example.com\r\n\r\n";
    std::string observed;
    PeerThread fallback([&] {
        auto socket = destination.Accept();
        if (xver == 1) observed = ReadUntil(socket, "\r\n");
        if (xver == 2) observed = socket.ReadExact(28);
        observed += socket.ReadExact(plain.size());
        socket.Write("FALLBACK-OK");
    });
    Config(root.Path(), Json::array({Inbound(port, ServerStream(destination.Port(), xver))}), Json::array({Direct()}));
    reservation.Close();
    auto child = Start(root.Path());
    auto socket = Socket::Connect(port);
    const auto source_port = socket.Port();
    socket.Write(plain);
    EXPECT_EQ(socket.ReadExact(11), "FALLBACK-OK");
    fallback.Join();
    if (xver == 0) EXPECT_EQ(observed, plain);
    if (xver == 1) {
        EXPECT_TRUE(observed.starts_with("PROXY TCP4 127.0.0.1 127.0.0.1 "));
        EXPECT_TRUE(observed.ends_with(plain));
        EXPECT_NE(observed.find(" " + std::to_string(source_port) + " " + std::to_string(port) + "\r\n"), std::string::npos);
    }
    if (xver == 2) {
        const std::string prefix("\r\n\r\n\0\r\nQUIT\n\x21\x11\0\x0c\x7f\0\0\1\x7f\0\0\1", 24);
        EXPECT_TRUE(observed.starts_with(prefix));
        EXPECT_EQ(observed.substr(24, 4), BigEndian(source_port, 2) + BigEndian(port, 2));
        EXPECT_EQ(observed.substr(28), plain);
    }
    EXPECT_TRUE(child->Running());
}
INSTANTIATE_TEST_SUITE_P(ProxyVersions, RealityFallback, testing::Values(0u, 1u, 2u));

TEST(Reality, WrongShortIdTriggersTlsSpiderFallback) {
    TempDir server_root, client_root;
    auto destination = Socket::Listen(), server_reservation = Socket::Listen(), entry_reservation = Socket::Listen();
    const auto server_port = server_reservation.Port(), entry_port = entry_reservation.Port();
    std::string request;
    PeerThread fallback([&] {
        TlsContext context(true);
        WireTls stream(destination.Accept(), context, true);
        request = ReadUntil(stream, "\r\n\r\n");
        stream.Write("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 13\r\nConnection: close\r\n\r\nfallback-body");
        stream.ShutdownWrite();
    });
    Config(server_root.Path(), Json::array({Inbound(server_port, ServerStream(destination.Port()))}), Json::array({Direct()}));
    Config(client_root.Path(), Json::array({Inbound(entry_port)}), Json::array({ClientOutbound(server_port, "safari", false, false, true)}));
    server_reservation.Close(); entry_reservation.Close();
    auto server = Start(server_root.Path());
    auto client = Start(client_root.Path());
    auto socket = Socket::Connect(entry_port);
    socket.Write(VlessRequest(443, Payload));
    std::string response;
    try { response = socket.ReadExact(2 + Payload.size()); } catch (const std::exception&) {}
    EXPECT_NE(response, std::string(2, '\0') + Payload);
    fallback.Join();
    EXPECT_TRUE(request.starts_with("GET /spider-probe?ok=1 HTTP/1.1\r\n"));
    EXPECT_TRUE(server->Running());
    EXPECT_TRUE(client->Running());
}

// The panel is a protocol fixture, not a replacement for cnode: its fetched
// configuration creates the real listener and authenticates the real relay.
class RealityPanel {
public:
    RealityPanel(uint16_t node, uint16_t dest) : listener_(Socket::Listen()), thread_([this, node, dest] {
        while (!stop_.load()) {
            pollfd fd{listener_.Fd(), POLLIN, 0};
            int ready = poll(&fd, 1, 50);
            if (ready < 0 && errno == EINTR) continue;
            Require(ready >= 0, "panel poll");
            if (!ready) continue;
            auto socket = listener_.Accept();
            auto header = ReadUntil(socket, "\r\n\r\n");
            Json body = Json::object();
            if (header.find("/config?") != std::string::npos) {
                body = {{"server_port", node}, {"network", "tcp"}, {"tls", 2}, {"flow", ""},
                    {"server_name", "example.com"}, {"tls_settings", {{"private_key", PrivateKey},
                    {"short_id", {ShortId}}, {"dest", "127.0.0.1:" + std::to_string(dest)}, {"xver", 1}, {"mldsa65_seed", Seed}}},
                    {"base_config", {{"pull_interval", 1}, {"push_interval", 60}}}};
                ++configs;
            } else if (header.find("/user?") != std::string::npos) {
                body = {{"users", {{{"id", 42}, {"uuid", UserId}, {"speed_limit", 0}, {"device_limit", 0}}}}};
                ++users;
            } else if (header.starts_with("POST ")) {
                // Consume a posted body before closing to avoid TCP reset of
                // the status response when curl sends buffered request data.
                const auto length_at = header.find("Content-Length:");
                if (length_at != std::string::npos) socket.ReadExact(std::stoul(header.substr(length_at + 15)));
                body = {{"status", "ok"}};
            }
            auto bytes = body.dump();
            socket.Write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + std::to_string(bytes.size()) + "\r\n\r\n" + bytes);
        }
    }) {}
    ~RealityPanel() { stop_ = true; }
    uint16_t Port() const { return listener_.Port(); }
    void Join() { stop_ = true; thread_.Join(); }
    std::atomic<unsigned> configs{0}, users{0};
private:
    Socket listener_;
    std::atomic<bool> stop_{false};
    PeerThread thread_;
};

TEST(Reality, V2BoardTlsTwoSynchronizesPostQuantumListenerAndUsers) {
    TempDir root;
    auto node_reservation = Socket::Listen(), entry_reservation = Socket::Listen();
    auto destination = Socket::Listen(), target = Socket::Listen();
    const auto node = node_reservation.Port(), entry = entry_reservation.Port();
    RealityPanel panel(node, destination.Port());
    auto outbound = ClientOutbound(node);
    outbound["tag"] = "panel-reality-out";
    auto inbound = Inbound(entry);
    inbound["outboundTag"] = "panel-reality-out";
    Json config{{"panels", {{{"name", "v2b"}, {"type", "V2board"},
        {"apiHost", "http://127.0.0.1:" + std::to_string(panel.Port())}, {"key", "test-token"},
        {"nodeIDs", {1}}, {"nodeType", "vless"}, {"listenIP", "127.0.0.1"}, {"requestTimeout", 1}}}}};
    Config(root.Path(), Json::array({inbound}), Json::array({Direct(), outbound}), config);
    node_reservation.Close(); entry_reservation.Close();
    auto child = Start(root.Path());
    Until([&] { return panel.users.load() > 0; }, 10s);
    std::this_thread::sleep_for(200ms);
    PeerThread echo([&] {
        auto socket = target.Accept();
        auto bytes = socket.ReadExact(Payload.size());
        Require(bytes == Payload, "panel REALITY target payload");
        socket.Write(bytes);
    });
    auto socket = Socket::Connect(entry);
    socket.Write(VlessRequest(target.Port(), Payload));
    EXPECT_EQ(socket.ReadExact(2 + Payload.size()), std::string(2, '\0') + Payload);
    socket.Close();
    echo.Join();
    EXPECT_GT(panel.configs.load(), 0u);
    EXPECT_GT(panel.users.load(), 0u);
    EXPECT_TRUE(child->Running());
    child->Stop();
    panel.Join();
}
} // namespace
} // namespace cnode::e2e
