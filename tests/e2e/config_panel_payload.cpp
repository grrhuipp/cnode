#include "config_panel_common.hpp"

#include <openssl/sha.h>
#include <tuple>

namespace cnode::e2e::config_panel {
namespace {
constexpr std::string_view Password = "MiXeD-Secret_42";
constexpr std::string_view Banner = "initial-payload-peer-ready";
std::string Sha224Hex(std::string_view text) {
    unsigned char digest[SHA224_DIGEST_LENGTH];
    SHA224(reinterpret_cast<const unsigned char*>(text.data()), text.size(), digest);
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(2 * sizeof(digest));
    for (const auto byte : digest) { result += digits[byte >> 4]; result += digits[byte & 15]; }
    return result;
}
using PayloadCase = std::tuple<std::string, size_t, bool>;
class InitialPayload : public testing::TestWithParam<PayloadCase> {};
TEST_P(InitialPayload, PreservesAuthenticationTargetServerFirstGreetingAndByteOrder) {
    const auto& [protocol, size, mixed] = GetParam();
    TempDir directory;
    std::string prefix(size, '\0'), tail;
    for (size_t i = 0; i < size; ++i) prefix[i] = static_cast<char>((i * 37 + 11) & 255);
    for (int i = 0; i < 9; ++i) tail += "later-payload-";
    const auto expected = prefix + tail;
    auto backend = Socket::Listen();
    auto reservation = Socket::Listen();
    const auto port = reservation.Port();
    Json outbound = {{"protocol", protocol}, {"settings", Json::object()}};
    if (protocol == "vless") outbound["settings"]["vnext"] = Json::array({
        {{"address", "127.0.0.1"}, {"port", backend.Port()},
         {"users", Json::array({{{"id", UserA}, {"encryption", "none"}}})}}
    });
    if (protocol == "trojan") outbound["settings"] = {{"servers", Json::array({{{"address", "127.0.0.1"},
        {"port", backend.Port()}, {"password", Password}}})}};
    if (protocol == "anytls") outbound["settings"] = {{"address", "127.0.0.1"}, {"port", backend.Port()},
        {"password", Password}, {"idleSessionCheckInterval", 1}, {"idleSessionTimeout", 1}, {"minIdleSession", 0}};
    if (protocol == "anytls" || protocol == "trojan") outbound["streamSettings"] = TlsSettings(false);
    auto inbound = Inbound(port, "vless", UserA);
    inbound["sniffing"] = {{"enabled", false}};
    Configure(directory.Path(), inbound, outbound);
    auto config = Json::parse(ReadFile(directory.Path() / "config.json"));
    config["timeouts"]["downlinkOnly"] = 3;
    WriteJson(directory.Path(), "config.json", config);
    if (mixed) {
        for (const auto name : {"config.json", "inbounds.json", "outbounds.json", "routing.json"})
            WriteJson(directory.Path(), name, MixedKeys(Json::parse(ReadFile(directory.Path() / name))));
    }
    TlsContext tls(true);
    std::string received;
    std::atomic<bool> application_finished = false;
    PeerThread peer([&] {
        auto socket = backend.Accept();
        if (protocol == "anytls") {
            TlsSocket stream(std::move(socket), tls, true);
            ReadAnyTlsAuthentication(stream, Password);
            bool settings_seen = false, target_seen = false, reply_sent = false, reply_acknowledged = false;
            uint32_t stream_id = 0;
            while (!reply_acknowledged) {
                const auto frame = ReadAnyTls(stream);
                switch (frame.command) {
                case 0: // Padding is not application data.
                    break;
                case 4:
                    EXPECT_FALSE(settings_seen);
                    EXPECT_EQ(frame.stream, 0u);
                    EXPECT_NE(frame.payload.find("v=2"), std::string::npos);
                    settings_seen = true;
                    stream.Write(AnyTlsFrame(10, 0, "v=2"));
                    break;
                case 1:
                    EXPECT_TRUE(settings_seen);
                    EXPECT_EQ(stream_id, 0u);
                    EXPECT_NE(frame.stream, 0u);
                    EXPECT_TRUE(frame.payload.empty());
                    stream_id = frame.stream;
                    stream.Write(AnyTlsFrame(7, stream_id));
                    break;
                case 2:
                    EXPECT_TRUE(settings_seen);
                    EXPECT_NE(stream_id, 0u);
                    EXPECT_EQ(frame.stream, stream_id);
                    if (!target_seen) {
                        EXPECT_EQ(frame.payload, SocksAddress(443));
                        target_seen = true;
                        stream.Write(AnyTlsFrame(2, stream_id, Banner));
                    } else {
                        received += frame.payload;
                        if (received.size() > expected.size()) throw std::runtime_error("duplicate AnyTLS initial payload");
                        if (received.size() == expected.size() && !reply_sent) {
                            EXPECT_EQ(received, expected);
                            reply_sent = true;
                            stream.Write(AnyTlsFrame(2, stream_id, received) + AnyTlsFrame(3, stream_id) +
                                         AnyTlsFrame(8, 0));
                        }
                    }
                    break;
                case 8:
                    EXPECT_EQ(frame.stream, 0u);
                    EXPECT_TRUE(frame.payload.empty());
                    stream.Write(AnyTlsFrame(9, 0));
                    break;
                case 9:
                    EXPECT_TRUE(reply_sent);
                    EXPECT_EQ(frame.stream, 0u);
                    EXPECT_TRUE(frame.payload.empty());
                    reply_acknowledged = true;
                    break;
                default:
                    throw std::runtime_error("unexpected AnyTLS initial-payload control frame");
                }
            }
            EXPECT_TRUE(target_seen);
            EXPECT_EQ(received, expected);
            // FIN ends the logical stream, not its pooled TLS session. An immediate
            // socket close races delivery and turns queued replies into transport errors.
            // Keep the session alive until the application has consumed both data and FIN.
            Until([&] { return application_finished.load(); });
            stream.ShutdownWrite();
        } else if (protocol == "trojan") {
            TlsSocket stream(std::move(socket), tls, true);
            EXPECT_EQ(stream.ReadExact(58), Sha224Hex(Password) + "\r\n");
            EXPECT_EQ(stream.ReadExact(10), std::string(1, '\1') + SocksAddress(443) + "\r\n");
            stream.Write(Banner);
            received = stream.ReadExact(expected.size());
            EXPECT_EQ(received, expected);
            stream.Write(received);
            stream.ShutdownWrite();
        } else {
            if (protocol == "vless") {
                const auto auth = socket.ReadExact(18);
                EXPECT_EQ(auth.substr(0, 17), std::string(1, '\0') + UuidBytes(UserA));
                socket.ReadExact(static_cast<unsigned char>(auth[17]));
                EXPECT_EQ(socket.ReadExact(8), std::string("\1\1\xbb\1\x7f\0\0\1", 8));
                socket.Write(std::string("\0\0", 2));
            }
            socket.Write(Banner);
            received = socket.ReadExact(expected.size());
            EXPECT_EQ(received, expected);
            socket.Write(received);
            socket.ShutdownWrite();
        }
    });
    reservation.Close();
    auto child = Start(directory.Path());
    child->WaitForLog("server started");
    auto client = Socket::Connect(port);
    client.Write(VlessRequest(protocol == "freedom" ? backend.Port() : 443, prefix, 1, "127.0.0.1", UserA));
    EXPECT_EQ(client.ReadExact(2 + Banner.size()), std::string("\0\0", 2) + std::string(Banner));
    client.Write(tail);
    if (protocol == "freedom" || protocol == "vless") client.ShutdownWrite();
    EXPECT_EQ(client.ReadExact(expected.size()), expected);
    if (protocol == "trojan") client.ShutdownWrite();
    if (protocol == "anytls")
        EXPECT_TRUE(client.Read(1, 5s).empty()) << "unexpected extra bytes after AnyTLS FIN";
    else
        EXPECT_TRUE(ReadClosed(client, 5s)) << "unexpected extra bytes or missing final EOF";
    application_finished = true;
    peer.Join();
    EXPECT_EQ(received, expected);
    EXPECT_TRUE(child->Running());
    EXPECT_EQ(child->Stop(), 0);
}
INSTANTIATE_TEST_SUITE_P(ProtocolsAndSizes, InitialPayload,
    testing::Values(PayloadCase{"freedom", 0, false}, PayloadCase{"freedom", 17, false}, PayloadCase{"freedom", 24000, false},
        PayloadCase{"vless", 0, false}, PayloadCase{"vless", 17, false}, PayloadCase{"vless", 24000, false},
        PayloadCase{"trojan", 0, false}, PayloadCase{"trojan", 17, false}, PayloadCase{"trojan", 24000, false},
        PayloadCase{"anytls", 0, false}, PayloadCase{"anytls", 17, false}, PayloadCase{"anytls", 24000, false},
        PayloadCase{"trojan", 17, true}));
} // namespace
} // namespace cnode::e2e::config_panel
