#include "config_panel_common.hpp"

#include <openssl/evp.h>

#include <format>
#include <tuple>

namespace cnode::e2e::config_panel {
namespace {

struct CipherCase {
    const char* name;
    const char* method;
    size_t key_size;
    bool identity;
    size_t selected;
};

std::string Key(size_t size, uint8_t start) {
    std::string key(size, '\0');
    for (size_t i = 0; i < size; ++i) key[i] = static_cast<char>(start + i);
    std::string encoded(4 * ((size + 2) / 3), '\0');
    const int count = EVP_EncodeBlock(reinterpret_cast<uint8_t*>(encoded.data()),
        reinterpret_cast<const uint8_t*>(key.data()), static_cast<int>(key.size()));
    if (count != static_cast<int>(encoded.size())) throw std::runtime_error("fixture base64 encoding failed");
    return encoded;
}

// This peer forwards the actual C++ client's encrypted wire unchanged and only
// records client-to-server bytes. It is not a substitute Shadowsocks endpoint.
void ForwardOne(Socket& listener, uint16_t server_port, std::string_view proxy_header,
                std::string* captured) {
    auto downstream = listener.Accept();
    auto upstream = Socket::Connect(server_port);
    upstream.Write(proxy_header);
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    bool down_eof = false;
    while (std::chrono::steady_clock::now() < deadline) {
        pollfd descriptors[] = {{down_eof ? -1 : downstream.Fd(), POLLIN, 0},
                                {upstream.Fd(), POLLIN, 0}};
        const int ready = ::poll(descriptors, 2, 100);
        if (ready < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "SS2022 capture poll");
        }
        if (descriptors[0].revents) {
            const auto bytes = downstream.Read();
            if (bytes.empty()) { down_eof = true; upstream.ShutdownWrite(); }
            else {
                if (captured) *captured += bytes;
                upstream.Write(bytes);
            }
        }
        if (descriptors[1].revents) {
            const auto bytes = upstream.Read();
            if (bytes.empty()) { downstream.ShutdownWrite(); return; }
            downstream.Write(bytes);
        }
    }
    throw std::runtime_error("SS2022 capture forwarding did not finish");
}

class Ss2022TcpReplay : public testing::TestWithParam<std::tuple<CipherCase, unsigned>> {};

TEST_P(Ss2022TcpReplay, RejectsCapturedRequestAndAcceptsFreshSaltWithoutBanningClient) {
    const auto& [cipher, workers] = GetParam();
    RecordProperty("configured_server_workers", static_cast<int>(workers));
    // This process test observes all replays rejected with the configured worker
    // count. It does not infer kernel REUSEPORT routing or distinct Worker IDs.
    // The two-explicit-reactor unit test proves cross-Worker pool authority.
    TempDir root;
    const auto server_dir = root.Path() / "server";
    const auto client_dir = root.Path() / "client";
    auto server_reservation = Socket::ReserveTcp();
    auto client_reservation = Socket::ReserveTcp();
    const auto server_port = server_reservation.Port();
    const auto client_port = client_reservation.Port();
    auto splitter = Socket::Listen();
    const std::string payload = "real-ss2022-tcp-replay-protection";
    const std::string proxy_header = std::format(
        "PROXY TCP4 192.0.2.7 127.0.0.1 44000 {}\r\n", server_port);
    std::atomic<unsigned> reached_backend{0};
    LoopServer backend([&](Socket socket) {
        ++reached_backend;
        const auto request = socket.ReadExact(payload.size());
        EXPECT_EQ(request, payload);
        socket.Write(request);
    });

    Json users = Json::array();
    for (size_t i = 0; i < 17; ++i) {
        users.push_back({{"password", Key(cipher.key_size, static_cast<uint8_t>(i))},
                         {"email", "salt-user-" + std::to_string(i) + "@example.test"}});
    }
    auto inbound = Inbound(server_port, "shadowsocks");
    inbound["proxyProtocol"] = "on";
    inbound["settings"] = {{"method", cipher.method}, {"clients", std::move(users)}};
    const auto identity_key = Key(cipher.key_size, 193);
    if (cipher.identity) inbound["settings"]["password"] = identity_key;
    Configure(server_dir, inbound, Direct(), workers);
    auto config = Json::parse(ReadFile(server_dir / "config.json"));
    config["log"]["loglevel"] = "debug";
    config["limits"]["ipBan"] = {
        {"enabled", true}, {"failureLimit", 1}, {"windowSeconds", 60}, {"banSeconds", 180}};
    WriteJson(server_dir, "config.json", config);
    auto server = Start(server_dir);
    server->WaitForLog("server started");

    const auto user_key = Key(cipher.key_size, static_cast<uint8_t>(cipher.selected));
    Configure(client_dir, Inbound(client_port), {{"protocol", "shadowsocks"},
        {"settings", {{"address", "127.0.0.1"}, {"port", splitter.Port()},
            {"method", cipher.method},
            {"password", cipher.identity ? identity_key + ':' + user_key : user_key}}}});
    auto client = Start(client_dir);
    client->WaitForLog("server started");

    std::string captured;
    {
        PeerThread forward([&, proxy_header] {
            ForwardOne(splitter, server_port, proxy_header, &captured);
        });
        auto request = Socket::Connect(client_port);
        request.Write(VlessRequest(backend.Port(), payload));
        EXPECT_EQ(request.ReadExact(payload.size() + 2), std::string("\0\0", 2) + payload);
        request.ShutdownWrite();
        forward.Join();
    }
    ASSERT_GT(captured.size(), cipher.key_size);
    ASSERT_EQ(reached_backend.load(), 1u);
    constexpr unsigned replay_count = 16;
    for (unsigned i = 0; i < replay_count; ++i) {
        SCOPED_TRACE(i);
        auto replay = Socket::Connect(server_port);
        replay.Write(proxy_header);
        replay.Write(captured);
        EXPECT_TRUE(ReadClosed(replay));
        EXPECT_EQ(reached_backend.load(), 1u);
    }
    {
        PeerThread forward([&, proxy_header] {
            ForwardOne(splitter, server_port, proxy_header, nullptr);
        });
        auto request = Socket::Connect(client_port);
        request.Write(VlessRequest(backend.Port(), payload));
        EXPECT_EQ(request.ReadExact(payload.size() + 2), std::string("\0\0", 2) + payload);
        request.ShutdownWrite();
        forward.Join();
    }
    EXPECT_EQ(reached_backend.load(), 2u);
    EXPECT_TRUE(server->Running());
    EXPECT_TRUE(client->Running());
    EXPECT_EQ(client->Stop(), 0);
    EXPECT_EQ(server->Stop(), 0);
    backend.Join();

}

INSTANTIATE_TEST_SUITE_P(RealCppClientAndServer, Ss2022TcpReplay,
    testing::Combine(testing::Values(
        CipherCase{"Aes128", "2022-blake3-aes-128-gcm", 16, false, 8},
        CipherCase{"Aes256", "2022-blake3-aes-256-gcm", 32, false, 8},
        CipherCase{"ChaCha20", "2022-blake3-chacha20-poly1305", 32, false, 8},
        CipherCase{"Aes128IdentityFirst", "2022-blake3-aes-128-gcm", 16, true, 0},
        CipherCase{"Aes128IdentityMiddle", "2022-blake3-aes-128-gcm", 16, true, 8},
        CipherCase{"Aes128IdentityLast", "2022-blake3-aes-128-gcm", 16, true, 16},
        CipherCase{"Aes256IdentityFirst", "2022-blake3-aes-256-gcm", 32, true, 0},
        CipherCase{"Aes256IdentityMiddle", "2022-blake3-aes-256-gcm", 32, true, 8},
        CipherCase{"Aes256IdentityLast", "2022-blake3-aes-256-gcm", 32, true, 16}),
        testing::Values(1u, 4u)),
    [](const testing::TestParamInfo<Ss2022TcpReplay::ParamType>& info) {
        return std::string(std::get<0>(info.param).name) + "Workers" +
               std::to_string(std::get<1>(info.param));
    });

}  // namespace
}  // namespace cnode::e2e::config_panel
