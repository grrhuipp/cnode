#include "config_panel_common.hpp"
#include <openssl/sha.h>

namespace cnode::e2e::config_panel {
namespace {
TEST(InboundHandshake, SegmentedVmessTrojanReplayFlowEofAndDeadline) {
    TempDir directory;
    const auto server_dir = directory.Path() / "vmess-server";
    const auto client_dir = directory.Path() / "vmess-client";
    const auto trojan_dir = directory.Path() / "trojan-server";
    std::filesystem::create_directories(server_dir);
    std::filesystem::create_directories(client_dir);
    std::filesystem::create_directories(trojan_dir);
    auto backend = Socket::Listen();
    auto server_reservation = Socket::Listen();
    auto front_reservation = Socket::Listen();
    auto trojan_reservation = Socket::Listen();
    const auto server_port = server_reservation.Port(), front_port = front_reservation.Port(), trojan_port = trojan_reservation.Port();
    const std::string payload = "vmess-inbound-handshake-regression";
    std::atomic<int> received{0};
    PeerThread destination([&] {
        for (int i = 0; i < 2; ++i) {
            auto socket = backend.Accept(15s);
            EXPECT_EQ(socket.ReadExact(payload.size()), payload);
            ++received;
            socket.Write(payload);
        }
    });
    Configure(server_dir, Inbound(server_port, "vmess"), Direct());
    auto config = Json::parse(ReadFile(server_dir / "config.json"));
    config["timeouts"]["handshake"] = 2;
    config["log"].update({{"enable", true}, {"loglevel", "debug"}});
    WriteJson(server_dir, "config.json", config);
    server_reservation.Close();
    auto server = Start(server_dir);
    server->WaitForLog("server started");
    auto splitter = Socket::Listen();
    std::string captured;
    PeerThread split([&] {
        auto downstream = splitter.Accept();
        auto upstream = Socket::Connect(server_port);
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        bool down_eof = false;
        while (std::chrono::steady_clock::now() < deadline) {
            pollfd fds[] = {{down_eof ? -1 : downstream.Fd(), POLLIN, 0}, {upstream.Fd(), POLLIN, 0}};
            if (::poll(fds, 2, 100) < 0) {
                if (errno == EINTR) continue;
                throw std::runtime_error("VMess splitter poll failed");
            }
            if (fds[0].revents) {
                const auto bytes = downstream.Read();
                if (bytes.empty()) { down_eof = true; upstream.ShutdownWrite(); }
                else {
                    captured += bytes;
                    for (const auto byte : bytes) {
                        upstream.Write(std::string_view(&byte, 1));
                        std::this_thread::sleep_for(1ms);
                    }
                }
            }
            if (fds[1].revents) {
                const auto bytes = upstream.Read();
                if (bytes.empty()) { downstream.ShutdownWrite(); return; }
                downstream.Write(bytes);
            }
        }
        throw std::runtime_error("VMess splitter did not finish");
    });
    Configure(client_dir, Inbound(front_port), {{"protocol", "vmess"},
        {"settings", {{"address", "127.0.0.1"}, {"port", splitter.Port()}, {"id", UserId}}}});
    config = Json::parse(ReadFile(client_dir / "config.json"));
    config["log"].update({{"enable", true}, {"loglevel", "debug"}});
    WriteJson(client_dir, "config.json", config);
    front_reservation.Close();
    auto client = Start(client_dir);
    client->WaitForLog("server started");
    {
        auto probe = Socket::Connect(front_port);
        probe.Write(VlessRequest(backend.Port(), payload));
        EXPECT_EQ(probe.ReadExact(payload.size() + 2, 6s), std::string("\0\0", 2) + payload);
        probe.ShutdownWrite();
    }
    split.Join();
    EXPECT_EQ(received, 1);
    ASSERT_FALSE(captured.empty());
    {
        auto replay = Socket::Connect(server_port);
        replay.Write(captured);
        EXPECT_TRUE(ReadClosed(replay));
        EXPECT_EQ(received, 1);
    }
    uint16_t rejected_flow_port = 0;
    {
        auto flow = Socket::Connect(front_port);
        rejected_flow_port = flow.Port();
        const std::string name = "xtls-rprx-vision";
        const auto addons = std::string(1, '\x0a') + std::string(1, static_cast<char>(name.size())) + name;
        flow.Write(std::string(1, '\0') + UuidBytes() + std::string(1, static_cast<char>(addons.size())) + addons +
            std::string(1, '\2') + BigEndian(backend.Port(), 2) + std::string("\1\x7f\0\0\1", 5));
        EXPECT_TRUE(ReadClosed(flow));
    }
    {
        auto eof = Socket::Connect(server_port);
        eof.ShutdownWrite();
        EXPECT_TRUE(ReadClosed(eof));
    }
    {
        auto silent = Socket::Connect(server_port);
        pollfd descriptor{silent.Fd(), POLLIN, 0};
        EXPECT_EQ(::poll(&descriptor, 1, 350), 0) << "silent handshake closed before deadline";
        EXPECT_TRUE(ReadClosed(silent, 4s));
    }
    EXPECT_TRUE(server->Running());
    EXPECT_TRUE(client->Running());
    auto trojan_inbound = Inbound(trojan_port, "trojan");
    trojan_inbound["settings"] = {{"clients", Json::array({{{"password", "segmented-secret"}}})}};
    trojan_inbound["streamSettings"] = TlsSettings(true);
    Configure(trojan_dir, trojan_inbound, Direct());
    trojan_reservation.Close();
    auto trojan = Start(trojan_dir);
    trojan->WaitForLog("server started");
    TlsContext tls(false);
    {
        TlsSocket stream(Socket::Connect(trojan_port), tls, false);
        unsigned char digest[SHA224_DIGEST_LENGTH];
        constexpr std::string_view password = "segmented-secret";
        SHA224(reinterpret_cast<const unsigned char*>(password.data()), password.size(), digest);
        constexpr char digits[] = "0123456789abcdef";
        std::string header;
        for (const auto byte : digest) { header += digits[byte >> 4]; header += digits[byte & 15]; }
        header += "\r\n\1";
        header += SocksAddress(backend.Port());
        header += "\r\n";
        for (const auto byte : header) { stream.Write(std::string_view(&byte, 1)); std::this_thread::sleep_for(1ms); }
        stream.Write(payload);
        EXPECT_EQ(stream.ReadExact(payload.size(), 6s), payload);
    }
    destination.Join();
    EXPECT_EQ(received, 2);
    EXPECT_TRUE(trojan->Running());
    EXPECT_EQ(trojan->Stop(), 0);
    EXPECT_EQ(client->Stop(), 0);
    EXPECT_EQ(server->Stop(), 0);
    bool replay_context = false, flow_context = false;
    std::istringstream server_logs(Logs(server_dir)), client_logs(Logs(client_dir));
    std::string line;
    while (std::getline(server_logs, line))
        if (line.find("rejected ") != std::string::npos && line.find("session replay admission rejected") != std::string::npos &&
            line.find("tcp:127.0.0.1:" + std::to_string(backend.Port())) != std::string::npos &&
            line.find("email:handshake@example.test") != std::string::npos) replay_context = true;
    while (std::getline(client_logs, line))
        if (line.find("127.0.0.1:" + std::to_string(rejected_flow_port)) != std::string::npos &&
            line.find("request flow not allowed") != std::string::npos &&
            line.find("udp:127.0.0.1:" + std::to_string(backend.Port())) != std::string::npos &&
            line.find("email:handshake@example.test") != std::string::npos) flow_context = true;
    EXPECT_TRUE(replay_context);
    EXPECT_TRUE(flow_context);
}
} // namespace
} // namespace cnode::e2e::config_panel
