#include "tls_wire.hpp"

namespace cnode::e2e {
namespace {
using namespace tls;
void ExpectClosed(Socket& socket) {
    pollfd fd{socket.Fd(), POLLIN, 0};
    ASSERT_GT(poll(&fd, 1, 5000), 0) << "rejected connection did not close";
    char byte = 0;
    auto n = recv(socket.Fd(), &byte, 1, 0);
    EXPECT_TRUE(n == 0 || (n < 0 && errno == ECONNRESET)) << "unexpected data or socket error " << errno;
}
TEST(ProxyProtocol, OffAutoOnAndDefaultPreserveOptionalHeaderBoundaries) {
    TempDir root;
    auto target = Socket::Listen();
    auto on = Socket::Listen(), off = Socket::Listen(), automatic = Socket::Listen(), fallback = Socket::Listen();
    const uint16_t required = on.Port(), disabled = off.Port(), auto_port = automatic.Port(), default_port = fallback.Port();
    Json inbounds = Json::array();
    for (const auto& [port, mode] : std::array<std::pair<uint16_t, std::string>, 4>{{{required, "on"}, {disabled, "off"}, {auto_port, "auto"}, {default_port, "default"}}}) {
        auto in = Inbound(port);
        in["tag"] = mode;
        if (mode != "default") in["proxyProtocol"] = mode;
        inbounds.push_back(in);
    }
    Json config{{"timeouts", {{"handshake", 2}, {"connIdle", 5}}},
        {"log", {{"loglevel", "info"}, {"access", "access.log"}, {"error", "error.log"}, {"rotateDaily", false}, {"gzip", false}}}};
    Config(root.Path(), inbounds, Json::array({Direct()}), config);
    on.Close(); off.Close(); automatic.Close(); fallback.Close();
    auto child = Start(root.Path());
    const std::string payload = "proxy-mode-boundary";
    const auto request = VlessRequest(target.Port(), payload);
    const std::string signature("\r\n\r\n\0\r\nQUIT\n", 12);
    const std::string v1 = "PROXY TCP4 192.0.2.1 198.51.100.1 32100 443\r\n";
    const std::string v2 = signature + std::string("\x21\x11\x00\x0c\xc0\x00\x02\x01\xc6\x33\x64\x01", 12) + BigEndian(32100, 2) + BigEndian(443, 2);
    struct Accepted { const char* name; uint16_t port; std::string prefix; bool fragmented; };
    const std::vector<Accepted> accepted{
        {"disabled-plain", disabled, {}, false}, {"required-v1", required, v1, false},
        {"required-v1-fragmented", required, v1, true}, {"required-v2", required, v2, false},
        {"required-v2-fragmented", required, v2, true}, {"required-v1-unknown", required, "PROXY UNKNOWN\r\n", false},
        {"required-v2-local", required, signature + std::string("\x20\0\0\0", 4), false},
        {"auto-plain", auto_port, {}, false}, {"auto-v1", auto_port, v1, false},
        {"auto-v2-fragmented", auto_port, v2, true}, {"default-plain", default_port, {}, false},
        {"default-v1-fragmented", default_port, v1, true}, {"default-v2", default_port, v2, false}};
    for (const auto& item : accepted) {
        SCOPED_TRACE(item.name);
        PeerThread backend([&] {
            auto socket = target.Accept();
            Require(socket.ReadExact(payload.size()) == payload, "PROXY target payload");
            socket.Write(payload);
        });
        auto socket = Socket::Connect(item.port);
        if (item.fragmented) {
            for (char byte : item.prefix) { socket.Write(std::string_view(&byte, 1)); std::this_thread::sleep_for(1ms); }
            socket.Write(request);
        } else socket.Write(item.prefix + request);
        EXPECT_EQ(socket.ReadExact(2 + payload.size()), std::string(2, '\0') + payload);
        socket.Close();
        backend.Join();
    }
    struct Rejected { const char* name; uint16_t port; std::string wire; };
    const std::vector<Rejected> rejected{
        {"required-missing", required, request},
        {"required-invalid", required, "PROXY TCP4 invalid 198.51.100.1 1 2\r\n" + request},
        {"disabled-proxy-not-sniffed", disabled, v1 + request},
        {"auto-invalid", auto_port, "PROXY TCP4 invalid 198.51.100.1 1 2\r\n" + request},
        {"default-invalid", default_port, signature + std::string("\x21\x11\0\x01x", 5)}};
    for (const auto& item : rejected) {
        SCOPED_TRACE(item.name);
        auto socket = Socket::Connect(item.port);
        socket.Write(item.wire);
        ExpectClosed(socket);
    }
    for (bool truncated : {false, true}) {
        auto socket = Socket::Connect(auto_port);
        if (truncated) socket.Write("PROX");
        socket.ShutdownWrite();
        ExpectClosed(socket);
    }
    EXPECT_TRUE(child->Running());
    child->Stop();
}
} // namespace
} // namespace cnode::e2e
