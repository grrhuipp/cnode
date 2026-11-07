#include "tls_wire.hpp"

namespace cnode::e2e {
namespace {
using namespace tls;
Json UpgradeTransport(bool secured, bool server) {
    auto stream = secured ? TlsSettings(server) : Json{{"security", "none"}};
    stream["network"] = "httpupgrade";
    stream["httpupgradeSettings"] = {{"path", "/up"}, {"host", "localhost"}};
    return stream;
}
class HttpUpgrade : public testing::TestWithParam<std::string> {};
TEST_P(HttpUpgrade, PreservesReadAheadSegmentationAndDirectionalEof) {
    const auto mode = GetParam();
    const bool secured = mode.ends_with("tls"), chained = mode.starts_with("chain");
    TempDir root;
    auto target = Socket::Listen();
    auto upgrade_reservation = Socket::Listen(), raw_reservation = Socket::Listen();
    const auto upgrade_port = upgrade_reservation.Port(), raw_port = raw_reservation.Port();
    std::string payload;
    for (unsigned i = 0; i < 719; ++i) for (unsigned byte = 0; byte < 251; ++byte) payload += static_cast<char>(byte);
    std::atomic<bool> eof{false};
    PeerThread backend([&] {
        auto socket = target.Accept();
        auto bytes = socket.ReadExact(payload.size());
        Require(bytes == payload, "corrupted HTTPUpgrade upload");
        socket.Write(bytes);
        socket.ShutdownWrite();
        Require(socket.Read(1).empty(), "extra HTTPUpgrade upload");
        eof = true;
    });
    auto upgrade = Inbound(upgrade_port, UpgradeTransport(secured, true));
    upgrade["tag"] = "upgrade";
    auto raw = Inbound(raw_port);
    raw["tag"] = "raw";
    raw["outboundTag"] = "next";
    Json next{{"tag", "next"}, {"protocol", "vless"},
              {"settings", {{"address", "127.0.0.1"}, {"port", upgrade_port}, {"id", UserId}, {"encryption", "none"}}},
              {"streamSettings", UpgradeTransport(secured, false)}};
    Config(root.Path(), Json::array({upgrade, raw}), Json::array({Direct(), next}));
    upgrade_reservation.Close(); raw_reservation.Close();
    auto child = Start(root.Path());
    const std::string header = "GET /up HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\ncOnNeCtIoN: UpGrAdE\r\nUpgrade: websocket\r\n\r\n";
    const auto request = VlessRequest(target.Port());
    auto exchange = [&](auto& stream) {
        if (mode.starts_with("coalesced")) stream.Write(header + request + payload.substr(0, 1024));
        else if (mode.starts_with("fragmented")) {
            for (const auto& part : {header.substr(0, 13), header.substr(13, header.size() - 15), header.substr(header.size() - 2)}) {
                stream.Write(part);
                std::this_thread::sleep_for(20ms);
            }
            EXPECT_TRUE(ReadUntil(stream, "\r\n\r\n").starts_with("HTTP/1.1 101 "));
            stream.Write(request + payload.substr(0, 1024));
        } else stream.Write(request + payload.substr(0, 1024));
        if (mode.starts_with("coalesced")) EXPECT_TRUE(ReadUntil(stream, "\r\n\r\n").starts_with("HTTP/1.1 101 "));
        for (size_t offset = 1024; offset < payload.size(); offset += 16381)
            stream.Write(std::string_view(payload).substr(offset, 16381));
        if (!secured || chained) stream.ShutdownWrite();
        EXPECT_EQ(stream.ReadExact(2), std::string(2, '\0'));
        EXPECT_EQ(stream.ReadExact(payload.size()), payload);
        EXPECT_TRUE(stream.Read().empty());
    };
    if (secured && !chained) {
        TlsContext context(false);
        WireTls stream(Socket::Connect(upgrade_port), context);
        exchange(stream);
    } else {
        auto stream = Socket::Connect(chained ? raw_port : upgrade_port);
        exchange(stream);
    }
    backend.Join();
    EXPECT_TRUE(eof.load());
    EXPECT_TRUE(child->Running());
}
INSTANTIATE_TEST_SUITE_P(PlainAndTls, HttpUpgrade,
    testing::Values("coalesced", "fragmented", "coalesced-tls", "fragmented-tls", "chain", "chain-tls"));
} // namespace
} // namespace cnode::e2e
