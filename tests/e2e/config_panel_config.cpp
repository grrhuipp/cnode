#include "config_panel_common.hpp"
#include "config_panel_cases.hpp"

#include <regex>

namespace cnode::e2e::config_panel {
namespace {
std::string ExpandFixture(std::string text) {
    const std::string marker = "@SOURCE@";
    for (size_t at; (at = text.find(marker)) != std::string::npos;)
        text.replace(at, marker.size(), SourceRoot().string());
    return text;
}
class ConfigSources : public testing::TestWithParam<ConfigCase> {};
TEST_P(ConfigSources, RejectsInvalidSourcesAndStartsValidSources) {
    const auto& value = GetParam();
    SCOPED_TRACE(value.name);
    TestPortLock lock;
    TempDir directory;
    WriteFile(directory.Path() / "config.json", ExpandFixture(value.main));
    std::vector<Socket> reservations;
    if (*value.sidecar) {
        std::string content = ExpandFixture(value.content);
        // Preserve raw duplicate keys and malformed JSON. Only replace the old
        // fixture's otherwise-valid listener port tokens, never invalid ports.
        if (std::string_view(value.sidecar) == "inbounds.json") {
            const std::regex port(R"("port":(12[0-9]{3}|43[0-9]{3})([,}]))");
            std::map<std::string, uint16_t> replacements;
            std::string relocated;
            std::smatch match;
            while (std::regex_search(content, match, port)) {
                const auto old = match[1].str();
                if (!replacements.contains(old)) {
                    reservations.push_back(Socket::ReserveTcp());
                    replacements[old] = reservations.back().Port();
                }
                relocated += match.prefix().str() + "\"port\":" + std::to_string(replacements[old]) + match[2].str();
                content = match.suffix().str();
            }
            content = relocated + content;
        }
        WriteFile(directory.Path() / value.sidecar, content);
    }
    auto child = Start(directory.Path());
    if (value.starts) {
        child->WaitForServerStart();
        EXPECT_TRUE(child->Running());
        EXPECT_EQ(child->Stop(), 0);
    } else {
        const int status = child->Wait(5s);
        EXPECT_GT(status, 0) << ReadFile(child->LogPath());
        EXPECT_LT(status, 128) << "configuration must reject, not crash";
    }
}
INSTANTIATE_TEST_SUITE_P(CompleteMatrix, ConfigSources, testing::ValuesIn(ConfigCases),
    [](const testing::TestParamInfo<ConfigCase>& info) { return info.param.name; });

class StaticRouting : public testing::TestWithParam<bool> {};
TEST_P(StaticRouting, DefaultDirectForcedOutboundAndOptInRouting) {
    TempDir directory;
    auto default_reservation = Socket::ReserveTcp();
    auto forced_reservation = Socket::ReserveTcp();
    auto routed_reservation = Socket::ReserveTcp();
    const auto direct_port = default_reservation.Port(), forced_port = forced_reservation.Port(), routed_port = routed_reservation.Port();
    auto direct = Inbound(direct_port, "vless", UserA);
    direct["tag"] = "default-direct";
    auto forced = Inbound(forced_port, "vless", UserA);
    forced.update({{"tag", "forced"}, {"routingEnabled", true}, {"outboundTag", "Chosen"}});
    auto routed = Inbound(routed_port, "vless", UserA);
    routed.update({{"tag", "routed"}, {"routingEnabled", true}});
    const bool mixed = GetParam();
    std::map<std::string, Json> files = {
        {"config.json", {{"workers", 1}, {"log", {{"logDir", (directory.Path() / "CaseSensitiveLogs").string()}}}}},
        {"inbounds.json", Json::array({direct, forced, routed})},
        {"outbounds.json", Json::array({{{"tag", "Chosen"}, {"protocol", "freedom"}}, {{"tag", "chosen"}, {"protocol", "blackhole"}}})},
        {"routing.json", {{"rules", Json::array({{{"type", "field"}, {"inboundTag", {"default-direct", "forced", "routed"}}, {"outboundTag", "blackhole"}}})}}}
    };
    for (const auto& [name, value] : files) WriteJson(directory.Path(), name, mixed ? MixedKeys(value) : value);
    auto backend = Socket::Listen();
    std::atomic<int> reached = 0;
    PeerThread peer([&] {
        for (int i = 0; i < 2; ++i) {
            auto socket = backend.Accept();
            EXPECT_EQ(socket.ReadExact(Payload.size()), Payload);
            ++reached;
            socket.Write(Payload);
        }
    });
    Child child({Binary().string(), mixed ? "--config-file" : "--config-dir",
                 mixed ? (directory.Path() / "config.json").string() : directory.Path().string()}, directory.Path() / "child.log", directory.Path());
    child.WaitForServerStart();
    EXPECT_TRUE(Echo(direct_port, backend.Port()));
    EXPECT_TRUE(Echo(forced_port, backend.Port()));
    peer.Join();
    EXPECT_FALSE(Echo(routed_port, backend.Port()));
    pollfd pending{backend.Fd(), POLLIN, 0};
    EXPECT_EQ(::poll(&pending, 1, 100), 0) << "routed request reached blackholed destination";
    EXPECT_EQ(reached, 2);
    EXPECT_EQ(child.Stop(), 0);
    if (mixed) {
        ASSERT_TRUE(std::filesystem::is_directory(directory.Path() / "CaseSensitiveLogs"));
        bool log_found = false;
        for (const auto& entry : std::filesystem::directory_iterator(directory.Path() / "CaseSensitiveLogs"))
            log_found |= entry.path().extension() == ".log";
        EXPECT_TRUE(log_found);
    }
}
INSTANTIATE_TEST_SUITE_P(LocalKeyCasing, StaticRouting, testing::Bool());

class BlackholeResponse : public testing::TestWithParam<bool> {};
TEST_P(BlackholeResponse, RejectsWithoutDialingAndClosesAfterOptionalHttpResponse) {
    TempDir directory;
    PortReservation reservation;
    auto backend = Socket::Listen();
    Json settings = Json::object();
    if (GetParam()) settings["response"] = {{"type", "http"}};
    Configure(directory.Path(), Inbound(reservation.port, "vless", UserA),
        {{"protocol", "blackhole"}, {"settings", std::move(settings)}}, 2);
    auto child = Start(directory.Path());
    child->WaitForServerStart();
    auto socket = Socket::Connect(reservation.port);
    socket.Write(VlessRequest(backend.Port(),
        "GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n", 1, "127.0.0.1", UserA));
    if (GetParam()) {
        EXPECT_EQ(socket.ReadExact(2), std::string("\0\0", 2));
        std::string response;
        const auto deadline = std::chrono::steady_clock::now() + 3s;
        while (response.find("\r\n\r\n") == std::string::npos) {
            const auto remaining = deadline - std::chrono::steady_clock::now();
            Require(remaining > std::chrono::steady_clock::duration::zero(),
                "blackhole HTTP response deadline exceeded");
            Require(response.size() < 1024, "oversized blackhole HTTP response");
            auto part = socket.Read(1024 - response.size(),
                std::chrono::ceil<Milliseconds>(remaining));
            Require(!part.empty(), "truncated blackhole HTTP response");
            response += part;
        }
        std::istringstream status_line(response);
        std::string version;
        unsigned status = 0;
        status_line >> version >> status;
        EXPECT_EQ(version, "HTTP/1.1");
        EXPECT_EQ(status, 403u);
        EXPECT_TRUE(response.ends_with("\r\n\r\n"));
    }
    EXPECT_TRUE(ReadClosed(socket));
    EXPECT_EQ(child->Stop(), 0);
    pollfd pending{backend.Fd(), POLLIN, 0};
    EXPECT_EQ(::poll(&pending, 1, 0), 0) << "blackhole request reached its destination";
}
INSTANTIATE_TEST_SUITE_P(ReplyPolicy, BlackholeResponse, testing::Bool());

TEST(ConfigRouting, ValidatesKnownAndIgnoresUnknownInboundRoutingControls) {
    const std::vector<Json> invalid = {{{"outboundTag", "missing"}}, {{"outboundTag", ""}},
        {{"outboundTag", 3}}, {{"routingEnabled", "true"}}};
    const std::vector<Json> unknown = {{{"routing_enabled", true}},
        {{"outbound_tag", "chosen"}}, {{"outbound", "chosen"}}};
    const auto write_config = [](const std::filesystem::path& directory,
                                 uint16_t port, const Json& override) {
        auto inbound = Inbound(port);
        inbound.update({{"routingEnabled", true}, {"outboundTag", "Chosen"}});
        inbound.update(override);
        Configure(directory, inbound, {{"tag", "Chosen"}, {"protocol", "freedom"}});
        inbound["tag"] = "fin-in";
        WriteJson(directory, "inbounds.json", Json::array({inbound}));
        WriteJson(directory, "outbounds.json", Json::array({{{"tag", "Chosen"}, {"protocol", "freedom"}}}));
        WriteJson(directory, "routing.json", {{"rules", Json::array()}});
    };
    for (const auto& override : invalid) {
        SCOPED_TRACE(override.dump());
        TempDir directory;
        auto reservation = Socket::ReserveTcp();
        write_config(directory.Path(), reservation.Port(), override);
        auto child = Start(directory.Path());
        EXPECT_EQ(child->Wait(), 1) << ReadFile(child->LogPath());
    }
    for (const auto& override : unknown) {
        SCOPED_TRACE(override.dump());
        TempDir directory;
        auto reservation = Socket::ReserveTcp();
        write_config(directory.Path(), reservation.Port(), override);
        auto child = Start(directory.Path());
        child->WaitForServerStart();
        EXPECT_EQ(child->Stop(), 0);
    }
}
} // namespace
} // namespace cnode::e2e::config_panel
