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
    if (*value.sidecar) {
        std::string content = ExpandFixture(value.content);
        // Preserve raw duplicate keys and malformed JSON. Only replace the old
        // fixture's otherwise-valid listener port tokens, never invalid ports.
        std::vector<Socket> reservations;
        if (std::string_view(value.sidecar) == "inbounds.json") {
            const std::regex port(R"("port":(12[0-9]{3}|43[0-9]{3})([,}]))");
            std::map<std::string, uint16_t> replacements;
            std::string relocated;
            std::smatch match;
            while (std::regex_search(content, match, port)) {
                const auto old = match[1].str();
                if (!replacements.contains(old)) {
                    reservations.push_back(Socket::Listen());
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
        child->WaitForLog("server started");
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
    auto default_reservation = Socket::Listen();
    auto forced_reservation = Socket::Listen();
    auto routed_reservation = Socket::Listen();
    const auto direct_port = default_reservation.Port(), forced_port = forced_reservation.Port(), routed_port = routed_reservation.Port();
    auto direct = Inbound(direct_port, "vless", UserA);
    direct["tag"] = "default-direct";
    auto forced = Inbound(forced_port, "vless", UserA);
    forced.update({{"tag", "forced"}, {"routingEnabled", true}, {"outboundTag", "Chosen"}});
    auto routed = Inbound(routed_port, "vless", UserA);
    routed.update({{"tag", "routed"}, {"routingEnabled", true}});
    const bool mixed = GetParam();
    std::map<std::string, Json> files = {
        {"config.json", {{"workers", 1}, {"log", {{"enable", mixed}, {"logDir", (directory.Path() / "CaseSensitiveLogs").string()}}}}},
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
    default_reservation.Close(); forced_reservation.Close(); routed_reservation.Close();
    Child child({Binary().string(), mixed ? "--config-file" : "--config-dir",
                 mixed ? (directory.Path() / "config.json").string() : directory.Path().string()}, directory.Path() / "child.log", directory.Path());
    child.WaitForLog("server started");
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

TEST(ConfigRouting, RejectsInvalidInboundRoutingControls) {
    const std::vector<Json> overrides = {{{"outboundTag", "missing"}}, {{"outboundTag", ""}},
        {{"outboundTag", 3}}, {{"routingEnabled", "true"}}, {{"routing_enabled", true}},
        {{"outbound_tag", "chosen"}}, {{"outbound", "chosen"}}};
    for (const auto& override : overrides) {
        SCOPED_TRACE(override.dump());
        TempDir directory;
        auto reservation = Socket::Listen();
        auto inbound = Inbound(reservation.Port());
        inbound.update({{"routingEnabled", true}, {"outboundTag", "Chosen"}});
        inbound.update(override);
        Configure(directory.Path(), inbound, {{"tag", "Chosen"}, {"protocol", "freedom"}});
        // Keep the candidate's controls intact instead of Configure's routing defaults.
        inbound["tag"] = "fin-in";
        WriteJson(directory.Path(), "inbounds.json", Json::array({inbound}));
        WriteJson(directory.Path(), "outbounds.json", Json::array({{{"tag", "Chosen"}, {"protocol", "freedom"}}}));
        WriteJson(directory.Path(), "routing.json", {{"rules", Json::array()}});
        reservation.Close();
        auto child = Start(directory.Path());
        EXPECT_EQ(child->Wait(), 1) << ReadFile(child->LogPath());
    }
}
} // namespace
} // namespace cnode::e2e::config_panel
