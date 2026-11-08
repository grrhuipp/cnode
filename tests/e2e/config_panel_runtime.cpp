#include "config_panel_common.hpp"
#include "../panel_http_fixture.hpp"

#include <ctime>
#include <iomanip>

namespace cnode::e2e::config_panel {
namespace {
struct PanelConsoleEntry {
    std::string timestamp;
    std::string message;
    std::string name;
    std::string node;

    bool Matches(std::string_view event, std::string_view node_id) const {
        return name == "replay-panel" && node == node_id && message.starts_with(event);
    }
};

PanelConsoleEntry ParsePanelConsole(const std::string& line) {
    PanelConsoleEntry entry;
    std::istringstream fields(line);
    std::string key, value;
    while (std::getline(fields >> std::ws, key, '=') && fields >> std::quoted(value)) {
        if (key == "time") entry.timestamp = value;
        else if (key == "msg") entry.message = value;
        else if (key == "Name") entry.name = value;
        else if (key == "ID") entry.node = value;
    }
    return entry;
}

size_t CountPanelEvents(const std::string& output, std::string_view event, int node,
                       std::string_view detail = {}) {
    const auto node_id = std::to_string(node);
    std::istringstream lines(output);
    std::string line;
    size_t count = 0;
    while (std::getline(lines, line)) {
        const auto entry = ParsePanelConsole(line);
        if (entry.Matches(event, node_id) && entry.message.find(detail) != std::string::npos) ++count;
    }
    return count;
}

bool HasFixedPanelHeartbeat(const std::string& output) {
    std::istringstream lines(output);
    std::string line;
    std::vector<std::time_t> times;
    bool ready = false;
    while (std::getline(lines, line)) {
        const auto entry = ParsePanelConsole(line);
        if (!entry.Matches("Panel status:", "1")) continue;
        std::tm timestamp{};
        std::istringstream prefix(entry.timestamp);
        prefix >> std::get_time(&timestamp, "%Y-%m-%dT%H:%M:%S");
        char sign = 0, colon = 0;
        int hours = 0, minutes = 0;
        prefix >> sign >> hours >> colon >> minutes;
        if (prefix.fail() || (sign != '+' && sign != '-') || colon != ':' ||
            hours > 23 || minutes > 59) return false;
        const int offset = (hours * 60 + minutes) * 60 * (sign == '+' ? 1 : -1);
        times.push_back(timegm(&timestamp) - offset);
        ready = entry.message.find("state=ready inbound=ready") != std::string::npos;
    }
    if (times.size() != 2 || !ready) return false;
    // Log timestamps have second resolution; allow scheduler jitter without
    // accepting two startup messages or a heartbeat tied to the 2-second push.
    const double elapsed = std::difftime(times[1], times[0]);
    std::cout << "panel heartbeat count=" << times.size() << " gap=" << elapsed
              << "s while the same POST remained pending\n";
    return elapsed >= 59 && elapsed <= 62;
}
size_t Events(const std::filesystem::path& path, std::string_view event, int node,
              std::string_view detail = {}) {
    return CountPanelEvents(ReadFile(path), event, node, detail);
}
void WaitEvent(Child& child, std::string_view event, int node, Milliseconds timeout = 12s) {
    Until([&] {
        if (!child.Running()) throw std::runtime_error("runtime child exited");
        return Events(child.LogPath(), event, node) != 0;
    }, timeout);
}

void ShutdownConfig(const std::filesystem::path& root, const std::vector<uint16_t>& ports,
                    uint16_t panel, std::string_view listen) {
    Json config = {{"workers", 2}, {"log", {{"enable", false}, {"logDir", (root / "logs").string()}}},
        {"dns", {{"servers", {"127.0.0.1", "::1"}}, {"timeout", 5}, {"cacheSize", 1000}, {"minTTL", 30}, {"maxTTL", 3600}}},
        {"limits", {{"maxConnections", 0}, {"maxConnectionsPerIP", 100}}},
        {"timeouts", {{"handshake", 60}, {"dial", 10}, {"read", 15}, {"write", 30}, {"idle", 300}, {"uplinkOnly", 5}, {"downlinkOnly", 5}}},
        {"panels", Json::array({{{"name", "shutdown-panel"}, {"type", "V2board"},
            {"apiHost", "http://127.0.0.1:" + std::to_string(panel)}, {"key", "shutdown-key"}, {"nodeIDs", {1}},
            {"nodeType", "vmess"}, {"listenIP", "auto"}, {"sendIP", "auto"}}})}};
    WriteJson(root, "config.json", config);
    Json inbounds = Json::array();
    for (const auto port : ports) inbounds.push_back({{"tag", "shutdown-test-" + std::to_string(inbounds.size())},
        {"protocol", "shadowsocks"}, {"listen", listen}, {"port", port},
        {"settings", {{"method", "aes-128-gcm"}, {"password", "shutdown-fixture"}}},
        {"streamSettings", {{"network", "tcp"}, {"security", "none"}}}});
    WriteJson(root, "inbounds.json", inbounds);
    WriteJson(root, "outbounds.json", Json::array({{{"tag", "explicit-bind"}, {"protocol", "freedom"}, {"sendThrough", "127.0.0.1"}}}));
    WriteJson(root, "routing.json", {{"rules", Json::array({{{"port", "80,443,1000-2000"},
        {"sourcePort", Json::array({53, "1024-65535"})}, {"outboundTag", "direct"}}})}});
}
void ExpectPortsReleased(uint16_t port, std::string_view address) {
    EXPECT_NO_THROW({ auto tcp = Socket::Listen(port, address); auto udp = Socket::BindUdp(port, address); });
}
TEST(RuntimeExit, StartupFailureRollsBackEarlierTcpAndUdpListeners) {
    TempDir directory;
    auto reservation = ReserveRuntimePort();
    auto blocked = Socket::Listen(0, reservation.address);
    auto unavailable_panel = Socket::Listen();
    const auto port = reservation.tcp.Port();
    ShutdownConfig(directory.Path(), {port, blocked.Port()}, unavailable_panel.Port(), reservation.address);
    reservation.tcp.Close();
    reservation.udp.Close();
    auto child = Start(directory.Path());
    EXPECT_EQ(child->Wait(10s), 1) << ReadFile(child->LogPath());
    ExpectPortsReleased(port, reservation.address);
}
TEST(RuntimeExit, SigtermJoinsPendingTcpUdpAndHangingPanelOperations) {
    TempDir directory;
    auto reservation = ReserveRuntimePort();
    auto panel = Socket::Listen();
    const auto port = reservation.tcp.Port();
    ShutdownConfig(directory.Path(), {port}, panel.Port(), reservation.address);
    std::atomic<bool> connected{false}, closed{false};
    PeerThread peer([&] {
        auto socket = panel.Accept(8s);
        ReadHttp(socket);
        connected = true;
        closed = ReadClosed(socket, 10s);
    });
    reservation.tcp.Close();
    reservation.udp.Close();
    auto child = Start(directory.Path());
    child->WaitForLog("server started");
    Until([&] { return connected.load(); }, 8s);
    auto held = Socket::Connect(port, reservation.address);
    held.Write("z");
    auto udp = Socket::BindUdp();
    udp.SendTo("z", port, reservation.address);
    EXPECT_THROW(Socket::BindUdp(port, reservation.address), std::exception);
    EXPECT_EQ(child->Stop(10s), 0);
    peer.Join();
    EXPECT_TRUE(closed.load());
    EXPECT_TRUE(ReadClosed(held, 2s));
    ExpectPortsReleased(port, reservation.address);
}
class TestMode : public testing::TestWithParam<std::string> {};
TEST_P(TestMode, ExplicitAndImplicitListenerOwnership) {
    const auto mode = GetParam();
    TestPortLock lock;
    TempDir directory;
    auto reservation = Socket::Listen();
    const uint16_t port = mode == "port_collision" ? 10086 : reservation.Port();
    WriteJson(directory.Path(), "config.json", {{"workers", 2},
        {"log", {{"enable", false}, {"logDir", (directory.Path() / "logs").string()}}}});
    if (mode != "implicit") {
        auto inbound = Inbound(port, "vmess", "22f6ee21-7dd1-4e62-9cf3-96ca6c7e8b72");
        inbound["tag"] = mode == "tag_collision" ? "test-vmess-10086" : "static-test-owner";
        WriteJson(directory.Path(), "inbounds.json", Json::array({inbound}));
    }
    reservation.Close();
    std::vector<std::string> args{Binary().string(), "--config-dir", directory.Path().string()};
    if (mode != "implicit") args.push_back("--test");
    Child child(args, directory.Path() / "child.log", directory.Path());
    if (mode == "coexist" || mode == "implicit") {
        child.WaitForLog("server started");
        EXPECT_TRUE(Listening(10086));
        if (mode == "coexist") EXPECT_TRUE(Listening(port));
        EXPECT_EQ(child.Stop(10s), 0);
    } else {
        EXPECT_EQ(child.Wait(10s), 1) << ReadFile(child.LogPath());
        EXPECT_FALSE(Listening(port));
    }
}
INSTANTIATE_TEST_SUITE_P(CliContract, TestMode, testing::Values("tag_collision", "port_collision", "coexist", "implicit"));

class PanelRuntime : public testing::TestWithParam<PanelHttpFixture::Mode> {};
TEST_P(PanelRuntime, RequestLifecycleAndListenerOwnership) {
    using Mode = PanelHttpFixture::Mode;
    const auto mode = GetParam();
    TempDir directory;
    PanelHttpFixture fixture(mode);
    ASSERT_TRUE(fixture.WriteConfig(directory.Path()));
    auto child = Start(directory.Path());
    const bool collision = mode == Mode::Collision || mode == Mode::CollisionRace || mode == Mode::StaticCollision;
    if (collision) {
        const auto port = fixture.NodePort();
        int loser = 2;
        if (mode == Mode::StaticCollision) child->WaitForLog("server started workers=2");
        else if (mode == Mode::CollisionRace) {
            int winner = 0;
            Until([&] {
                for (const int node : {1, 2})
                    if (Events(child->LogPath(), "Panel configuration ready:", node)) { winner = node; return true; }
                return false;
            }, 12s);
            loser = winner == 1 ? 2 : 1;
        } else WaitEvent(*child, "Panel configuration ready:", 1);
        EXPECT_TRUE(Listening(port));
        fixture.ReleaseCompanion();
        WaitEvent(*child, "Panel sync unavailable: operation=pull", loser, 8s);
        const auto expected = mode == Mode::StaticCollision ?
            "tag=panel/replay-panel/2/vmess/" + std::to_string(port) + " owner=static-owner port=" + std::to_string(port) :
            "owner=replay-panel/" + std::to_string(3 - loser) + " port=" + std::to_string(port);
        Until([&] { return Logs(directory.Path() / "logs").find(expected) != std::string::npos; }, 1s);
        EXPECT_TRUE(Listening(port));
        EXPECT_EQ(child->Stop(10s), 0);
        EXPECT_EQ(Events(child->LogPath(), "Panel configuration ready:", loser), 0u);
        return;
    }
    if (mode == Mode::Lifecycle) {
        const auto node = fixture.NodePort(), companion = fixture.CompanionPort();
        Until([&] { return Listening(node) && Listening(companion); }, 12s);
        EXPECT_TRUE(fixture.WaitForConfigStatus(503));
        EXPECT_TRUE(Listening(node)); EXPECT_TRUE(Listening(companion));
        EXPECT_TRUE(fixture.WaitForUserRequests(2));
        EXPECT_TRUE(Listening(node)); EXPECT_TRUE(Listening(companion));
        EXPECT_TRUE(fixture.WaitForConfigStatus(404));
        EXPECT_TRUE(Listening(node)); EXPECT_TRUE(Listening(companion));
        EXPECT_TRUE(fixture.WaitForUserRequests(3));
        EXPECT_TRUE(Listening(node)); EXPECT_TRUE(Listening(companion));
        EXPECT_EQ(child->Stop(10s), 0);
        return;
    }
    ASSERT_TRUE(fixture.WaitForPost());
    if (mode == Mode::Timeout) EXPECT_TRUE(fixture.WaitForClientClose());
    if (mode == Mode::Heartbeat) {
        std::this_thread::sleep_for(60s);
        EXPECT_TRUE(fixture.RequestPending());
    } else std::this_thread::sleep_for(500ms);
    EXPECT_EQ(child->Stop(10s), 0);
    if (mode == Mode::Heartbeat) EXPECT_TRUE(fixture.WaitForClientClose());
    const auto posts = fixture.Posts();
    ASSERT_EQ(posts.size(), 1u);
    EXPECT_EQ(posts[0].address, mode == Mode::Fallback ? "127.77.0.3" : "127.77.0.2");
    EXPECT_EQ(posts[0].body, "{}");
    const auto output = ReadFile(child->LogPath());
    if (mode == Mode::Heartbeat) {
        EXPECT_TRUE(HasFixedPanelHeartbeat(output));
        EXPECT_EQ(CountPanelEvents(output, "Panel report:", 1), 0u);
    } else EXPECT_GT(CountPanelEvents(output, "Panel report:", 1,
        mode == Mode::Fallback ? "traffic=ok traffic_users=0" : "traffic=failed traffic_users=0"), 0u);
}
INSTANTIATE_TEST_SUITE_P(HttpAndController, PanelRuntime, testing::Values(
    PanelHttpFixture::Mode::Replay, PanelHttpFixture::Mode::Fallback, PanelHttpFixture::Mode::Timeout,
    PanelHttpFixture::Mode::Heartbeat, PanelHttpFixture::Mode::Lifecycle, PanelHttpFixture::Mode::Collision,
    PanelHttpFixture::Mode::CollisionRace, PanelHttpFixture::Mode::StaticCollision));
} // namespace
} // namespace cnode::e2e::config_panel
