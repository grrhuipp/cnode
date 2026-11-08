#include "config_panel_common.hpp"

namespace cnode::e2e::config_panel {
namespace {
class IntegrityPanel {
public:
    explicit IntegrityPanel(uint16_t node) : node_(node), server_([this](Socket socket) { Serve(socket); }) {}
    uint16_t Port() const { return server_.Port(); }
    void Join() { server_.Join(); }
    void Mode(std::string mode) { std::lock_guard lock(mutex_); mode_ = std::move(mode); }
    void Rules(std::string rules) { std::lock_guard lock(mutex_); rules_ = std::move(rules); }
    void PushInterval(unsigned interval) { std::lock_guard lock(mutex_); push_interval_ = interval; }
    size_t Posts(bool nonempty = false) {
        std::lock_guard lock(mutex_);
        return nonempty ? std::count_if(posts_.begin(), posts_.end(), [](const Json& post) { return !post.empty(); }) : posts_.size();
    }
    std::vector<std::pair<std::string, std::string>> Gets() { std::lock_guard lock(mutex_); return gets_; }
    void EmptyCycles(Child& child) {
        const auto baseline = Posts();
        Until([&] { if (!child.Running()) throw std::runtime_error("panel child exited"); return Posts() >= baseline + 2; }, 12s);
    }
private:
    void Serve(Socket& socket) {
        const auto request = ReadHttp(socket);
        if (request.method == "GET") {
            if (request.path.find("/config?") == std::string::npos) {
                Reply(socket, 200, Json({{"users", Json::array({{{"id", 1}, {"uuid", UserA}}})}}).dump(), "users"); return;
            }
            std::string phase;
            unsigned interval;
            {
                std::lock_guard lock(mutex_);
                phase = rules_; interval = push_interval_;
                const auto validator = request.headers.find("if-none-match");
                gets_.emplace_back(phase, validator == request.headers.end() ? "" : validator->second);
            }
            Json routes = Json::array();
            if (phase == "blocked") routes.push_back({{"action", "block"}, {"match", {R"(127\.0\.0\.1)"}}});
            if (phase == "invalid") {
                routes.push_back({{"action", "block"}, {"match", {R"(127\.0\.0\.2)"}}});
                routes.push_back({{"action", "block"}, {"match", {"["}}});
            }
            Reply(socket, 200, Json({{"server_port", node_}, {"network", "tcp"}, {"tls", 0}, {"routes", routes},
                {"base_config", {{"pull_interval", 1}, {"push_interval", interval}}}}).dump(), "rules-" + phase);
            return;
        }
        if (request.path.find("/push?") == std::string::npos) { Reply(socket, 200, R"({"data":true})"); return; }
        const auto data = Json::parse(request.body);
        std::string mode;
        { std::lock_guard lock(mutex_); mode = mode_; posts_.push_back(data); }
        if (data.empty() || mode == "ok") Reply(socket, 200, R"({"data":true})");
        else if (mode == "non2xx") Reply(socket, 503, R"({"message":"partial application is possible"})");
        else if (mode == "truncated") socket.Write("HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{");
        else if (mode == "kill") std::this_thread::sleep_for(4s);
        // lost: accept the full request and close without any response.
    }
    uint16_t node_;
    std::mutex mutex_;
    std::string mode_ = "ok", rules_ = "none";
    unsigned push_interval_ = 1;
    std::vector<Json> posts_;
    std::vector<std::pair<std::string, std::string>> gets_;
    LoopServer server_;
};
std::vector<std::filesystem::path> Records(const std::filesystem::path& root, std::string_view state) {
    std::vector<std::filesystem::path> result;
    const auto journal = root / "traffic-journal";
    if (!std::filesystem::exists(journal)) return result;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(journal))
        if (entry.is_regular_file() && entry.path().extension() == "." + std::string(state)) result.push_back(entry.path());
    std::sort(result.begin(), result.end());
    return result;
}
auto SnapshotUnknown(const std::filesystem::path& root) {
    std::vector<std::pair<std::string, std::string>> result;
    for (const auto& path : Records(root, "unknown")) result.emplace_back(path.filename().string(), ReadFile(path));
    return result;
}
void WaitEcho(Child& child, uint16_t node, uint16_t echo, std::string_view host = "127.0.0.1",
              std::string_view inbound_address = "127.0.0.1") {
    Until([&] {
        if (!child.Running()) throw std::runtime_error("panel child exited");
        try { return Echo(node, echo, UserA, host, inbound_address); }
        catch (const std::system_error& error) {
            if (error.code() == std::errc::connection_refused) return false;
            throw;
        }
    }, 12s);
}
class AccountingFault : public testing::TestWithParam<std::string> {};
TEST_P(AccountingFault, QuarantinesAmbiguousRequestsAcrossRestartUntilExplicitReconciliation) {
    const auto mode = GetParam();
    TempDir directory;
    auto reservation = Socket::Listen();
    const auto node = reservation.Port();
    LoopServer echo(EchoPeer, "0.0.0.0");
    IntegrityPanel panel(node);
    panel.Mode(mode);
    PanelConfig(directory.Path(), panel.Port(), "integrity");
    reservation.Close();
    auto child = Start(directory.Path());
    WaitEcho(*child, node, echo.Port());
    Until([&] { return panel.Posts(true) != 0; }, 12s);
    Until([&] { return !Records(directory.Path(), "unknown").empty(); }, 12s);
    if (mode == "kill") { child->Signal(SIGKILL); EXPECT_NE(child->Wait(), 0); }
    else {
        const auto count = panel.Posts(true);
        panel.EmptyCycles(*child);
        EXPECT_EQ(panel.Posts(true), count) << "ambiguous additive request was retried";
        EXPECT_EQ(child->Stop(10s), 0);
    }
    const auto unknown = SnapshotUnknown(directory.Path());
    ASSERT_FALSE(unknown.empty());
    for (const auto& path : Records(directory.Path(), "unknown")) {
        EXPECT_EQ(std::filesystem::status(path).permissions() & std::filesystem::perms::mask,
                  std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        EXPECT_EQ(std::filesystem::status(path.parent_path()).permissions() & std::filesystem::perms::mask,
                  std::filesystem::perms::owner_all);
        EXPECT_EQ(ReadFile(path).find("fixture-secret"), std::string::npos);
    }
    panel.Mode("ok");
    auto count = panel.Posts(true);
    child = Start(directory.Path());
    panel.EmptyCycles(*child);
    EXPECT_EQ(panel.Posts(true), count) << "restart retransmitted unknown traffic";
    EXPECT_EQ(SnapshotUnknown(directory.Path()), unknown);
    EXPECT_EQ(child->Stop(10s), 0);
    const auto path = Records(directory.Path(), "unknown").front();
    {
        Child list({CNODE_TEST_JOURNAL_BINARY, path.parent_path().string(), "list"}, directory.Path() / "journal-list.log");
        EXPECT_EQ(list.Wait(), 0);
    }
    const auto decision = mode == "non2xx" ? "confirmed-not-applied" : "confirmed-applied";
    {
        Child resolve({CNODE_TEST_JOURNAL_BINARY, path.parent_path().string(), "resolve", path.filename().string(),
            "--decision", decision, "--evidence", "fixture operator ledger check"}, directory.Path() / "journal-resolve.log");
        EXPECT_EQ(resolve.Wait(), 0) << ReadFile(resolve.LogPath());
    }
    EXPECT_FALSE(std::filesystem::exists(path));
    if (mode == "non2xx") {
        auto ready = path;
        ready.replace_extension(".ready");
        EXPECT_TRUE(std::filesystem::exists(ready));
        count = panel.Posts(true);
        child = Start(directory.Path());
        Until([&] { return panel.Posts(true) >= count + 1; }, 12s);
        panel.EmptyCycles(*child);
        EXPECT_EQ(panel.Posts(true), count + 1) << "explicit replay was repeated";
        EXPECT_FALSE(std::filesystem::exists(ready));
        EXPECT_FALSE(std::filesystem::exists(path));
        EXPECT_EQ(child->Stop(10s), 0);
    }
    panel.Join();
    echo.Join();
}
INSTANTIATE_TEST_SUITE_P(HttpAmbiguity, AccountingFault, testing::Values("non2xx", "truncated", "lost", "kill"));

TEST(PanelIntegrity, GracefulShutdownPersistsUnsampledCountersAndReplaysExactlyOnce) {
    TempDir directory;
    auto reservation = Socket::Listen();
    const auto node = reservation.Port();
    LoopServer echo(EchoPeer);
    IntegrityPanel panel(node);
    panel.PushInterval(3600);
    PanelConfig(directory.Path(), panel.Port(), "integrity");
    reservation.Close();
    auto child = Start(directory.Path());
    WaitEcho(*child, node, echo.Port());
    EXPECT_EQ(child->Stop(10s), 0);
    EXPECT_FALSE(Records(directory.Path(), "ready").empty());
    EXPECT_EQ(panel.Posts(true), 0u);
    panel.PushInterval(1);
    child = Start(directory.Path());
    Until([&] { return panel.Posts(true) != 0; }, 12s);
    Until([&] { return Records(directory.Path(), "ready").empty() && Records(directory.Path(), "unknown").empty(); }, 12s);
    const auto count = panel.Posts(true);
    panel.EmptyCycles(*child);
    EXPECT_EQ(panel.Posts(true), count);
    EXPECT_EQ(child->Stop(10s), 0);
    panel.Join();
    echo.Join();
}

TEST(PanelIntegrity, InvalidRuleCandidateNeverAdmitsOrPartiallyReplacesCommittedRules) {
    TempDir directory;
    auto reservation = ReserveRuntimePort();
    const auto node = reservation.tcp.Port();
    LoopServer echo(EchoPeer, "0.0.0.0");
    IntegrityPanel panel(node);
    panel.Rules("invalid");
    PanelConfig(directory.Path(), panel.Port(), "integrity");
    auto config = Json::parse(ReadFile(directory.Path() / "config.json"));
    config["panels"][0]["listenIP"] = reservation.address;
    WriteJson(directory.Path(), "config.json", config);
    reservation.tcp.Close();
    reservation.udp.Close();
    auto child = Start(directory.Path());
    // A rejected initial candidate cannot publish its one-second pull interval;
    // without committed state the controller retains the 60-second default.
    // Wait for completed rejection, not three requests or an arbitrary sleep.
    Until([&] {
        if (!child->Running()) throw std::runtime_error("panel child exited");
        return ReadFile(child->LogPath()).find(
            "Panel sync unavailable: operation=pull reason=Invalid block route detect rule 1 (match 0):") !=
            std::string::npos;
    }, 12s);
    const auto initial_requests = panel.Gets();
    ASSERT_FALSE(initial_requests.empty());
    for (const auto& [phase, validator] : initial_requests) {
        EXPECT_EQ(phase, "invalid");
        EXPECT_TRUE(validator.empty()) << "invalid initial rules committed a validator";
    }
    SCOPED_TRACE("default loopback port remains owned by this fixture, not the child");
    EXPECT_TRUE(Listening(node)) << "the unrelated default-address listener must remain live";
    EXPECT_FALSE(Listening(node, reservation.address)) << "invalid initial rules admitted a listener";
    EXPECT_EQ(child->Stop(10s), 0);
    panel.Rules("blocked");
    child = Start(directory.Path(), "committed.log");
    WaitEcho(*child, node, echo.Port(), "127.0.0.2", reservation.address);
    EXPECT_FALSE(Echo(node, echo.Port(), UserA, "127.0.0.1", reservation.address));
    const auto baseline = panel.Gets().size();
    panel.Rules("invalid");
    Until([&] { return panel.Gets().size() >= baseline + 3; }, 12s);
    EXPECT_FALSE(Echo(node, echo.Port(), UserA, "127.0.0.1", reservation.address));
    EXPECT_TRUE(Echo(node, echo.Port(), UserA, "127.0.0.2", reservation.address));
    const auto requests = panel.Gets();
    size_t invalid = 0;
    for (size_t i = baseline; i < requests.size(); ++i)
        if (requests[i].first == "invalid") { ++invalid; EXPECT_EQ(requests[i].second, "rules-blocked"); }
    EXPECT_GT(invalid, 0u);
    panel.Rules("none");
    WaitEcho(*child, node, echo.Port(), "127.0.0.1", reservation.address);
    EXPECT_TRUE(Echo(node, echo.Port(), UserA, "127.0.0.2", reservation.address))
        << "valid recovery retained a prefix from the invalid candidate";
    EXPECT_EQ(child->Stop(10s), 0);
    EXPECT_FALSE(Listening(node, reservation.address));
    EXPECT_TRUE(Listening(node));
    panel.Join();
    echo.Join();
}
} // namespace
} // namespace cnode::e2e::config_panel
