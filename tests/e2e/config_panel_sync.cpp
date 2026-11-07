#include "config_panel_common.hpp"

namespace cnode::e2e::config_panel {
namespace {
class SyncPanel {
public:
    SyncPanel(uint16_t node, uint16_t blocked) : node_(node), blocked_(blocked), server_([this](Socket socket) { Serve(socket); }) {}
    uint16_t Port() const { return server_.Port(); }
    void Join() { server_.Join(); }
    void Enter(std::string phase) { std::lock_guard lock(mutex_); phase_ = std::move(phase); }
    void WaitCycles(Child& child) {
        Until([&] {
            if (!child.Running()) throw std::runtime_error("cnode exited during panel sync");
            std::lock_guard lock(mutex_);
            return std::count_if(requests_.begin(), requests_.end(), [&](const auto& request) {
                return request.phase == phase_ && request.config;
            }) >= 3;
        }, 12s);
    }
    std::vector<std::string> Headers(std::string_view phase, bool config) {
        std::lock_guard lock(mutex_);
        std::vector<std::string> result;
        for (const auto& request : requests_)
            if (request.phase == phase && request.config == config) result.push_back(request.etag);
        return result;
    }
private:
    void Serve(Socket& socket) {
        const auto request = ReadHttp(socket);
        if (request.method != "GET") { Reply(socket, 200, R"({"data":true})"); return; }
        const bool config = request.path.find("/config?") != std::string::npos;
        const auto found = request.headers.find("if-none-match");
        const std::string etag = found == request.headers.end() ? "" : found->second;
        std::string phase;
        {
            std::lock_guard lock(mutex_);
            if (config) pull_phase_ = phase_;
            phase = pull_phase_;
            requests_.push_back({phase, config, etag});
        }
        if (config) {
            if (phase == "config404" || phase == "config503") {
                Reply(socket, phase == "config404" ? 404 : 503, R"({"message":"panel unavailable"})"); return;
            }
            if (phase == "config-invalid") { Reply(socket, 200, R"({"message":"not a node configuration"})", "invalid-config"); return; }
            if (phase == "invalid-candidate") {
                Reply(socket, 200, Json({{"server_port", node_}, {"network", "invalid-transport"}, {"tls", 0},
                    {"base_config", {{"pull_interval", 1}, {"push_interval", 3600}}}}).dump(), "invalid-candidate-config"); return;
            }
            const auto port = phase == "rejected-update" ? blocked_ : node_;
            const auto validator = "config-" + std::to_string(port);
            if (etag == validator) Reply(socket, 304, "");
            else Reply(socket, 200, Json({{"server_port", std::to_string(port)}, {"network", "TCP"}, {"tls", "0"},
                {"networkSettings", Json::array()}, {"base_config", {{"pull_interval", "1"}, {"push_interval", "3600"}}}}).dump(), validator);
            return;
        }
        if (phase == "user404" || phase == "user500") {
            Reply(socket, phase == "user404" ? 404 : 500, R"({"message":"panel unavailable"})"); return;
        }
        if (phase == "user-timeout") {
            std::this_thread::sleep_for(1300ms);
            // The product intentionally cancels this timed-out HTTP request.
            try { Reply(socket, 200, R"({"users":[]})", "invalid-timeout"); } catch (const std::exception&) {}
            return;
        }
        if (phase == "user-json") { Reply(socket, 200, R"({"users":)", "invalid-json"); return; }
        if (phase == "user-schema") { Reply(socket, 200, R"({"message":"not a user list"})", "invalid-schema"); return; }
        if (phase == "user-credentials") {
            Reply(socket, 200, Json({{"users", Json::array({{{"id", 1}, {"uuid", std::string(100, 'x')}}})}}).dump(), "invalid-credentials"); return;
        }
        if (phase == "unexpected304") { Reply(socket, 304, ""); return; }
        std::string version = "v1";
        std::string_view user = UserA;
        if (phase == "rejected-update" || phase == "invalid-candidate" || phase == "recovered") { version = "v2"; user = UserB; }
        else if (phase == "restored") { version = "v4"; user = UserB; }
        else if (phase == "empty") version = "empty";
        const auto validator = phase == "no-etag" ? "" : "users-" + version;
        if (!validator.empty() && etag == validator) Reply(socket, 304, "");
        else {
            const auto users = phase == "empty" ? Json::array() : Json::array({{{"id", "1"}, {"uuid", user},
                {"speed_limit", nullptr}, {"device_limit", "0"}}});
            Reply(socket, 200, Json({{"users", users}}).dump(), validator);
        }
    }
    struct Request { std::string phase; bool config; std::string etag; };
    uint16_t node_, blocked_;
    std::mutex mutex_;
    std::string phase_ = "ready", pull_phase_ = "ready";
    std::vector<Request> requests_;
    LoopServer server_;
};
void CheckUsers(uint16_t node, uint16_t target, const std::vector<std::string_view>& accepted,
                const std::vector<std::string_view>& rejected) {
    for (int attempt = 0; attempt < 4; ++attempt) {
        for (const auto user : accepted) EXPECT_TRUE(Echo(node, target, user)) << user;
        for (const auto user : rejected) EXPECT_FALSE(Echo(node, target, user)) << user;
    }
}
TEST(PanelUserSync, FailuresPreserveCommittedUsersAndValidatorsThenRevokeAndRecover) {
    TempDir directory;
    auto blocked = Socket::Listen();
    auto reservation = Socket::Listen();
    const auto node = reservation.Port();
    LoopServer echo(EchoPeer);
    SyncPanel panel(node, blocked.Port());
    PanelConfig(directory.Path(), panel.Port(), "user-sync", true);
    reservation.Close();
    auto child = Start(directory.Path());
    panel.WaitCycles(*child);
    CheckUsers(node, echo.Port(), {UserA}, {UserB});
    const auto ready = panel.Headers("ready", false);
    ASSERT_GE(ready.size(), 2u);
    EXPECT_TRUE(ready[0].empty());
    EXPECT_EQ(ready[1], "users-v1");
    for (const auto phase : {"config404", "config503", "config-invalid", "user404", "user500", "user-timeout",
             "user-json", "user-schema", "user-credentials", "unchanged", "invalid-candidate", "rejected-update"}) {
        SCOPED_TRACE(phase);
        panel.Enter(phase);
        panel.WaitCycles(*child);
        CheckUsers(node, echo.Port(), {UserA}, {UserB});
        const auto configs = panel.Headers(phase, true);
        EXPECT_FALSE(configs.empty());
        for (const auto& etag : configs) EXPECT_EQ(etag, "config-" + std::to_string(node));
        if (!std::string_view(phase).starts_with("config")) {
            const auto users = panel.Headers(phase, false);
            EXPECT_FALSE(users.empty());
            for (const auto& etag : users) EXPECT_EQ(etag, "users-v1");
        }
    }
    struct Transition { const char* phase; std::vector<std::string_view> accepted, rejected; const char* previous; };
    const std::vector<Transition> transitions = {
        {"recovered", {UserB}, {UserA}, "users-v1"}, {"no-etag", {UserA}, {UserB}, "users-v2"},
        {"unexpected304", {UserA}, {UserB}, ""}, {"empty", {}, {UserA, UserB}, ""},
        {"restored", {UserB}, {UserA}, "users-empty"}};
    for (const auto& transition : transitions) {
        SCOPED_TRACE(transition.phase);
        panel.Enter(transition.phase);
        panel.WaitCycles(*child);
        CheckUsers(node, echo.Port(), transition.accepted, transition.rejected);
        const auto headers = panel.Headers(transition.phase, false);
        ASSERT_FALSE(headers.empty());
        EXPECT_EQ(headers.front(), transition.previous);
    }
    EXPECT_EQ(child->Stop(), 0);
    panel.Join();
    echo.Join();
}
} // namespace
} // namespace cnode::e2e::config_panel
