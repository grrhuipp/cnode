#pragma once

#include "acppnode/service/controller/controller.hpp"

#include "acppnode/api/api.hpp"
#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/service/controller/config.hpp"
#include "online_snapshot.hpp"
#include "node_state.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

namespace monitor_detail {
class MonitorLoop;
}

struct Controller::Impl : std::enable_shared_from_this<Controller::Impl> {
    struct PanelRuntime;
    Impl(net::io_context& io_context,
         const std::vector<std::unique_ptr<Worker>>& workers,
         const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters);

    void AddPanel(std::unique_ptr<api::API> panel, const PanelConfig& panel_config);
    void Start();

    [[nodiscard]] std::vector<Controller::NodeStatsInfo> GetNodeStats() const;

    net::awaitable<void> panelSyncLoop(PanelRuntime& panel);
    net::awaitable<void> panelStatusLoop(const PanelRuntime& panel) const;
    net::awaitable<void> nodeInfoMonitor(PanelRuntime& panel);
    void logPanelStatus(const PanelRuntime& panel) const;
    net::awaitable<void> userInfoMonitor(PanelRuntime& panel,
                                         const std::string& tag);

    net::awaitable<std::vector<api::UserTraffic>> getTraffic(const std::string& tag);
    net::awaitable<controller::OnlineSnapshot>
    GetOnlineSnapshot(const std::string& tag);
    net::awaitable<std::vector<api::DetectResult>> GetDetectResult(const std::string& tag);

    [[nodiscard]] std::string BuildUserTag(std::string_view tag,
                                           const api::UserInfo& user) const;
    [[nodiscard]] std::optional<proxyman::inbound::UserSet> BuildUsersForInbound(
        std::string_view protocol,
        std::string_view tag,
        const api::NodeInfo& node_config,
        const std::vector<api::UserInfo>& api_users) const;

    net::io_context&                       io_context_;
    const std::vector<std::unique_ptr<Worker>>&  workers_;
    const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters_;

    enum class PanelState {
        Connecting,
        Ready,
        Degraded,
        Missing,
        Unavailable,
    };

    struct NodeStats {
        size_t   online_count = 0;
        uint64_t bytes_up     = 0;
        uint64_t bytes_down   = 0;
    };
    struct PanelRuntime {
        PanelRuntime(std::unique_ptr<api::API> api, const PanelConfig& source);

        const std::unique_ptr<api::API> client;
        const PanelConfig config;
        PanelState state = PanelState::Connecting;
        controller::NodeState node;
        NodeStats stats;
        // Active loops retain Impl, which owns these address-stable entities.
        std::weak_ptr<monitor_detail::MonitorLoop> sync_loop;
        std::weak_ptr<monitor_detail::MonitorLoop> status_loop;
    };
    std::vector<std::unique_ptr<PanelRuntime>> panels_;
};

}  // namespace acpp
