#pragma once

#include "acppnode/service/controller/controller.hpp"

#include "acppnode/api/api.hpp"
#include "acppnode/app/proxyman/inbound/prepared_config.hpp"
#include "acppnode/service/controller/config.hpp"

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

struct Controller::Impl {
    Impl(net::io_context& io_context,
         std::vector<std::unique_ptr<Worker>>& workers,
         const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters);

    void AddPanel(std::unique_ptr<api::API> panel, const PanelConfig& panel_config);
    void Start();
    void Stop();

    [[nodiscard]] std::vector<Controller::NodeStatsInfo> GetNodeStats() const;

    net::awaitable<void> runPanelMonitors(uint64_t generation);
    net::awaitable<void> panelMonitor(api::API* panel, uint64_t generation);
    net::awaitable<void> nodeInfoMonitor(api::API* panel);
    net::awaitable<void> userInfoMonitor(api::API* panel,
                                         const std::string& tag,
                                         const std::string& protocol);

    net::awaitable<std::vector<api::UserTraffic>> getTraffic(const std::string& tag);
    net::awaitable<std::vector<api::OnlineUser>> GetOnlineDevice(const std::string& tag,
                                                                 const std::string& protocol);
    net::awaitable<void> UpdateRule(
        const std::string& tag,
        const std::vector<api::DetectRule>& new_rule_list);
    net::awaitable<std::vector<api::DetectResult>> GetDetectResult(const std::string& tag);

    net::awaitable<void> removeInbound(const std::string& tag);
    net::awaitable<bool> addInbound(api::API* panel, const api::NodeInfo& node_config);
    net::awaitable<void> removeOutbound(const std::string& tag);
    net::awaitable<bool> addOutbound(api::API* panel,
                                     const api::NodeInfo& node_config,
                                     const std::string& tag);

    void clearUsers(const std::string& tag, const std::string& protocol);

    [[nodiscard]] std::string BuildUserTag(std::string_view tag,
                                           const api::UserInfo& user) const;
    [[nodiscard]] std::optional<proxyman::inbound::UserSet> BuildUsersForInbound(
        std::string_view protocol,
        std::string_view tag,
        const api::NodeInfo& node_config,
        const std::vector<api::UserInfo>& api_users) const;

    net::io_context&                       io_context_;
    std::vector<std::unique_ptr<Worker>>&  workers_;
    const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters_;

    std::vector<std::unique_ptr<api::API>>         panels_;
    std::map<api::API*, PanelConfig>               panel_configs_;
    std::vector<api::API*>                         panel_nodes_;
    struct CommittedNodeState {
        api::NodeInfo config;
        std::vector<api::UserInfo> users;
        std::vector<api::DetectRule> rules;
        bool inbound_started = false;
    };
    std::map<api::API*, CommittedNodeState> committed_nodes_;

    struct NodeStats {
        size_t   user_count   = 0;
        size_t   online_count = 0;
        uint64_t bytes_up     = 0;
        uint64_t bytes_down   = 0;
    };
    std::map<std::string, NodeStats> node_stats_;
    bool running_ = false;
    uint64_t monitor_generation_ = 0;
};

}  // namespace acpp
