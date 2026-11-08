#pragma once

#include "service/controller/controller.hpp"

#include "api/api.hpp"
#include "app/prepared_inbound.hpp"
#include "infra/panel_config.hpp"
#include "core/naming.hpp"
#include "online_snapshot.hpp"
#include "node_state.hpp"
#include "node_transaction.hpp"
#include "traffic_journal.hpp"
#include "journal_executor.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>


namespace monitor_detail {
class MonitorLoop;
}

struct Controller::Impl : std::enable_shared_from_this<Controller::Impl> {
    struct PanelRuntime;
    Impl(net::io_context& io_context,
         const std::vector<std::unique_ptr<Worker>>& workers);

    void AddPanel(std::unique_ptr<api::API> panel, const PanelConfig& panel_config);
    void Start();
    void RequestStop() noexcept;
    net::awaitable<void> AsyncJoin();
    net::awaitable<void> FlushTraffic();
    void ThrowIfStopping() const;

    [[nodiscard]] std::vector<Controller::NodeStatsInfo> GetNodeStats() const;

    net::awaitable<void> panelSyncLoop(PanelRuntime& panel);
    net::awaitable<void> panelStatusLoop(const PanelRuntime& panel) const;
    net::awaitable<void> nodeInfoMonitor(PanelRuntime& panel);
    void logPanelStatus(const PanelRuntime& panel) const;
    net::awaitable<void> userInfoMonitor(PanelRuntime& panel,
                                         std::string tag);

    net::awaitable<bool> collectTraffic(PanelRuntime& panel,
                                        bool* appended_out = nullptr);
    net::awaitable<controller::OnlineSnapshot>
    GetOnlineSnapshot(const std::string& tag);

    net::io_context&                       io_context_;
    const std::vector<std::unique_ptr<Worker>>&  workers_;
    bool stopping_ = false;
    controller::NodeMutationGate node_mutations_;
    std::unique_ptr<controller::JournalExecutor> journal_executor_;

    enum class PanelState {
        Connecting,
        Ready,
        Degraded,
        Unavailable,
    };

    struct NodeStats {
        size_t   online_count = 0;
        uint64_t bytes_up     = 0;
        uint64_t bytes_down   = 0;
    };
    struct PanelRuntime {
        PanelRuntime(std::unique_ptr<api::API> api, const PanelConfig& source,
                     controller::NodeMutationGate& gate, net::any_io_executor executor);

        const std::unique_ptr<api::API> client;
        const PanelConfig config;
        const std::string accounting_key;
        PanelState state = PanelState::Connecting;
        controller::NodeState node;
        controller::NodeMutationGate::Participant mutation;
        NodeStats stats;
        std::unique_ptr<controller::TrafficJournal> traffic_journal;
        // Active loops retain Impl, which owns these address-stable entities.
        std::weak_ptr<monitor_detail::MonitorLoop> sync_loop;
        std::weak_ptr<monitor_detail::MonitorLoop> status_loop;
    };
    std::vector<std::unique_ptr<PanelRuntime>> panels_;
};

