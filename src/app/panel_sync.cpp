#include "acppnode/app/panel_sync.hpp"

#include "acppnode/app/worker.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/panel/v2board_panel.hpp"

#include <algorithm>
#include <chrono>
#include <unordered_map>
#include <unordered_set>

namespace acpp {

PanelSyncManager::PanelSyncManager(net::io_context& io_context,
                                   std::vector<std::unique_ptr<Worker>>& workers,
                                   std::shared_ptr<ConnectionLimiter> limiter)
    : io_context_(io_context)
    , workers_(workers)
    , limiter_(std::move(limiter)) {}

void PanelSyncManager::AddPanel(std::unique_ptr<IPanel> panel,
                                const PanelConfig& panel_config) {
    auto* p = panel.get();
    panels_.push_back(std::move(panel));
    panel_configs_[p] = panel_config;
    for (int nid : panel_config.node_ids) {
        panel_nodes_.push_back({p, nid});
    }
}

void PanelSyncManager::Start() {
    running_ = true;
    cobalt::spawn(io_context_.get_executor(), SyncLoop(), net::detached);
}

void PanelSyncManager::Stop() {
    running_ = false;
}

std::vector<PanelSyncManager::NodeStatsInfo> PanelSyncManager::GetNodeStats() const {
    std::vector<NodeStatsInfo> result;
    result.reserve(node_configs_.size());
    for (const auto& [key, cfg] : node_configs_) {
        NodeStatsInfo info;
        info.panel_name  = key.first->Name();
        info.node_id     = key.second;
        info.network     = cfg.network;
        info.port        = cfg.port;
        std::string ukey = naming::BuildPanelNodeStatsKey(info.panel_name, info.node_id);
        if (auto it = node_stats_.find(ukey); it != node_stats_.end()) {
            info.total_users  = it->second.user_count;
            info.online_users = it->second.online_count;
            info.bytes_up     = it->second.bytes_up;
            info.bytes_down   = it->second.bytes_down;
        }
        result.push_back(info);
    }
    return result;
}

cobalt::task<void> PanelSyncManager::SyncLoop() {
    co_await DoSync();

    while (running_) {
        net::steady_timer timer(io_context_);
        timer.expires_after(std::chrono::seconds(defaults::kPanelPullInterval));
        (void)co_await timer.async_wait(net::as_tuple(cobalt::use_op));
        if (!running_) break;
        co_await DoSync();
    }
}

cobalt::task<void> PanelSyncManager::DoSync() {
    if (panel_nodes_.empty()) {
        co_return;
    }

    const size_t batch_size = std::min(
        panel_nodes_.size(),
        std::max<size_t>(workers_.size() * 2, 1));

    for (size_t offset = 0; offset < panel_nodes_.size(); offset += batch_size) {
        std::vector<cobalt::task<void>> tasks;
        tasks.reserve(std::min(batch_size, panel_nodes_.size() - offset));

        const size_t end = std::min(panel_nodes_.size(), offset + batch_size);
        for (size_t i = offset; i < end; ++i) {
            const auto& [panel, node_id] = panel_nodes_[i];
            tasks.push_back(SyncNode(panel, node_id));
        }

        co_await cobalt::join(tasks);
    }
}

cobalt::task<std::vector<TrafficData>>
PanelSyncManager::CollectTraffic(const std::string& tag) {
    using TrafficMap = std::unordered_map<int64_t, Worker::UserTraffic>;
    std::vector<TrafficMap> per_worker(workers_.size());

    std::vector<cobalt::task<void>> tasks;
    tasks.reserve(workers_.size());
    for (size_t i = 0; i < workers_.size(); ++i) {
        tasks.push_back(
            [](Worker* w, const std::string& t, TrafficMap& out) -> cobalt::task<void> {
                out = co_await cobalt::spawn(
                    w->GetExecutor(), w->CollectTrafficTask(t), cobalt::use_op);
            }(workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await cobalt::join(tasks);

    size_t merged_hint = 0;
    for (const auto& traffic : per_worker) {
        merged_hint += traffic.size();
    }

    std::unordered_map<int64_t, TrafficData> merged;
    merged.reserve(merged_hint);
    for (const auto& traffic : per_worker) {
        for (const auto& [uid, t] : traffic) {
            auto& m   = merged[uid];
            m.user_id  = uid;
            m.upload  += t.upload;
            m.download += t.download;
        }
    }

    std::vector<TrafficData> result;
    result.reserve(merged.size());
    for (const auto& [uid, td] : merged) {
        if (td.upload > 0 || td.download > 0) {
            result.push_back(td);
        }
    }
    co_return result;
}

cobalt::task<std::vector<int64_t>>
PanelSyncManager::CollectOnlineUsers(const std::string& tag,
                                      const std::string& /*protocol*/) {
    std::vector<std::vector<int64_t>> per_worker(workers_.size());

    std::vector<cobalt::task<void>> tasks;
    tasks.reserve(workers_.size());
    for (size_t i = 0; i < workers_.size(); ++i) {
        tasks.push_back(
            [](Worker* w, const std::string& t,
               std::vector<int64_t>& out) -> cobalt::task<void> {
                out = co_await cobalt::spawn(
                    w->GetExecutor(), w->CollectOnlineUsersTask(t),
                    cobalt::use_op);
            }(workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await cobalt::join(tasks);

    size_t total_online = 0;
    for (const auto& online : per_worker) {
        total_online += online.size();
    }

    std::unordered_set<int64_t> users;
    users.reserve(total_online);
    for (const auto& online : per_worker) {
        users.insert(online.begin(), online.end());
    }
    co_return std::vector<int64_t>(users.begin(), users.end());
}

}  // namespace acpp
