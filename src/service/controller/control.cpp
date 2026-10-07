#include "controller_impl.hpp"
#include "../../common/awaitable_batch.hpp"

#include "acppnode/app/traffic_types.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/common/serverstatus.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace acpp {

net::awaitable<std::vector<api::UserTraffic>>
Controller::Impl::getTraffic(const std::string& tag) {
    using TrafficSnapshot = Worker::UserTrafficSnapshot;
    std::vector<TrafficSnapshot> per_worker(workers_.size());

    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers_.size());
    for (size_t i = 0; i < workers_.size(); ++i) {
        tasks.push_back(
            [](Worker* w, const std::string& t,
               TrafficSnapshot& out) -> net::awaitable<void> {
                out = co_await w->PostTask(w->GetTrafficTask(t));
            }(workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await RunAwaitableBatch(
        io_context_.get_executor(), std::move(tasks));

    size_t merged_hint = 0;
    for (const auto& traffic : per_worker) {
        merged_hint += traffic.size();
    }

    std::unordered_map<int64_t, api::UserTraffic> merged;
    merged.reserve(merged_hint);
    for (const auto& traffic : per_worker) {
        for (const auto& [uid, t] : traffic) {
            auto& m   = merged[uid];
            m.UID      = uid;
            m.Upload  += t.upload;
            m.Download += t.download;
        }
    }

    std::vector<api::UserTraffic> result;
    result.reserve(merged.size());
    for (const auto& [uid, td] : merged) {
        if (td.Upload > 0 || td.Download > 0) {
            result.push_back(td);
        }
    }
    co_return result;
}

net::awaitable<controller::OnlineSnapshot>
Controller::Impl::GetOnlineSnapshot(const std::string& tag) {
    std::vector<std::vector<OnlineDevice>> per_worker(workers_.size());

    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers_.size());
    for (size_t i = 0; i < workers_.size(); ++i) {
        tasks.push_back(
            [](Worker* w, const std::string& t,
               std::vector<OnlineDevice>& out) -> net::awaitable<void> {
                out = co_await w->PostTask(w->GetOnlineDeviceTask(t));
            }(workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await RunAwaitableBatch(
        io_context_.get_executor(), std::move(tasks));

    size_t total_online = 0;
    for (const auto& online : per_worker) {
        total_online += online.size();
    }

    std::vector<OnlineDevice> devices;
    devices.reserve(total_online);
    for (const auto& online : per_worker) {
        devices.insert(devices.end(), online.begin(), online.end());
    }
    co_return controller::BuildOnlineSnapshot(std::move(devices));
}

net::awaitable<std::vector<api::DetectResult>>
Controller::Impl::GetDetectResult(const std::string& tag) {
    std::vector<std::vector<api::DetectResult>> per_worker(workers_.size());

    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers_.size());
    for (size_t i = 0; i < workers_.size(); ++i) {
        tasks.push_back(
            [](Worker* w, const std::string& t,
               std::vector<api::DetectResult>& out) -> net::awaitable<void> {
                out = co_await w->PostTask(w->GetDetectResultTask(t));
            }(workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await RunAwaitableBatch(
        io_context_.get_executor(), std::move(tasks));

    size_t total = 0;
    for (const auto& results : per_worker) {
        total += results.size();
    }

    std::vector<api::DetectResult> merged;
    merged.reserve(total);
    for (const auto& results : per_worker) {
        for (const auto& result : results) {
            const auto duplicate = std::find_if(
                merged.begin(), merged.end(),
                [&](const api::DetectResult& current) {
                    return current.UID == result.UID &&
                           current.RuleID == result.RuleID;
                });
            if (duplicate == merged.end()) {
                merged.push_back(result);
            }
        }
    }
    co_return merged;
}

net::awaitable<void> Controller::Impl::userInfoMonitor(PanelRuntime& panel,
                                                 const std::string& tag) {
    const int node_id = panel.config.NodeIDs.Front();
    const auto& panel_name = panel.config.Name;

    bool node_status_ok = false;
    try {
        api::NodeStatus node_status = serverstatus::GetSystemInfo();
        node_status_ok = co_await panel.client->ReportNodeStatus(node_status);
        if (!node_status_ok) {
            LOG_WARN("Panel {}/{} report: node failed", panel_name, node_id);
        }
    } catch (const std::exception& e) {
        LOG_WARN("Panel {}/{} report: node failed | {}",
                 panel_name, node_id, e.what());
    }

    auto traffic_data = co_await getTraffic(tag);
    bool traffic_ok = false;
    {
        auto& ns = panel.stats;
        // Match V2Board/v2node: node online users are the unique UIDs that
        // produced traffic during this push interval.
        ns.online_count = traffic_data.size();
        for (const auto& td : traffic_data) {
            ns.bytes_up   += td.Upload;
            ns.bytes_down += td.Download;
        }
    }

    auto online = co_await GetOnlineSnapshot(tag);

    try {
        // An empty push clears the panel's previous online-user count.
        traffic_ok = co_await panel.client->ReportUserTraffic(traffic_data);
        if (traffic_ok) {
            LOG_DEBUG("Panel {}/{} report: traffic ok | users {}",
                      panel_name, node_id, traffic_data.size());
        }
    } catch (const std::exception& e) {
        LOG_WARN("Panel {}/{} report: traffic failed | {}",
                 panel_name, node_id, e.what());
    }

    bool online_ok = false;
    try {
        online_ok = co_await panel.client->ReportNodeOnlineUsers(online.entries);
    } catch (const std::exception& e) {
        LOG_WARN("Panel {}/{} report: online failed | {}",
                 panel_name, node_id, e.what());
    }

    auto detect_results = co_await GetDetectResult(tag);
    const bool illegal_attempted = !detect_results.empty();
    bool illegal_ok = !illegal_attempted;
    if (!detect_results.empty()) {
        try {
            illegal_ok = co_await panel.client->ReportIllegal(detect_results);
            if (illegal_ok) {
                LOG_DEBUG("Panel {}/{} report: illegal ok | events {}",
                          panel_name, node_id, detect_results.size());
            }
        } catch (const std::exception& e) {
            LOG_WARN("Panel {}/{} report: illegal failed | {}",
                     panel_name, node_id, e.what());
        }
    }
    const auto result_text = [](bool attempted, bool ok) -> std::string_view {
        if (!attempted) {
            return "idle";
        }
        return ok ? "ok" : "failed";
    };
    const bool report_ok = node_status_ok && traffic_ok && online_ok && illegal_ok;
    LOG_CONSOLE(
        "Panel {}/{} report: {} | node {} | traffic {}/{} | online {}/{} | "
        "devices {} | illegal {}/{}",
        panel_name,
        node_id,
        report_ok ? "ok" : "degraded",
        node_status_ok ? "ok" : "failed",
        traffic_ok ? "ok" : "failed",
        traffic_data.size(),
        online_ok ? "ok" : "failed",
        online.user_count,
        online.entries.size(),
        result_text(illegal_attempted, illegal_ok),
        detect_results.size());
    co_return;
}

}  // namespace acpp
