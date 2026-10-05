#include "controller_impl.hpp"

#include "acppnode/app/traffic_types.hpp"
#include "acppnode/runtime/runtime.hpp"
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
    const auto snapshot = co_await runtime_.GetTraffic(tag);
    std::vector<api::UserTraffic> result;
    result.reserve(snapshot.size());
    for (const auto& [uid, traffic] : snapshot) {
        if (traffic.upload != 0 || traffic.download != 0)
            result.push_back(api::UserTraffic{.UID = uid, .Email = {}, .Upload = static_cast<int64_t>(traffic.upload),
                .Download = static_cast<int64_t>(traffic.download)});
    }
    co_return result;
}

net::awaitable<controller::OnlineSnapshot>
Controller::Impl::GetOnlineSnapshot(const std::string& tag) {
    auto devices = co_await runtime_.GetOnlineDevices(tag);
    co_return controller::BuildOnlineSnapshot(std::move(devices));
}

net::awaitable<std::vector<api::DetectResult>>
Controller::Impl::GetDetectResult(const std::string& tag) {
    co_return co_await runtime_.GetDetectResults(tag);
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
