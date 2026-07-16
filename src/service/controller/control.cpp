#include "controller_impl.hpp"
#include "awaitable_batch.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"

#include "inboundbuilder.hpp"
#include "outboundbuilder.hpp"

#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/traffic_types.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/common/serverstatus.hpp"

#include <algorithm>
#include <unordered_map>

namespace acpp {

net::awaitable<void> Controller::Impl::removeInbound(const std::string& tag) {
    for (const auto& worker : workers_) {
        co_await net::co_spawn(
            worker->GetExecutor(),
            worker->UnregisterListenerTask(tag),
            net::use_awaitable);
    }
    registered_tags_.erase(
        std::remove(registered_tags_.begin(), registered_tags_.end(), tag),
        registered_tags_.end());
    co_return;
}

net::awaitable<void> Controller::Impl::removeOutbound(const std::string& tag) {
    for (const auto& worker : workers_) {
        co_await net::co_spawn(
            worker->GetExecutor(),
            worker->RemoveOutboundTask(tag),
            net::use_awaitable);
    }
    co_return;
}

net::awaitable<bool> Controller::Impl::addOutbound(api::API* panel,
                                             const api::NodeInfo& node_config,
                                             const std::string& tag) {
    const auto panel_cfg_it = panel_configs_.find(panel);
    const PanelConfig* panel_cfg = panel_cfg_it != panel_configs_.end()
        ? &panel_cfg_it->second
        : nullptr;

    auto prepared = controller::OutboundBuilder(tag, panel_cfg, node_config);
    if (!prepared) {
        co_return false;
    }
    for (const auto& worker : workers_) {
        const bool added = co_await net::co_spawn(
            worker->GetExecutor(),
            worker->AddOutboundTask(*prepared),
            net::use_awaitable);
        if (!added) {
            co_return false;
        }
    }
    co_return true;
}

net::awaitable<bool> Controller::Impl::addInbound(api::API* panel,
                                            const api::NodeInfo& node_config) {
    const auto client_info = panel->Describe();
    const int node_id = client_info.NodeID;
    const auto panel_cfg_it = panel_configs_.find(panel);
    const std::string panel_name =
        (panel_cfg_it != panel_configs_.end() && !panel_cfg_it->second.Name.empty())
            ? panel_cfg_it->second.Name
            : client_info.APIHost;
    const PanelConfig* panel_cfg = panel_cfg_it != panel_configs_.end()
        ? &panel_cfg_it->second
        : nullptr;

    auto inbound = controller::InboundBuilder(panel_name, panel_cfg, node_config);

    if (!proxyman::inbound::HasProxy(inbound.protocol)) {
        LOG_WARN("Node {}/{}: unsupported inbound protocol '{}'",
                 panel_name, node_id, inbound.protocol);
        co_return false;
    }

    for (const auto& worker : workers_) {
        auto* limiter = limiters_[worker->Id()].get();

        auto receiver = proxyman::inbound::MakeReceiverSettings(
            inbound.tag,
            std::vector<std::string>{inbound.tag, std::string(constants::protocol::kNode)},
            inbound.protocol,
            inbound.stream_settings,
            inbound.sniff,
            limiter,
            inbound.proxy_protocol,
            proxyman::inbound::RoutePolicy::RouteWithFallback(inbound.tag));

        const bool registered = co_await net::co_spawn(
            worker->GetExecutor(),
            worker->RegisterInboundTask(
                inbound.protocol,
                limiter,
                inbound.handler_request,
                std::move(receiver)),
            net::use_awaitable);

        if (!registered) {
            LOG_WARN("Node {}/{}: create inbound handler failed, protocol={}",
                     panel_name, node_id, inbound.protocol);
            co_await removeInbound(inbound.tag);
            co_return false;
        }
    }

    for (const auto& worker : workers_) {
        const bool tcp_bound = co_await net::co_spawn(
            worker->GetExecutor(),
            worker->AddListenerTask(inbound.binding),
            net::use_awaitable);
        if (!tcp_bound) {
            LOG_WARN("Node {}/{}: TCP bind failed, tag={}",
                     panel_name, node_id, inbound.tag);
            co_await removeInbound(inbound.tag);
            co_return false;
        }

        auto* limiter = limiters_[worker->Id()].get();
        const bool udp_bound = co_await net::co_spawn(
            worker->GetExecutor(),
            worker->AddUdpListenerTask(
                inbound.binding,
                inbound.protocol,
                limiter,
                inbound.handler_request),
            net::use_awaitable);
        if (!udp_bound) {
            LOG_WARN("Node {}/{}: UDP bind failed, tag={}",
                     panel_name, node_id, inbound.tag);
            co_await removeInbound(inbound.tag);
            co_return false;
        }
    }

    if (std::find(registered_tags_.begin(), registered_tags_.end(), inbound.tag)
            == registered_tags_.end()) {
        registered_tags_.push_back(inbound.tag);
    }

    LOG_CONSOLE("inbound ready tag={} port={} protocol={} workers={} accept=SO_REUSEPORT",
                inbound.tag, node_config.Port, inbound.protocol, workers_.size());
    co_return true;
}

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
                out = co_await net::co_spawn(
                    w->GetExecutor(), w->GetTrafficTask(t), net::use_awaitable);
            }(workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await controller::RunAwaitableBatch(
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

net::awaitable<std::vector<api::OnlineUser>>
Controller::Impl::GetOnlineDevice(const std::string& tag,
                            const std::string& /*protocol*/) {
    std::vector<std::vector<OnlineDevice>> per_worker(workers_.size());

    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers_.size());
    for (size_t i = 0; i < workers_.size(); ++i) {
        tasks.push_back(
            [](Worker* w, const std::string& t,
               std::vector<OnlineDevice>& out) -> net::awaitable<void> {
                out = co_await net::co_spawn(
                    w->GetExecutor(), w->GetOnlineDeviceTask(t),
                    net::use_awaitable);
            }(workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await controller::RunAwaitableBatch(
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
    std::sort(devices.begin(), devices.end());
    devices.erase(std::unique(devices.begin(), devices.end()), devices.end());

    std::vector<api::OnlineUser> users;
    users.reserve(devices.size());
    for (const auto& device : devices) {
        users.push_back(api::OnlineUser{
            .UID = device.user_id,
            .IP = device.ip,
        });
    }
    co_return users;
}

void Controller::Impl::UpdateRule(const std::string& tag,
                            const std::vector<api::DetectRule>& new_rule_list) {
    for (const auto& worker : workers_) {
        worker->UpdateRuleAsync(tag, new_rule_list);
    }
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
                out = co_await net::co_spawn(
                    w->GetExecutor(), w->GetDetectResultTask(t),
                    net::use_awaitable);
            }(workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await controller::RunAwaitableBatch(
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

net::awaitable<void> Controller::Impl::userInfoMonitor(api::API* panel,
                                                 const std::string& tag,
                                                 const std::string& protocol) {
    const auto client_info = panel->Describe();
    const int node_id = client_info.NodeID;
    const auto panel_cfg_it = panel_configs_.find(panel);
    const std::string panel_name =
        (panel_cfg_it != panel_configs_.end() && !panel_cfg_it->second.Name.empty())
            ? panel_cfg_it->second.Name
            : client_info.APIHost;

    try {
        api::NodeStatus node_status = serverstatus::GetSystemInfo();
        bool ok = co_await panel->ReportNodeStatus(node_status);
        if (!ok) {
            LOG_WARN("Panel {}/{}: ReportNodeStatus failed", panel_name, node_id);
        }
    } catch (const std::exception& e) {
        LOG_WARN("Panel {}/{}: ReportNodeStatus failed: {}",
                 panel_name, node_id, e.what());
    }

    auto traffic_data = co_await getTraffic(tag);
    {
        std::string ukey = naming::BuildPanelNodeStatsKey(panel_name, node_id);
        auto& ns = node_stats_[ukey];
        for (const auto& td : traffic_data) {
            ns.bytes_up   += td.Upload;
            ns.bytes_down += td.Download;
        }
    }

    auto online_users = co_await GetOnlineDevice(tag, protocol);
    {
        std::string ukey = naming::BuildPanelNodeStatsKey(panel_name, node_id);
        node_stats_[ukey].online_count = online_users.size();
    }

    if (!traffic_data.empty()) {
        try {
            bool ok = co_await panel->ReportUserTraffic(traffic_data);
            if (ok) {
                LOG_DEBUG("Panel {}/{}: reported traffic for {} users",
                          panel_name, node_id, traffic_data.size());
            }
        } catch (const std::exception& e) {
            LOG_WARN("Panel {}/{}: ReportUserTraffic failed: {}",
                     panel_name, node_id, e.what());
        }
    }

    if (!online_users.empty()) {
        try {
            co_await panel->ReportNodeOnlineUsers(online_users);
        } catch (const std::exception& e) {
            LOG_WARN("Panel {}/{}: ReportNodeOnlineUsers failed: {}",
                     panel_name, node_id, e.what());
        }
    }

    auto detect_results = co_await GetDetectResult(tag);
    if (!detect_results.empty()) {
        try {
            bool ok = co_await panel->ReportIllegal(detect_results);
            if (ok) {
                LOG_DEBUG("Panel {}/{}: reported {} illegal behaviors",
                          panel_name, node_id, detect_results.size());
            }
        } catch (const std::exception& e) {
            LOG_WARN("Panel {}/{}: ReportIllegal failed: {}",
                     panel_name, node_id, e.what());
        }
    }
    co_return;
}

void Controller::Impl::clearUsers(const std::string& tag, const std::string& protocol) {
    if (!proxyman::inbound::HasProxy(protocol)) {
        return;
    }

    proxyman::inbound::UserStore::ClearUsers(protocol, tag);
}

bool Controller::Impl::applyUserList(
    const std::string& tag,
    const std::string& protocol,
    const api::NodeInfo& node_config,
    const std::vector<api::UserInfo>& api_users) {
    if (!proxyman::inbound::HasProxy(protocol)) {
        LOG_WARN("applyUserList: unsupported protocol '{}'", protocol);
        return false;
    }

    auto user_set = BuildUsersForInbound(protocol, tag, node_config, api_users);
    if (!user_set) {
        LOG_WARN("applyUserList: build users failed for protocol '{}'", protocol);
        return false;
    }
    proxyman::inbound::UserStore::ApplyUsers(protocol, tag, *user_set);
    return true;
}

bool Controller::Impl::syncUserList(
    api::API* panel,
    const std::string& tag,
    const std::string& protocol,
    const api::NodeInfo& node_config,
    const std::vector<api::UserInfo>& api_users) {
    const auto client_info = panel->Describe();
    const int node_id = client_info.NodeID;
    const auto panel_cfg_it = panel_configs_.find(panel);
    const std::string panel_name =
        (panel_cfg_it != panel_configs_.end() && !panel_cfg_it->second.Name.empty())
            ? panel_cfg_it->second.Name
            : client_info.APIHost;

    if (!applyUserList(tag, protocol, node_config, api_users)) {
        return false;
    }
    user_lists_[panel] = api_users;
    std::string stats_key = naming::BuildPanelNodeStatsKey(panel_name, node_id);
    node_stats_[stats_key].user_count = api_users.size();
    return true;
}

}  // namespace acpp
