#include "controller_impl.hpp"
#include "../../common/awaitable_batch.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"

#include "inboundbuilder.hpp"
#include "outboundbuilder.hpp"

#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/traffic_types.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/access_log_reporter.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/common/serverstatus.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <unordered_map>
#include <vector>

namespace acpp {

namespace {

template <typename WorkerRange, typename TaskFactory>
net::awaitable<void> RunWorkerMutationBatch(
    net::any_io_executor executor,
    WorkerRange& workers,
    TaskFactory task_factory) {
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers.size());
    for (size_t i = 0; i < workers.size(); ++i) {
        tasks.push_back(task_factory(*workers[i], i));
    }
    co_await RunAwaitableBatch(executor, std::move(tasks));
}

struct WorkerBindResult {
    bool tcp = false;
    bool udp = false;
};

}  // namespace

net::awaitable<void> Controller::Impl::removeInbound(const std::string& tag) {
    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [tag](Worker& worker, size_t) {
            return [](Worker* current, std::string current_tag)
                       -> net::awaitable<void> {
                co_await net::co_spawn(
                    current->GetExecutor(),
                    current->UnregisterListenerTask(std::move(current_tag)),
                    net::use_awaitable);
            }(&worker, tag);
        });
}

net::awaitable<void> Controller::Impl::removeOutbound(const std::string& tag) {
    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [tag](Worker& worker, size_t) {
            return [](Worker* current, std::string current_tag)
                       -> net::awaitable<void> {
                co_await net::co_spawn(
                    current->GetExecutor(),
                    current->RemoveOutboundTask(std::move(current_tag)),
                    net::use_awaitable);
            }(&worker, tag);
        });
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
    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [&prepared](Worker& worker, size_t) {
            return [](Worker* current,
                      proxyman::outbound::PreparedOutboundConfig config)
                       -> net::awaitable<void> {
                co_await net::co_spawn(
                    current->GetExecutor(),
                    current->AddOutboundTask(std::move(config)),
                    net::use_awaitable);
            }(&worker, *prepared);
        });
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

    const uint32_t access_source_ref = accesslog::Reporter::Instance().RegisterSource({
        .panel_name = panel_name,
        .panel_api_host = client_info.APIHost,
        .node_type = inbound.protocol,
        .node_id = static_cast<uint64_t>(node_id),
    });
    if (access_source_ref == 0) {
        LOG_ERROR("Node {}/{}: centralized access-log source registration failed api={}",
                  panel_name, node_id, client_info.APIHost);
    }

    std::exception_ptr publish_failure;
    try {
        std::vector<uint8_t> registered(workers_.size(), 0);
        co_await RunWorkerMutationBatch(
            io_context_.get_executor(), workers_,
            [&](Worker& worker, size_t index) {
                auto* limiter = limiters_[worker.Id()].get();
                auto receiver = proxyman::inbound::MakeReceiverSettings(
                    inbound.tag,
                    std::vector<std::string>{
                        inbound.tag, std::string(constants::protocol::kNode)},
                    inbound.protocol,
                    inbound.stream_settings,
                    inbound.sniff,
                    limiter,
                    inbound.proxy_protocol,
                    proxyman::inbound::RoutePolicy::RouteWithFallback(inbound.tag),
                    access_source_ref);
                return [](Worker* current,
                          std::string protocol,
                          ConnectionLimiterPtr current_limiter,
                          proxyman::inbound::BuildRequest request,
                          proxyman::inbound::ReceiverSettings current_receiver,
                          uint8_t* result) -> net::awaitable<void> {
                    *result = co_await net::co_spawn(
                        current->GetExecutor(),
                        current->RegisterInboundTask(
                            std::move(protocol),
                            current_limiter,
                            std::move(request),
                            std::move(current_receiver)),
                        net::use_awaitable);
                }(&worker,
                  inbound.protocol,
                  limiter,
                  inbound.handler_request,
                  std::move(receiver),
                  &registered[index]);
            });

        if (std::ranges::find(registered, uint8_t{0}) != registered.end()) {
            LOG_WARN("Node {}/{}: create inbound handler failed, protocol={}",
                     panel_name, node_id, inbound.protocol);
            co_await removeInbound(inbound.tag);
            co_return false;
        }

        std::vector<WorkerBindResult> bound(workers_.size());
        co_await RunWorkerMutationBatch(
            io_context_.get_executor(), workers_,
            [&](Worker& worker, size_t index) {
                auto* limiter = limiters_[worker.Id()].get();
                return [](Worker* current,
                          PortBinding binding,
                          std::string protocol,
                          ConnectionLimiterPtr current_limiter,
                          proxyman::inbound::BuildRequest request,
                          WorkerBindResult* result) -> net::awaitable<void> {
                    result->tcp = co_await net::co_spawn(
                        current->GetExecutor(),
                        current->AddListenerTask(binding),
                        net::use_awaitable);
                    if (!result->tcp) {
                        co_return;
                    }
                    result->udp = co_await net::co_spawn(
                        current->GetExecutor(),
                        current->AddUdpListenerTask(
                            std::move(binding),
                            std::move(protocol),
                            current_limiter,
                            std::move(request)),
                        net::use_awaitable);
                }(&worker,
                  inbound.binding,
                  inbound.protocol,
                  limiter,
                  inbound.handler_request,
                  &bound[index]);
            });

        const auto failed_bind = std::ranges::find_if(
            bound, [](const WorkerBindResult& result) {
                return !result.tcp || !result.udp;
            });
        if (failed_bind != bound.end()) {
            LOG_WARN("Node {}/{}: {} bind failed, tag={}",
                     panel_name, node_id,
                     failed_bind->tcp ? "UDP" : "TCP",
                     inbound.tag);
            co_await removeInbound(inbound.tag);
            co_return false;
        }
    } catch (...) {
        publish_failure = std::current_exception();
    }

    if (publish_failure) {
        try {
            co_await removeInbound(inbound.tag);
        } catch (const std::exception& cleanup_error) {
            LOG_ERROR("Node {}/{}: inbound cleanup after publish failure raised: {}",
                      panel_name, node_id, cleanup_error.what());
        } catch (...) {
            LOG_ERROR("Node {}/{}: inbound cleanup after publish failure raised unknown exception",
                      panel_name, node_id);
        }
        std::rethrow_exception(publish_failure);
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

net::awaitable<void> Controller::Impl::UpdateRule(
    const std::string& tag,
    const std::vector<api::DetectRule>& new_rule_list) {
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers_.size());
    for (const auto& worker : workers_) {
        tasks.push_back(
            [](Worker* current,
               std::string current_tag,
               std::vector<rule::DetectRule> rules) -> net::awaitable<void> {
                co_await net::co_spawn(
                    current->GetExecutor(),
                    current->UpdateRuleTask(
                        std::move(current_tag), std::move(rules)),
                    net::use_awaitable);
            }(worker.get(), tag, new_rule_list));
    }
    co_await RunAwaitableBatch(
        io_context_.get_executor(), std::move(tasks));
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
    const auto user_protocol =
        proxyman::inbound::RegisteredUserProtocol(protocol);
    if (!user_protocol) {
        return;
    }

    proxyman::inbound::UserStore::ClearUsers(*user_protocol, tag);
}

}  // namespace acpp
