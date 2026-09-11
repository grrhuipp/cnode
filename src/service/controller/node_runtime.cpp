#include "node_runtime.hpp"
#include "../../common/awaitable_batch.hpp"
#include "inboundbuilder.hpp"
#include "outboundbuilder.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/infra/access_log_reporter.hpp"
#include "acppnode/infra/log.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <vector>

namespace acpp::controller {

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

net::awaitable<void> NodeRuntime::RemoveInbound(const std::string& tag) {
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

net::awaitable<void> NodeRuntime::RemoveOutbound(const std::string& tag) {
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

net::awaitable<bool> NodeRuntime::AddOutbound(const std::string& tag) {
    auto prepared = controller::OutboundBuilder(tag, config_);
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

net::awaitable<bool> NodeRuntime::AddInbound(const api::NodeInfo& node_config) {
    const int node_id = config_.NodeIDs.Front();
    const auto& panel_name = config_.Name;

    auto inbound = controller::InboundBuilder(config_, node_config);

    if (!proxyman::inbound::HasProxy(inbound.protocol)) {
        LOG_WARN("Node {}/{}: unsupported inbound protocol '{}'",
                 panel_name, node_id, inbound.protocol);
        co_return false;
    }

    const uint32_t access_source_ref = accesslog::Reporter::Instance().RegisterSource({
        .panel_name = panel_name,
        .panel_api_host = config_.APIHost,
        .node_type = inbound.protocol,
        .node_id = static_cast<uint64_t>(node_id),
    });
    if (access_source_ref == 0) {
        LOG_ERROR("Node {}/{}: centralized access-log source registration failed api={}",
                  panel_name, node_id, config_.APIHost);
        co_return false;
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
                    routing::RouteWithFallback(inbound.tag),
                    access_source_ref);
                return [](Worker* current,
                          ConnectionLimiterPtr current_limiter,
                          proxyman::inbound::BuildRequest request,
                          proxyman::inbound::ReceiverSettings current_receiver,
                          uint8_t* result) -> net::awaitable<void> {
                    *result = co_await net::co_spawn(
                        current->GetExecutor(),
                        current->RegisterInboundTask(
                            current_limiter,
                            std::move(request),
                            std::move(current_receiver)),
                        net::use_awaitable);
                }(&worker,
                  limiter,
                  inbound.handler_request,
                  std::move(receiver),
                  &registered[index]);
            });

        if (std::ranges::find(registered, uint8_t{0}) != registered.end()) {
            LOG_WARN("Node {}/{}: create inbound handler failed, protocol={}",
                     panel_name, node_id, inbound.protocol);
            co_await RemoveInbound(inbound.tag);
            co_return false;
        }

        std::vector<WorkerBindResult> bound(workers_.size());
        co_await RunWorkerMutationBatch(
            io_context_.get_executor(), workers_,
            [&](Worker& worker, size_t index) {
                auto* limiter = limiters_[worker.Id()].get();
                return [](Worker* current,
                          PortBinding binding,
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
                            current_limiter,
                            std::move(request)),
                        net::use_awaitable);
                }(&worker,
                  inbound.binding,
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
            co_await RemoveInbound(inbound.tag);
            co_return false;
        }
    } catch (...) {
        publish_failure = std::current_exception();
    }

    if (publish_failure) {
        try {
            co_await RemoveInbound(inbound.tag);
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

net::awaitable<void> NodeRuntime::UpdateRules(
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

void NodeRuntime::ClearUsers(const std::string& tag, const std::string& protocol) {
    const auto user_protocol =
        proxyman::inbound::RegisteredUserProtocol(protocol);
    if (!user_protocol) {
        return;
    }

    proxyman::inbound::UserStore::ClearUsers(*user_protocol, tag);
}

void NodeRuntime::ApplyUsers(const std::string& tag, const proxyman::inbound::UserSet& users) {
    proxyman::inbound::UserStore::ApplyUsers(tag, users);
}

}  // namespace acpp::controller
