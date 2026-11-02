#include "node_runtime.hpp"
#include "../../common/awaitable_batch.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/worker.hpp"
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
void NodeRuntime::ThrowIfStopping() const {
    if (stopping_) throw IoSystemError(net::error::operation_aborted);
}


net::awaitable<void> NodeRuntime::RemoveInbound(const std::string& tag) {
    ThrowIfStopping();
    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [this, tag](Worker& worker, size_t) {
            return [](NodeRuntime* runtime, Worker* current, std::string current_tag)
                       -> net::awaitable<void> {
                runtime->ThrowIfStopping();
                co_await current->PostTask(
                    current->UnregisterListenerTask(std::move(current_tag)));
            }(this, &worker, tag);
        });
}

net::awaitable<void> NodeRuntime::RemoveOutbound(const std::string& tag) {
    ThrowIfStopping();
    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [this, tag](Worker& worker, size_t) {
            return [](NodeRuntime* runtime, Worker* current, std::string current_tag)
                       -> net::awaitable<void> {
                runtime->ThrowIfStopping();
                co_await current->PostTask(
                    current->RemoveOutboundTask(std::move(current_tag)));
            }(this, &worker, tag);
        });
}

net::awaitable<bool> NodeRuntime::AddOutbound(
    const proxyman::outbound::PreparedOutboundConfig& prepared) {
    ThrowIfStopping();
    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [this, &prepared](Worker& worker, size_t) {
            return [](NodeRuntime* runtime, Worker* current,
                      proxyman::outbound::PreparedOutboundConfig config)
                       -> net::awaitable<void> {
                runtime->ThrowIfStopping();
                co_await current->PostTask(
                    current->AddOutboundTask(std::move(config)));
            }(this, &worker, prepared);
        });
    co_return true;
}

net::awaitable<bool> NodeRuntime::AddInbound(const InboundBuild& inbound) {
    ThrowIfStopping();
    const int node_id = config_.NodeIDs.Front();
    const auto& panel_name = config_.Name;


    std::exception_ptr publish_failure;
    try {
        std::vector<uint8_t> registered(workers_.size(), 0);
        co_await RunWorkerMutationBatch(
            io_context_.get_executor(), workers_,
            [&](Worker& worker, size_t index) {
                auto receiver = proxyman::inbound::MakeReceiverSettings(
                    inbound.tag,
                    std::vector<std::string>{
                        inbound.tag, std::string(constants::protocol::kNode)},
                    inbound.protocol,
                    inbound.stream_settings,
                    inbound.sniff,
                    inbound.proxy_protocol,
                    routing::RouteWithFallback(inbound.tag),
                    inbound.accounting_key);
                return [](NodeRuntime* runtime, Worker* current,
                          proxyman::inbound::BuildRequest request,
                          proxyman::inbound::ReceiverSettings current_receiver,
                          uint8_t* result) -> net::awaitable<void> {
                    runtime->ThrowIfStopping();
                    *result = co_await current->PostTask(
                        current->RegisterInboundTask(
                            std::move(request),
                            std::move(current_receiver)));
                }(this, &worker,
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

        ThrowIfStopping();
        std::vector<WorkerBindResult> bound(workers_.size());
        co_await RunWorkerMutationBatch(
            io_context_.get_executor(), workers_,
            [&](Worker& worker, size_t index) {
                return [](NodeRuntime* runtime, Worker* current,
                          PortBinding binding,
                          proxyman::inbound::BuildRequest request,
                          WorkerBindResult* result) -> net::awaitable<void> {
                    runtime->ThrowIfStopping();
                    result->tcp = co_await current->PostTask(
                        current->AddListenerTask(binding));
                    if (!result->tcp) {
                        co_return;
                    }
                    runtime->ThrowIfStopping();
                    result->udp = co_await current->PostTask(
                        current->AddUdpListenerTask(
                            std::move(binding),
                            std::move(request)));
                }(this, &worker,
                  inbound.binding,
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
        if (IsStopping()) std::rethrow_exception(publish_failure);
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
    ThrowIfStopping();

    LOG_CONSOLE("inbound ready tag={} port={} protocol={} workers={} accept=SO_REUSEPORT",
                inbound.tag, inbound.binding.port, inbound.protocol, workers_.size());
    co_return true;
}

net::awaitable<void> NodeRuntime::UpdateRules(
    const std::string& tag,
    const std::vector<rule::DetectRule>& new_rule_list) {
    ThrowIfStopping();
    std::vector<net::awaitable<void>> tasks;
    tasks.reserve(workers_.size());
    for (const auto& worker : workers_) {
        tasks.push_back(
            [](NodeRuntime* runtime, Worker* current,
               std::string current_tag,
               std::vector<rule::DetectRule> rules) -> net::awaitable<void> {
                runtime->ThrowIfStopping();
                co_await current->PostTask(
                    current->UpdateRuleTask(
                        std::move(current_tag), std::move(rules)));
            }(this, worker.get(), tag, new_rule_list));
    }
    co_await RunAwaitableBatch(
        io_context_.get_executor(), std::move(tasks));
}

net::awaitable<void> NodeRuntime::RecoverUsers() {
    ThrowIfStopping();
    if (!state_.user_recovery) co_return;
    auto& recovery = *state_.user_recovery;
    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [this, &recovery](Worker& worker, size_t index) {
            return [](NodeRuntime* runtime, Worker* current,
                      proxyman::inbound::UserStore::WorkerView view) -> net::awaitable<void> {
                runtime->ThrowIfStopping();
                co_await current->PostTask(current->InstallUserViewTask(std::move(view)));
            }(this, &worker, recovery.worker_views[index]);
        });
    ThrowIfStopping();
    proxyman::inbound::UserStore::CommitSnapshot(recovery.previous);
    state_.user_recovery.reset();
}

net::awaitable<void> NodeRuntime::PublishUsers(
    proxyman::inbound::UserStore::PublishedSnapshot snapshot) {
    using Store = proxyman::inbound::UserStore;
    ThrowIfStopping();
    if (state_.user_recovery) {
        throw std::logic_error("user publication requires completed compensation");
    }
    UserPublicationRecovery recovery;
    recovery.previous = Store::CaptureSnapshot();
    recovery.worker_views.reserve(workers_.size());
    std::vector<Store::WorkerView> candidate_views;
    candidate_views.reserve(workers_.size());
    for (size_t i = 0; i < workers_.size(); ++i) {
        recovery.worker_views.push_back(Store::PrepareWorkerView(recovery.previous));
        candidate_views.push_back(Store::PrepareWorkerView(snapshot));
    }
    // Retain rollback leases before any mailbox can install a candidate.
    // The node transaction shields and joins RecoverUsers on every failure.
    state_.user_recovery = std::move(recovery);
    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [this, &candidate_views](Worker& worker, size_t index) {
            return [](NodeRuntime* runtime, Worker* current, Store::WorkerView view) -> net::awaitable<void> {
                runtime->ThrowIfStopping();
                co_await current->PostTask(current->InstallUserViewTask(std::move(view)));
            }(this, &worker, std::move(candidate_views[index]));
        });
    ThrowIfStopping();
    Store::CommitSnapshot(std::move(snapshot));
    state_.user_recovery.reset();
}

net::awaitable<void> NodeRuntime::ClearUsers(const std::string& tag, const std::string& protocol) {
    co_await RecoverUsers();
    const auto user_protocol = proxyman::inbound::RegisteredUserProtocol(protocol);
    if (!user_protocol) throw std::logic_error("node has no registered user protocol");
    co_await PublishUsers(proxyman::inbound::UserStore::PrepareClearUsers(*user_protocol, tag));
}

net::awaitable<void> NodeRuntime::ApplyUsers(
    const std::string& tag, const proxyman::inbound::UserSet& users) {
    co_await RecoverUsers();
    co_await PublishUsers(proxyman::inbound::UserStore::PrepareUsers(tag, users));
}

}  // namespace acpp::controller
