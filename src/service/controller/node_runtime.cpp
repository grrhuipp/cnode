#include "node_runtime.hpp"
#include "../../common/awaitable_batch.hpp"

#include "app/proxyman/inbound/user_store.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/runtime_publication.hpp"
#include "app/worker.hpp"
#include "infra/log.hpp"

#include <algorithm>
#include <cstdint>
#include <exception>
#include <vector>

namespace controller {

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
                co_await current->PostCall([current, tag = std::move(current_tag)] {
                    current->RemoveOutbound(tag);
                });
            }(this, &worker, tag);
        });
}

net::awaitable<void> NodeRuntime::AddOutbound(
    const proxyman::outbound::PreparedOutboundConfig& prepared) {
    ThrowIfStopping();
    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [this, &prepared](Worker& worker, size_t) {
            return [](NodeRuntime* runtime, Worker* current,
                      proxyman::outbound::PreparedOutboundConfig config)
                       -> net::awaitable<void> {
                runtime->ThrowIfStopping();
                co_await current->PostCall([current, config = std::move(config)]() mutable {
                    current->AddOutbound(std::move(config));
                });
            }(this, &worker, prepared);
        });
}

net::awaitable<bool> NodeRuntime::AddInbound(const PreparedInbound& inbound) {
    ThrowIfStopping();
    const PanelLogContext log_context{config_.Name, config_.APIHost, config_.NodeIDs.Front(), config_.NodeType};
    const auto& tag = inbound.binding.tag;

    std::exception_ptr publish_failure;
    try {
        std::vector<InboundInstallFailure> installed(
            workers_.size(), InboundInstallFailure::None);
        co_await RunWorkerMutationBatch(
            io_context_.get_executor(), workers_,
            [&](Worker& worker, size_t index) {
                return [](NodeRuntime* runtime, Worker* current,
                          const PreparedInbound* prepared,
                          InboundInstallFailure* result) -> net::awaitable<void> {
                    runtime->ThrowIfStopping();
                    *result = co_await current->PostTask(
                        InstallInbound(*current, *prepared));
                }(this, &worker, &inbound, &installed[index]);
            });

        const auto failed = std::ranges::find_if(
            installed, [](InboundInstallFailure result) {
                return result != InboundInstallFailure::None;
            });
        if (failed != installed.end()) {
            LOG_PANEL_WARN(log_context, "Inbound install failed: stage={} protocol={} tag={}",
                     InboundInstallFailureName(*failed), inbound.binding.protocol, tag);
            co_await RemoveInbound(tag);
            co_return false;
        }
    } catch (...) {
        publish_failure = std::current_exception();
    }

    if (publish_failure) {
        if (IsStopping()) std::rethrow_exception(publish_failure);
        try {
            co_await RemoveInbound(tag);
        } catch (const std::exception& cleanup_error) {
            LOG_PANEL_ERROR(log_context, "Inbound cleanup after publish failure failed: {}", cleanup_error.what());
        } catch (...) {
            LOG_PANEL_ERROR(log_context, "Inbound cleanup after publish failure failed: unknown exception");
        }
        std::rethrow_exception(publish_failure);
    }
    ThrowIfStopping();

    LOG_PANEL_INFO(log_context, "inbound ready: tag={} port={} protocol={} network={} workers={} accept=SO_REUSEPORT",
                   tag, inbound.binding.port, inbound.binding.protocol,
                   inbound.receiver.stream_settings.network, workers_.size());
    co_return true;
}

net::awaitable<void> NodeRuntime::UpdateRules(
    const std::string& tag,
    const std::vector<rule::DetectRule>& new_rule_list) {
    ThrowIfStopping();
    co_await RunWorkerMutationBatch(
        io_context_.get_executor(), workers_,
        [this, &tag, &new_rule_list](Worker& worker, size_t) {
            return [](NodeRuntime* runtime, Worker* current,
                      std::string current_tag,
                      std::vector<rule::DetectRule> rules) -> net::awaitable<void> {
                runtime->ThrowIfStopping();
                co_await current->PostCall(
                    [current, tag = std::move(current_tag), rules = std::move(rules)]() mutable {
                        current->UpdateRule(tag, std::move(rules));
                    });
            }(this, &worker, tag, new_rule_list);
        });
}

net::awaitable<void> NodeRuntime::RecoverUsers() {
    co_await RollbackUsers(
        io_context_.get_executor(), workers_, state_.user_recovery, stopping_);
}

net::awaitable<void> NodeRuntime::ClearUsers(const std::string& tag, const std::string& protocol) {
    co_await RecoverUsers();
    const auto user_protocol = proxyman::inbound::RegisteredUserProtocol(protocol);
    if (!user_protocol) throw std::logic_error("node has no registered user protocol");
    co_await PublishUsers(io_context_.get_executor(), workers_,
        proxyman::inbound::UserStore::PrepareClearUsers(*user_protocol, tag),
        state_.user_recovery, stopping_);
}

net::awaitable<void> NodeRuntime::ApplyUsers(
    const std::string& tag, const proxyman::inbound::UserSet& users) {
    co_await RecoverUsers();
    co_await PublishUsers(io_context_.get_executor(), workers_,
        proxyman::inbound::UserStore::PrepareUsers(tag, users),
        state_.user_recovery, stopping_);
}

}  // namespace controller
