#include "controller_impl.hpp"
#include "awaitable_batch.hpp"
#include "node_transition.hpp"

#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <stdexcept>

namespace acpp {

namespace {

std::string ResolvePanelName(api::API* panel,
                             const std::map<api::API*, PanelConfig>& panel_configs) {
    const auto client_info = panel->Describe();
    auto cfg_it = panel_configs.find(panel);
    if (cfg_it != panel_configs.end() && !cfg_it->second.Name.empty()) {
        return cfg_it->second.Name;
    }
    return client_info.APIHost;
}

}  // namespace

Controller::Controller(net::io_context& io_context,
                       std::vector<std::unique_ptr<Worker>>& workers,
                       const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters)
    : impl_(std::make_unique<Impl>(io_context, workers, limiters)) {}

Controller::~Controller() = default;
Controller::Controller(Controller&&) noexcept = default;
Controller& Controller::operator=(Controller&&) noexcept = default;

void Controller::AddPanel(std::unique_ptr<api::API> panel,
                          const PanelConfig& panel_config) {
    impl_->AddPanel(std::move(panel), panel_config);
}

void Controller::Start() {
    impl_->Start();
}

void Controller::Stop() {
    impl_->Stop();
}

std::vector<Controller::NodeStatsInfo> Controller::GetNodeStats() const {
    return impl_->GetNodeStats();
}

Controller::Impl::Impl(net::io_context& io_context,
                       std::vector<std::unique_ptr<Worker>>& workers,
                       const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters)
    : io_context_(io_context)
    , workers_(workers)
    , limiters_(limiters) {}

void Controller::Impl::AddPanel(std::unique_ptr<api::API> panel,
                                const PanelConfig& panel_config) {
    auto* p = panel.get();
    panels_.push_back(std::move(panel));
    panel_configs_[p] = panel_config;
    panel_nodes_.push_back(p);
}

void Controller::Impl::Start() {
    running_ = true;
    net::co_spawn(io_context_.get_executor(), runNodeInfoMonitors(), net::detached);
}

void Controller::Impl::Stop() {
    running_ = false;
}

std::vector<Controller::NodeStatsInfo> Controller::Impl::GetNodeStats() const {
    std::vector<NodeStatsInfo> result;
    result.reserve(node_configs_.size());
    for (const auto& [panel, cfg] : node_configs_) {
        const auto client_info = panel->Describe();
        const int node_id = client_info.NodeID;
        const auto panel_cfg = panel_configs_.find(panel);
        const std::string panel_name =
            (panel_cfg != panel_configs_.end() && !panel_cfg->second.Name.empty())
                ? panel_cfg->second.Name
                : client_info.APIHost;

        NodeStatsInfo info;
        info.panel_name  = panel_name;
        info.node_id     = node_id;
        info.network     = cfg.TransportProtocol;
        info.port        = cfg.Port;
        std::string ukey = naming::BuildPanelNodeStatsKey(info.panel_name, node_id);
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

net::awaitable<void> Controller::Impl::runNodeInfoMonitors() {
    if (panel_nodes_.empty()) {
        co_return;
    }

    const auto run_once = [this]() -> net::awaitable<void> {
        const size_t batch_size = std::min(
            panel_nodes_.size(),
            std::max<size_t>(workers_.size() * 2, 1));

        for (size_t offset = 0; offset < panel_nodes_.size(); offset += batch_size) {
            std::vector<net::awaitable<void>> tasks;
            tasks.reserve(std::min(batch_size, panel_nodes_.size() - offset));

            const size_t end = std::min(panel_nodes_.size(), offset + batch_size);
            for (size_t i = offset; i < end; ++i) {
                tasks.push_back(nodeInfoMonitor(panel_nodes_[i]));
            }

            try {
                co_await controller::RunAwaitableBatch(
                    io_context_.get_executor(), std::move(tasks));
            } catch (const std::exception& e) {
                LOG_ERROR("panel monitor batch failed: {}", e.what());
            } catch (...) {
                LOG_ERROR("panel monitor batch failed with unknown exception");
            }
        }
    };

    co_await run_once();

    while (running_) {
        net::steady_timer timer(io_context_);
        timer.expires_after(std::chrono::seconds(defaults::kPanelPullInterval));
        (void)co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        if (!running_) break;
        co_await run_once();
    }
}

net::awaitable<void> Controller::Impl::nodeInfoMonitor(api::API* panel) {
    constexpr int kMaxAttempts  = defaults::kControllerSyncMaxAttempts;
    constexpr int kRetryBaseSec = defaults::kControllerSyncRetryBaseSeconds;
    const auto client_info = panel->Describe();
    const int node_id = client_info.NodeID;
    const std::string panel_name = ResolvePanelName(panel, panel_configs_);
    std::string stats_key = naming::BuildPanelNodeStatsKey(panel_name, node_id);

    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (attempt > 0) {
            const int delay = kRetryBaseSec * attempt;
            LOG_WARN("Panel {}/{}: retry {}/{} in {}s",
                     panel_name, node_id, attempt, kMaxAttempts - 1, delay);
            net::steady_timer timer(io_context_);
            timer.expires_after(std::chrono::seconds(delay));
            (void)co_await timer.async_wait(net::as_tuple(net::use_awaitable));
            if (!running_) co_return;
        }

        try {
            auto config_result = co_await panel->GetNodeInfo();
            if (config_result.missing) {
                auto cfg_it = node_configs_.find(panel);
                if (cfg_it != node_configs_.end()) {
                    std::string old_protocol =
                        naming::ResolveProtocolOrDefault(cfg_it->second.NodeType);
                    std::string old_tag = naming::BuildPanelNodeTag(
                        panel_name, old_protocol, cfg_it->second.Port);

                    co_await removeInbound(old_tag);
                    co_await removeOutbound(old_tag);
                    clearUsers(old_tag, old_protocol);
                    co_await UpdateRule(old_tag, {});
                    node_configs_.erase(cfg_it);
                    user_lists_.erase(panel);
                    inbound_started_.erase(panel);
                    node_stats_.erase(stats_key);

                    LOG_CONSOLE("node removed panel={} node={} inbound={}",
                                panel_name, node_id, old_tag);
                }
                co_return;
            }

            if (!config_result.Ok()) {
                throw std::runtime_error(ErrorMessage(config_result.error, config_result.error_msg));
            }

            const api::NodeInfo& fetched_config = *config_result.node_info;

            const std::string protocol =
                naming::ResolveProtocolOrDefault(fetched_config.NodeType);
            const std::string tag = naming::BuildPanelNodeTag(
                panel_name, protocol, fetched_config.Port);

            std::optional<api::NodeInfo> old_config;
            if (const auto old = node_configs_.find(panel); old != node_configs_.end()) {
                old_config = old->second;
            }
            const bool old_started = old_config &&
                inbound_started_.find(panel) != inbound_started_.end() &&
                inbound_started_.at(panel);
            const auto transition = controller::PlanNodeTransition(
                old_config ? &*old_config : nullptr,
                old_started,
                fetched_config);
            const bool transitioning = transition.Transitioning();

            std::string old_protocol;
            std::string old_tag;
            if (old_config) {
                old_protocol = naming::ResolveProtocolOrDefault(old_config->NodeType);
                old_tag = naming::BuildPanelNodeTag(
                    panel_name, old_protocol, old_config->Port);
            }

            if (transition.mode == controller::NodeTransitionMode::StageNewEndpoint
                || transition.mode == controller::NodeTransitionMode::ReplaceInPlace
                || transition.mode == controller::NodeTransitionMode::SwapSameEndpoint) {
                LOG_CONSOLE("node config_changed panel={} node={} action=recreate",
                            panel_name, node_id);
            }

            auto rules_result = co_await panel->GetNodeRule();
            if (!rules_result.Ok()) {
                LOG_WARN("Panel {}/{}: GetNodeRule failed: {}",
                         panel_name, node_id,
                         rules_result.error_msg.empty()
                            ? ErrorCodeToString(rules_result.error)
                            : rules_result.error_msg);
            }

            auto users_result = co_await panel->GetUserList();
            std::optional<std::vector<api::UserInfo>> next_users;
            if (!users_result.Ok()) {
                if (transitioning) {
                    throw std::runtime_error(ErrorMessage(
                        users_result.error, users_result.error_msg));
                }
                LOG_WARN("Panel {}/{}: user sync skipped: {}",
                         panel_name, node_id,
                         users_result.error_msg.empty()
                            ? ErrorCodeToString(users_result.error)
                            : users_result.error_msg);
            } else if (users_result.not_modified) {
                if (transitioning) {
                    if (const auto cached = user_lists_.find(panel);
                        cached != user_lists_.end()) {
                        next_users = cached->second;
                    } else {
                        throw std::runtime_error(
                            "panel returned users not modified without a committed user snapshot");
                    }
                }
            } else {
                next_users = std::move(users_result.users);
            }

            if (!transitioning) {
                if (next_users &&
                    !syncUserList(panel, tag, protocol, fetched_config, *next_users)) {
                    throw std::runtime_error("failed to build panel user snapshot");
                }
                node_configs_[panel] = fetched_config;
                if (rules_result.Ok() && !rules_result.not_modified) {
                    co_await UpdateRule(tag, rules_result.rules);
                }
            } else {
                if (!next_users) {
                    throw std::runtime_error("candidate node has no user snapshot");
                }

                auto candidate_user_set = BuildUsersForInbound(
                    protocol, tag, fetched_config, *next_users);
                if (!candidate_user_set) {
                    throw std::runtime_error("failed to build candidate user snapshot");
                }

                const bool destructive_swap = transition.DestructiveSwap();
                std::optional<proxyman::inbound::UserSet> rollback_user_set;
                if (old_config && old_tag == tag) {
                    const auto cached = user_lists_.find(panel);
                    if (cached == user_lists_.end()) {
                        throw std::runtime_error(
                            "cannot safely replace node without rollback users");
                    }
                    rollback_user_set = BuildUsersForInbound(
                        old_protocol, old_tag, *old_config, cached->second);
                    if (!rollback_user_set) {
                        throw std::runtime_error(
                            "failed to build rollback user snapshot");
                    }
                }

                auto rollback = [&]() -> net::awaitable<bool> {
                    try {
                        bool restored = true;
                        if (!old_config || old_tag != tag) {
                            co_await removeOutbound(tag);
                            clearUsers(tag, protocol);
                        } else {
                            if (rollback_user_set) {
                                proxyman::inbound::UserStore::ApplyUsers(
                                    old_tag, *rollback_user_set);
                            }
                            restored = co_await addOutbound(
                                panel, *old_config, old_tag);
                        }

                        if (transition.RestoreOldInboundOnRollback()
                            && old_config && old_started) {
                            bool inbound_restored = false;
                            if (restored) {
                                inbound_restored = co_await addInbound(panel, *old_config);
                            }
                            restored = restored && inbound_restored;
                            inbound_started_[panel] = restored;
                        }
                        co_return restored;
                    } catch (const std::exception& e) {
                        LOG_ERROR("Node {}/{}: rollback raised: {}",
                                  panel_name, node_id, e.what());
                    } catch (...) {
                        LOG_ERROR("Node {}/{}: rollback raised an unknown exception",
                                  panel_name, node_id);
                    }
                    co_return false;
                };

                if (destructive_swap) {
                    co_await removeInbound(old_tag);
                }

                proxyman::inbound::UserStore::ApplyUsers(tag, *candidate_user_set);

                std::exception_ptr candidate_failure;
                try {
                    if (!co_await addOutbound(panel, fetched_config, tag)) {
                        throw std::runtime_error("candidate outbound creation failed");
                    }

                    if (!co_await addInbound(panel, fetched_config)) {
                        throw std::runtime_error("candidate inbound creation failed");
                    }
                } catch (...) {
                    candidate_failure = std::current_exception();
                }
                if (candidate_failure) {
                    const bool restored = co_await rollback();
                    if (!restored) {
                        LOG_ERROR("Node {}/{}: rollback failed after candidate prepare failure",
                                  panel_name, node_id);
                    }
                    std::rethrow_exception(candidate_failure);
                }

                node_configs_[panel] = fetched_config;
                user_lists_[panel] = *next_users;
                inbound_started_[panel] = true;
                node_stats_[stats_key].user_count = next_users->size();

                if (rules_result.Ok() && !rules_result.not_modified) {
                    co_await UpdateRule(tag, rules_result.rules);
                }

                if (old_config && old_tag != tag) {
                    if (transition.RetireOldAfterCommit()) {
                        co_await removeInbound(old_tag);
                    }
                    co_await removeOutbound(old_tag);
                    clearUsers(old_tag, old_protocol);
                    co_await UpdateRule(old_tag, {});
                }

                LOG_CONSOLE(
                    "node config_committed panel={} node={} tag={} replaced={}",
                    panel_name, node_id, tag, old_config.has_value());
            }

            co_await userInfoMonitor(panel, tag, protocol);

            co_return;

        } catch (const std::exception& e) {
            if (attempt + 1 < kMaxAttempts) {
                LOG_WARN("Panel {}/{}: attempt {}/{} failed: {}",
                         panel_name, node_id, attempt + 1, kMaxAttempts, e.what());
            } else {
                LOG_ERROR("Panel {}/{}: all {} attempts failed: {}",
                          panel_name, node_id, kMaxAttempts, e.what());
            }
        }
    }
}

}  // namespace acpp
