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
    result.reserve(committed_nodes_.size());
    for (const auto& [panel, state] : committed_nodes_) {
        const auto& cfg = state.config;
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
                auto state_it = committed_nodes_.find(panel);
                if (state_it != committed_nodes_.end()) {
                    std::string old_protocol =
                        naming::ResolveProtocolOrDefault(state_it->second.config.NodeType);
                    std::string old_tag = naming::BuildPanelNodeTag(
                        panel_name, old_protocol, state_it->second.config.Port);

                    co_await removeInbound(old_tag);
                    co_await removeOutbound(old_tag);
                    clearUsers(old_tag, old_protocol);
                    co_await UpdateRule(old_tag, {});
                    committed_nodes_.erase(state_it);
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

            std::optional<CommittedNodeState> old_state;
            if (const auto committed = committed_nodes_.find(panel);
                committed != committed_nodes_.end()) {
                old_state = committed->second;
            }
            const api::NodeInfo* old_config =
                old_state ? &old_state->config : nullptr;
            const bool old_started = old_state && old_state->inbound_started;
            const auto transition = controller::PlanNodeTransition(
                old_config,
                old_started,
                fetched_config);
            const bool transitioning = transition.Transitioning();

            std::string old_protocol;
            std::string old_tag;
            if (old_config != nullptr) {
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
            std::optional<std::vector<api::DetectRule>> next_rules;
            if (!rules_result.Ok()) {
                if (transitioning) {
                    throw std::runtime_error(ErrorMessage(
                        rules_result.error, rules_result.error_msg));
                }
                LOG_WARN("Panel {}/{}: GetNodeRule failed: {}",
                         panel_name, node_id,
                         rules_result.error_msg.empty()
                            ? ErrorCodeToString(rules_result.error)
                            : rules_result.error_msg);
            } else if (rules_result.not_modified) {
                if (transitioning) {
                    if (!old_state) {
                        throw std::runtime_error(
                            "panel returned rules not modified without a committed rule snapshot");
                    }
                    next_rules = old_state->rules;
                }
            } else {
                next_rules = std::move(rules_result.rules);
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
                    if (!old_state) {
                        throw std::runtime_error(
                            "panel returned users not modified without a committed user snapshot");
                    }
                    next_users = old_state->users;
                }
            } else {
                next_users = std::move(users_result.users);
            }

            auto [stats_it, stats_inserted] = node_stats_.try_emplace(stats_key);
            (void)stats_inserted;
            NodeStats& committed_stats = stats_it->second;

            if (!transitioning) {
                CommittedNodeState next_state = *old_state;
                next_state.config = fetched_config;
                std::optional<proxyman::inbound::UserSet> next_user_set;
                std::optional<proxyman::inbound::UserSet> previous_user_set;
                if (next_users) {
                    next_user_set = BuildUsersForInbound(
                        protocol, tag, fetched_config, *next_users);
                    previous_user_set = BuildUsersForInbound(
                        protocol, tag, old_state->config, old_state->users);
                    if (!next_user_set || !previous_user_set) {
                        throw std::runtime_error("failed to build panel user snapshot");
                    }
                    next_state.users = *next_users;
                }

                bool rules_attempted = false;
                bool users_attempted = false;
                std::exception_ptr refresh_failure;
                try {
                    if (next_rules) {
                        rules_attempted = true;
                        co_await UpdateRule(tag, *next_rules);
                        next_state.rules = *next_rules;
                    }
                    if (next_user_set) {
                        users_attempted = true;
                        proxyman::inbound::UserStore::ApplyUsers(
                            tag, *next_user_set);
                    }
                    committed_nodes_.insert_or_assign(panel, std::move(next_state));
                } catch (...) {
                    refresh_failure = std::current_exception();
                }
                if (refresh_failure) {
                    if (users_attempted) {
                        try {
                            proxyman::inbound::UserStore::ApplyUsers(
                                tag, *previous_user_set);
                        } catch (...) {
                            LOG_ERROR("Node {}/{}: refresh user rollback incomplete",
                                      panel_name, node_id);
                        }
                    }
                    if (rules_attempted) {
                        try {
                            co_await UpdateRule(tag, old_state->rules);
                        } catch (...) {
                            LOG_ERROR("Node {}/{}: refresh rule rollback incomplete",
                                      panel_name, node_id);
                        }
                    }
                    std::rethrow_exception(refresh_failure);
                }
                if (next_users) {
                    committed_stats.user_count = next_users->size();
                }
            } else {
                if (!next_users || !next_rules) {
                    throw std::runtime_error(
                        "candidate node has no complete user and rule snapshot");
                }

                auto candidate_user_set = BuildUsersForInbound(
                    protocol, tag, fetched_config, *next_users);
                if (!candidate_user_set) {
                    throw std::runtime_error("failed to build candidate user snapshot");
                }

                std::optional<proxyman::inbound::UserSet> rollback_user_set;
                if (old_config != nullptr) {
                    rollback_user_set = BuildUsersForInbound(
                        old_protocol, old_tag, *old_config, old_state->users);
                    if (!rollback_user_set) {
                        throw std::runtime_error(
                            "failed to build rollback user snapshot");
                    }
                }

                bool candidate_users_applied = false;
                bool candidate_outbound_attempted = false;
                bool candidate_inbound_attempted = false;
                bool candidate_rules_attempted = false;
                bool old_inbound_retirement_attempted = false;
                bool old_outbound_retirement_attempted = false;
                bool old_users_cleared = false;
                bool old_rules_retirement_attempted = false;

                auto rollback = [&]() -> net::awaitable<bool> {
                    bool restored = true;
                    if (candidate_inbound_attempted) {
                        try {
                            co_await removeInbound(tag);
                        } catch (...) {
                            restored = false;
                        }
                    }
                    if (candidate_rules_attempted && old_tag != tag) {
                        try {
                            co_await UpdateRule(tag, {});
                        } catch (...) {
                            restored = false;
                        }
                    }
                    if (candidate_outbound_attempted && old_tag != tag) {
                        try {
                            co_await removeOutbound(tag);
                        } catch (...) {
                            restored = false;
                        }
                    }
                    if (candidate_users_applied && old_tag != tag) {
                        try {
                            clearUsers(tag, protocol);
                        } catch (...) {
                            restored = false;
                        }
                    }

                    if (old_config != nullptr) {
                        if ((old_tag == tag && candidate_users_applied)
                            || old_users_cleared) {
                            try {
                                proxyman::inbound::UserStore::ApplyUsers(
                                    old_tag, *rollback_user_set);
                            } catch (...) {
                                restored = false;
                            }
                        }
                        if ((old_tag == tag && candidate_outbound_attempted)
                            || old_outbound_retirement_attempted) {
                            try {
                                if (!co_await addOutbound(panel, *old_config, old_tag)) {
                                    restored = false;
                                }
                            } catch (...) {
                                restored = false;
                            }
                        }
                        if ((old_tag == tag && candidate_rules_attempted)
                            || old_rules_retirement_attempted) {
                            try {
                                co_await UpdateRule(old_tag, old_state->rules);
                            } catch (...) {
                                restored = false;
                            }
                        }
                        if (old_started
                            && ((old_tag == tag && candidate_inbound_attempted)
                                || old_inbound_retirement_attempted)) {
                            try {
                                if (!co_await addInbound(panel, *old_config)) {
                                    restored = false;
                                }
                            } catch (...) {
                                restored = false;
                            }
                        }
                    }
                    co_return restored;
                };

                std::exception_ptr transition_failure;
                try {
                    if (transition.DestructiveSwap()) {
                        old_inbound_retirement_attempted = true;
                        co_await removeInbound(old_tag);
                    }

                    candidate_users_applied = true;
                    proxyman::inbound::UserStore::ApplyUsers(tag, *candidate_user_set);

                    candidate_outbound_attempted = true;
                    if (!co_await addOutbound(panel, fetched_config, tag)) {
                        throw std::runtime_error("candidate outbound creation failed");
                    }

                    candidate_inbound_attempted = true;
                    if (!co_await addInbound(panel, fetched_config)) {
                        throw std::runtime_error("candidate inbound creation failed");
                    }

                    if (old_config != nullptr && old_tag != tag) {
                        if (transition.RetireOldInboundBeforeCommit()) {
                            old_inbound_retirement_attempted = true;
                            co_await removeInbound(old_tag);
                        }
                        old_outbound_retirement_attempted = true;
                        co_await removeOutbound(old_tag);
                        old_users_cleared = true;
                        clearUsers(old_tag, old_protocol);
                        old_rules_retirement_attempted = true;
                        co_await UpdateRule(old_tag, {});
                    }

                    candidate_rules_attempted = true;
                    co_await UpdateRule(tag, *next_rules);

                    CommittedNodeState next_state{
                        .config = fetched_config,
                        .users = *next_users,
                        .rules = *next_rules,
                        .inbound_started = true,
                    };
                    committed_nodes_.insert_or_assign(panel, std::move(next_state));
                    committed_stats.user_count = next_users->size();
                } catch (...) {
                    transition_failure = std::current_exception();
                }
                if (transition_failure) {
                    const bool restored = co_await rollback();
                    if (!restored) {
                        LOG_ERROR("Node {}/{}: rollback incomplete after transition failure",
                                  panel_name, node_id);
                    }
                    std::rethrow_exception(transition_failure);
                }

                LOG_CONSOLE(
                    "node config_committed panel={} node={} tag={} replaced={}",
                    panel_name, node_id, tag, old_config != nullptr);
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
