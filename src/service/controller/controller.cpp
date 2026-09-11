#include "controller_impl.hpp"
#include "../../common/monitor_loop.hpp"
#include "node_transaction.hpp"
#include "node_runtime.hpp"
#include "panel_schedule.hpp"

#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <format>
#include <stdexcept>

namespace acpp {

Controller::Controller(net::io_context& io_context,
                       const std::vector<std::unique_ptr<Worker>>& workers,
                       const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters)
    : impl_(std::make_shared<Impl>(io_context, workers, limiters)) {}

Controller::~Controller() = default;

void Controller::AddPanel(std::unique_ptr<api::API> panel,
                          const PanelConfig& panel_config) {
    impl_->AddPanel(std::move(panel), panel_config);
}

void Controller::Start() {
    impl_->Start();
}

std::vector<Controller::NodeStatsInfo> Controller::GetNodeStats() const {
    return impl_->GetNodeStats();
}

Controller::Impl::Impl(net::io_context& io_context,
                       const std::vector<std::unique_ptr<Worker>>& workers,
                       const std::vector<std::unique_ptr<ConnectionLimiter>>& limiters)
    : io_context_(io_context)
    , workers_(workers)
    , limiters_(limiters) {}

Controller::Impl::PanelRuntime::PanelRuntime(
    std::unique_ptr<api::API> api, const PanelConfig& source)
    : client(std::move(api)), config(source) {
    if (!client || config.Name.empty() || config.NodeIDs.Values().size() != 1) {
        throw std::invalid_argument("panel runtime requires a client, a name and one node ID");
    }
}

void Controller::Impl::AddPanel(std::unique_ptr<api::API> panel,
                                const PanelConfig& panel_config) {
    // Construct the complete entity before publishing it to the owner.
    panels_.push_back(std::make_unique<PanelRuntime>(std::move(panel), panel_config));
}

void Controller::Impl::Start() {
    enum class LoopKind { Sync, Status };
    for (auto& entry : panels_) {
        auto* panel = entry.get();
        for (const auto kind : {LoopKind::Sync, LoopKind::Status}) {
            auto& slot = kind == LoopKind::Sync ? panel->sync_loop : panel->status_loop;
            if (!slot.expired()) continue;
            const auto name = std::format("{}/{} {}",
                panel->config.Name, panel->config.NodeIDs.Front(),
                kind == LoopKind::Sync ? "sync" : "status");
            auto self = shared_from_this();
            auto loop = std::make_shared<monitor_detail::MonitorLoop>(
                io_context_.get_executor(), name,
                [self, panel, kind] {
                    return kind == LoopKind::Sync
                        ? self->panelSyncLoop(*panel) : self->panelStatusLoop(*panel);
                },
                [self, panel, kind](std::string_view loop_name, std::exception_ptr failure) {
                    if (kind == LoopKind::Sync) {
                        panel->state = PanelState::Unavailable;
                    }
                    if (!failure) {
                        LOG_WARN("Panel {} monitor: stopped", loop_name);
                        return;
                    }
                    try {
                        std::rethrow_exception(failure);
                    } catch (const std::exception& error) {
                        LOG_ERROR("Panel {} monitor: failed | {}", loop_name, error.what());
                    } catch (...) {
                        LOG_ERROR("Panel {} monitor: failed | unknown exception", loop_name);
                    }
                });
            slot = loop;
            loop->Start();
        }
    }
}

std::vector<Controller::NodeStatsInfo> Controller::Impl::GetNodeStats() const {
    std::vector<NodeStatsInfo> result;
    result.reserve(panels_.size());
    for (const auto& panel : panels_) {
        if (!panel->node.committed) continue;
        const auto& state = *panel->node.committed;

        NodeStatsInfo info;
        info.panel_name  = panel->config.Name;
        info.node_id     = panel->config.NodeIDs.Front();
        info.network    = state.config.TransportProtocol;
        info.port       = state.config.Port;
        info.total_users  = state.users.size();
        info.online_users = panel->stats.online_count;
        info.bytes_up     = panel->stats.bytes_up;
        info.bytes_down   = panel->stats.bytes_down;
        result.push_back(std::move(info));
    }
    return result;
}

net::awaitable<void> Controller::Impl::panelSyncLoop(
    PanelRuntime& panel) {
    using Clock = std::chrono::steady_clock;
    const int node_id = panel.config.NodeIDs.Front();
    const auto& panel_name = panel.config.Name;
    auto next_pull = Clock::now();
    // Match v2node reporting semantics: the first traffic/online snapshot
    // needs one complete push interval to accumulate meaningful activity.
    auto next_push = Clock::time_point::max();
    net::steady_timer timer(io_context_);

    const auto interval = [&](bool pull) {
        if (panel.node.committed) {
            return pull
                ? controller::PanelInterval(
                      panel.node.committed->config.PullInterval,
                      defaults::kPanelPullInterval)
                : controller::PanelInterval(
                      panel.node.committed->config.PushInterval,
                      defaults::kPanelPushInterval);
        }
        return std::chrono::seconds(
            pull ? defaults::kPanelPullInterval
                 : defaults::kPanelPushInterval);
    };

    for (;;) {
        auto now = Clock::now();
        if (now >= next_pull) {
            try {
                co_await nodeInfoMonitor(panel);
            } catch (const std::exception& e) {
                panel.state = PanelState::Unavailable;
                LOG_WARN("Panel {}/{} sync: unavailable | pull | {}",
                         panel_name,
                         node_id,
                         e.what());
            } catch (...) {
                panel.state = PanelState::Unavailable;
                LOG_WARN("Panel {}/{} sync: unavailable | pull | unknown error",
                         panel_name,
                         node_id);
            }
            now = Clock::now();
            next_pull = now + interval(true);
            if (panel.node.committed && panel.node.phase == controller::NodeRuntimePhase::Ready) {
                const auto scheduled_push = now + interval(false);
                if (next_push == Clock::time_point::max()) {
                    next_push = scheduled_push;
                } else {
                    next_push = std::min(next_push, scheduled_push);
                }
            } else {
                next_push = Clock::time_point::max();
            }
        }

        now = Clock::now();
        if (now >= next_push) {
            if (panel.node.committed && panel.node.phase == controller::NodeRuntimePhase::Ready) {
                const std::string& tag = panel.node.committed->tag;
                try {
                    co_await userInfoMonitor(panel, tag);
                } catch (const std::exception& e) {
                    LOG_WARN("Panel {}/{} report: unavailable | {}",
                             panel_name,
                             node_id,
                             e.what());
                } catch (...) {
                    LOG_WARN("Panel {}/{} report: unavailable | unknown error",
                             panel_name,
                             node_id);
                }
            }
            next_push = Clock::now() + interval(false);
        }

        timer.expires_at(std::min(next_pull, next_push));
        co_await timer.async_wait(net::use_awaitable);
    }
}

net::awaitable<void> Controller::Impl::panelStatusLoop(const PanelRuntime& panel) const {
    using Clock = std::chrono::steady_clock;
    constexpr auto interval = std::chrono::seconds(defaults::kPanelStatusLogInterval);
    auto next_status = Clock::now();
    net::steady_timer timer(io_context_);
    for (;;) {
        // Read the last committed state on the controller executor. No snapshot
        // reference crosses the wait, and no network request delays this loop.
        logPanelStatus(panel);
        next_status += interval;
        const auto now = Clock::now();
        if (next_status <= now) {
            // Keep the fixed cadence without emitting a burst for missed ticks.
            next_status += interval * ((now - next_status) / interval + 1);
        }
        timer.expires_at(next_status);
        co_await timer.async_wait(net::use_awaitable);
    }
}

net::awaitable<void> Controller::Impl::nodeInfoMonitor(PanelRuntime& panel) {
    const int node_id = panel.config.NodeIDs.Front();
    const auto& panel_name = panel.config.Name;

    controller::NodeRuntime runtime(io_context_, workers_, limiters_, panel.config);

    // One pull attempt is made for each scheduler invocation.
    {
        try {
            // Cleanup depends only on retained local snapshots, so a failing or
            // unavailable panel cannot indefinitely retain orphan resources.
            co_await controller::CleanPendingNodeRuntime(runtime, panel.node);
            auto config_result = co_await panel.client->GetNodeInfo();
            if (config_result.missing) {
                const bool removed = panel.node.committed || panel.node.HasPendingCleanup();
                const auto previous = panel.node.committed;
                co_await controller::RemoveNode(runtime, panel.node);
                panel.stats = {};
                if (removed) {
                    LOG_CONSOLE("Panel {}/{} config: removed | inbound {}",
                        panel_name, node_id, previous ? previous->tag : "uncommitted");
                }
                panel.state = PanelState::Missing;
                LOG_CONSOLE("Panel {}/{} sync: missing | {}",
                    panel_name, node_id, removed ? "removed" : "unchanged");
                co_return;
            }

            if (!config_result.Ok()) {
                throw std::runtime_error(ErrorMessage(config_result.error, config_result.error_msg));
            }

            const api::NodeInfo& fetched_config = *config_result.node_info;

            const std::string protocol =
                naming::ResolveProtocolOrDefault(fetched_config.NodeType);
            const std::string tag = naming::BuildPanelNodeTag(
                panel_name, node_id, protocol, fetched_config.Port);

            const auto old_state = panel.node.committed;
            const api::NodeInfo* old_config =
                old_state ? &old_state->config : nullptr;
            const bool old_started = panel.node.phase == controller::NodeRuntimePhase::Ready;
            const auto transition = controller::PlanNodeTransition(
                old_config,
                old_started,
                fetched_config);
            const bool transitioning = transition.Transitioning();

            if (transition.mode == controller::NodeTransitionMode::StageNewEndpoint
                || transition.mode == controller::NodeTransitionMode::ReplaceInPlace
                || transition.mode == controller::NodeTransitionMode::SwapSameEndpoint) {
                LOG_CONSOLE("Panel {}/{} config: changed | recreate",
                            panel_name, node_id);
            }

            auto rules_result = co_await panel.client->GetNodeRule();
            std::optional<std::vector<api::DetectRule>> next_rules;
            if (!rules_result.Ok()) {
                if (transitioning) {
                    throw std::runtime_error(ErrorMessage(
                        rules_result.error, rules_result.error_msg));
                }
                LOG_WARN("Panel {}/{} sync: degraded | rules | {}",
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

            auto users_result = co_await panel.client->GetUserList();
            std::optional<std::vector<api::UserInfo>> next_users;
            if (!users_result.Ok()) {
                if (transitioning) {
                    throw std::runtime_error(ErrorMessage(
                        users_result.error, users_result.error_msg));
                }
                LOG_WARN("Panel {}/{} sync: degraded | users | {}",
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

            if (transitioning && (!next_users || !next_rules)) {
                throw std::runtime_error("candidate node has no complete user and rule snapshot");
            }
            auto candidate = std::make_shared<controller::NodeSnapshot>();
            candidate->config = fetched_config;
            candidate->protocol = protocol;
            candidate->tag = tag;
            candidate->users = next_users ? std::move(*next_users) : old_state->users;
            candidate->rules = next_rules ? std::move(*next_rules) : old_state->rules;

            controller::PreparedNodeChange change;
            change.next = std::move(candidate);
            change.replace_users = next_users.has_value();
            change.replace_rules = next_rules.has_value();
            if (change.replace_users) {
                auto users = BuildUsersForInbound(protocol, tag, change.next->config, change.next->users);
                if (!users) throw std::runtime_error("failed to build candidate user snapshot");
                change.users = std::move(*users);
            }
            if (old_state && (transitioning || change.replace_users)) {
                change.previous_users = BuildUsersForInbound(
                    old_state->protocol, old_state->tag, old_state->config, old_state->users);
                if (!change.previous_users) {
                    throw std::runtime_error("failed to build rollback user snapshot");
                }
            }
            // Candidate data and authentication payloads are complete before
            // entering the transaction's first runtime mutation.
            // The initial local cleanup finished before this panel pull. With
            // no pending cleanup, ApplyNodeChange records {old, next} before
            // its first suspension. Admission and reservation are therefore
            // one uninterrupted step on the controller executor, covering all
            // Workers without sharing their live listener state.
            if (panel.node.HasPendingCleanup()) {
                throw std::logic_error("node admission requires completed local cleanup");
            }
            for (const auto& other : panels_) {
                if (other.get() != &panel && other->node.ReservesPort(fetched_config.Port) &&
                    other->config.ListenIP.Overlaps(panel.config.ListenIP)) {
                    throw std::runtime_error(std::format(
                        "panel listener endpoint conflict owner={}/{} port={}",
                        other->config.Name, other->config.NodeIDs.Front(), fetched_config.Port));
                }
            }
            co_await controller::ApplyNodeChange(runtime, panel.node, std::move(change));
            if (transitioning) {
                LOG_CONSOLE("Panel {}/{} config: ready | {} | replaced {}",
                    panel_name, node_id, tag, old_state ? "yes" : "no");
            }
            panel.state = rules_result.Ok() && users_result.Ok()
                ? PanelState::Ready : PanelState::Degraded;
        } catch (const std::exception& e) {
            panel.state = PanelState::Unavailable;
            LOG_ERROR("Panel {}/{} sync: unavailable | pull | {}",
                panel_name, node_id, e.what());
            if (panel.node.HasPendingCleanup()) {
                LOG_ERROR("Panel {}/{} sync: recovery required | pending runtime cleanup",
                    panel_name, node_id);
            }
        }
    }
}

void Controller::Impl::logPanelStatus(const PanelRuntime& panel) const {
    const int node_id = panel.config.NodeIDs.Front();
    const auto& panel_name = panel.config.Name;
    const std::string_view state_text = [&]() -> std::string_view {
        switch (panel.state) {
            case PanelState::Connecting: return "connecting";
            case PanelState::Ready: return "ready";
            case PanelState::Degraded: return "degraded";
            case PanelState::Missing: return "missing";
            case PanelState::Unavailable: return "unavailable";
        }
        return "unavailable";
    }();
    const std::string_view runtime_text = [&]() -> std::string_view {
        switch (panel.node.phase) {
            case controller::NodeRuntimePhase::Stopped: return "stopped";
            case controller::NodeRuntimePhase::Ready: return "ready";
            case controller::NodeRuntimePhase::Updating: return "updating";
            case controller::NodeRuntimePhase::RecoveryRequired: return "recovery required";
        }
        return "recovery required";
    }();

    if (!panel.node.committed) {
        LOG_CONSOLE(
            "Panel {}/{} status: {} | inbound {} | {} | {}",
            panel_name,
            node_id,
            state_text,
            runtime_text,
            panel.config.NodeType,
            panel.config.APIHost);
        return;
    }

    const auto& committed_state = *panel.node.committed;
    const std::string protocol =
        naming::ResolveProtocolOrDefault(committed_state.config.NodeType);
    const auto pull_interval = controller::PanelInterval(
        committed_state.config.PullInterval,
        defaults::kPanelPullInterval);
    const auto push_interval = controller::PanelInterval(
        committed_state.config.PushInterval,
        defaults::kPanelPushInterval);
    LOG_CONSOLE(
        "Panel {}/{} status: {} | inbound {} | {}:{} | users {} | rules {} | "
        "pull/push {}s/{}s",
        panel_name,
        node_id,
        state_text,
        runtime_text,
        protocol,
        committed_state.config.Port,
        committed_state.users.size(),
        committed_state.rules.size(),
        pull_interval.count(),
        push_interval.count());
}

}  // namespace acpp
