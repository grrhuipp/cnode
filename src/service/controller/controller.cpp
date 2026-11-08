#include "controller_impl.hpp"
#include "../../common/monitor_loop.hpp"
#include "node_transaction.hpp"
#include "node_runtime.hpp"
#include "panel_inbound.hpp"
#include "panel_schedule.hpp"
#include "../../proxy/freedom/freedom_outbound.hpp"

#include "app/prepared_inbound.hpp"
#include "core/constants.hpp"
#include "core/naming.hpp"
#include "infra/log.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <format>
#include <stdexcept>
#include <utility>
#include <variant>


namespace {

[[nodiscard]] proxyman::outbound::PreparedOutboundConfig BuildPanelAutoOutbound(
    const std::string& tag,
    const PanelConfig& panel_config) {
    proxy::freedom::outbound::FreedomSettings settings;
    settings.domain_strategy = panel_config.EnableDNS
        ? panel_config.DNSType : proxy::freedom::outbound::DomainStrategy::AsIs;
    return proxyman::outbound::PreparedOutboundConfig{
        .tag = tag,
        .protocol = std::string(constants::protocol::kFreedom),
        // The panel sendIP is the auto outbound Handler's sendThrough.
        .sender = OutboundSenderSettings{
            .stream_settings = {},
            .send_through = panel_config.SendIP,
        },
        .create = proxy::freedom::outbound::PrepareOutbound(std::move(settings)),
    };
}

std::unique_ptr<api::API> ValidatePanelRuntimeArgs(
    std::unique_ptr<api::API> api, const PanelConfig& source) {
    if (!api || source.Name.empty() || source.NodeIDs.Values().size() != 1) {
        throw std::invalid_argument("panel runtime requires a client, a name and one node ID");
    }
    return api;
}

[[nodiscard]] std::string_view ResolvedNodeNetwork(
    const controller::NodeSnapshot& state) noexcept {
    if (state.inbound) {
        return state.inbound->receiver.stream_settings.network;
    }
    return state.config.TransportProtocol.empty()
        ? constants::protocol::kTcp
        : std::string_view(state.config.TransportProtocol);
}

}  // namespace
Controller::Controller(net::io_context& io_context,
                       const std::vector<std::unique_ptr<Worker>>& workers)
    : impl_(std::make_shared<Impl>(io_context, workers)) {}

Controller::~Controller() = default;

void Controller::AddPanel(std::unique_ptr<api::API> panel,
                          const PanelConfig& panel_config) {
    impl_->AddPanel(std::move(panel), panel_config);
}

void Controller::Start() {
    impl_->Start();
}

void Controller::RequestStop() noexcept {
    impl_->RequestStop();
}

net::awaitable<void> Controller::AsyncJoin() {
    co_await impl_->AsyncJoin();
}

net::awaitable<void> Controller::FlushTraffic() {
    co_await impl_->FlushTraffic();
}

std::vector<Controller::NodeStatsInfo> Controller::GetNodeStats() const {
    return impl_->GetNodeStats();
}

Controller::Impl::Impl(net::io_context& io_context,
                       const std::vector<std::unique_ptr<Worker>>& workers)
    : io_context_(io_context)
    , workers_(workers) {}

Controller::Impl::PanelRuntime::PanelRuntime(
    std::unique_ptr<api::API> api, const PanelConfig& source,
    controller::NodeMutationGate& gate, net::any_io_executor executor)
    : client(ValidatePanelRuntimeArgs(std::move(api), source))
    , config(source)
    , accounting_key(naming::BuildPanelNodeAccountingKey(config.Name, config.NodeIDs.Front()))
    , mutation(gate, std::move(executor), node) {
    traffic_journal = std::make_unique<controller::TrafficJournal>(config);
    const auto unknown = traffic_journal->UnknownCount();
    if (unknown != 0) {
        const PanelLogContext log_context{config.Name, config.APIHost, config.NodeIDs.Front(), config.NodeType};
        LOG_PANEL_ERROR(log_context, "Traffic accounting requires reconciliation: unknown_records={} directory={}",
                        unknown, traffic_journal->Directory().string());
    }
}

void Controller::Impl::AddPanel(std::unique_ptr<api::API> panel,
                                const PanelConfig& panel_config) {
    ThrowIfStopping();
    // Construct the complete entity before publishing it to the owner.
    auto runtime = std::make_unique<PanelRuntime>(
        std::move(panel), panel_config, node_mutations_, io_context_.get_executor());
    if (!journal_executor_) {
        journal_executor_ = std::make_unique<controller::JournalExecutor>();
    }
    panels_.push_back(std::move(runtime));
}

void Controller::Impl::Start() {
    if (stopping_) return;
    node_mutations_.Seal();
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
                    if (self->stopping_ && !failure) return;
                    const PanelLogContext log_context{panel->config.Name, panel->config.APIHost,
                        panel->config.NodeIDs.Front(), panel->config.NodeType};
                    if (kind == LoopKind::Sync) {
                        panel->state = PanelState::Unavailable;
                    }
                    if (!failure) {
                        LOG_PANEL_WARN(log_context, "Panel monitor stopped unexpectedly: loop={}", loop_name);
                        return;
                    }
                    try {
                        std::rethrow_exception(failure);
                    } catch (const std::exception& error) {
                        LOG_PANEL_ERROR(log_context, "Panel monitor failed: loop={} reason={}", loop_name, error.what());
                    } catch (...) {
                        LOG_PANEL_ERROR(log_context, "Panel monitor failed: loop={} reason=unknown exception", loop_name);
                    }
                });
            slot = loop;
            loop->Start();
        }
    }
}

void Controller::Impl::RequestStop() noexcept {
    if (stopping_) return;
    stopping_ = true;
    node_mutations_.Close();
    for (const auto& panel : panels_) {
        if (auto loop = panel->sync_loop.lock()) loop->RequestStop();
        if (auto loop = panel->status_loop.lock()) loop->RequestStop();
    }
}

net::awaitable<void> Controller::Impl::AsyncJoin() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    for (const auto& panel : panels_) {
        if (auto loop = panel->sync_loop.lock()) co_await loop->AsyncJoin();
        if (auto loop = panel->status_loop.lock()) co_await loop->AsyncJoin();
    }
}

void Controller::Impl::ThrowIfStopping() const {
    if (stopping_) throw IoSystemError(net::error::operation_aborted);
}

std::vector<Controller::NodeStatsInfo> Controller::Impl::GetNodeStats() const {
    std::vector<NodeStatsInfo> result;
    result.reserve(panels_.size());
    for (const auto& panel : panels_) {
        if (!panel->node.committed ||
            panel->node.phase != controller::NodeRuntimePhase::Ready) {
            continue;
        }
        const auto& state = *panel->node.committed;

        NodeStatsInfo info;
        info.panel_name  = panel->config.Name;
        info.panel_host  = panel->config.APIHost;
        info.node_type   = panel->config.NodeType;
        info.node_id     = panel->config.NodeIDs.Front();
        info.network      = std::string(ResolvedNodeNetwork(state));
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
    const PanelLogContext log_context{panel.config.Name, panel.config.APIHost,
        panel.config.NodeIDs.Front(), panel.config.NodeType};
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
        if (stopping_) co_return;
        auto now = Clock::now();
        if (now >= next_pull) {
            try {
                co_await nodeInfoMonitor(panel);
            } catch (const std::exception& e) {
                if (stopping_) throw;
                panel.state = PanelState::Unavailable;
                LOG_PANEL_ERROR(log_context, "Panel sync unavailable: operation=pull reason={}", e.what());
                if (panel.node.HasPendingCleanup()) {
                    LOG_PANEL_ERROR(log_context, "Panel sync requires recovery: pending runtime cleanup");
                }
            } catch (...) {
                if (stopping_) throw;
                panel.state = PanelState::Unavailable;
                LOG_PANEL_ERROR(log_context, "Panel sync unavailable: operation=pull reason=unknown error");
                if (panel.node.HasPendingCleanup()) {
                    LOG_PANEL_ERROR(log_context, "Panel sync requires recovery: pending runtime cleanup");
                }
            }
            now = Clock::now();
            const auto pull_delay = panel.node.HasPendingCleanup()
                ? std::min(interval(true), std::chrono::seconds(1))
                : interval(true);
            next_pull = now + pull_delay;
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

        if (stopping_) co_return;
        now = Clock::now();
        if (now >= next_push) {
            if (panel.node.committed && panel.node.phase == controller::NodeRuntimePhase::Ready) {
                try {
                    co_await userInfoMonitor(panel, panel.node.committed->tag);
                } catch (const std::exception& e) {
                    if (stopping_) throw;
                    LOG_PANEL_WARN(log_context, "Panel report unavailable: operation=push reason={}", e.what());
                } catch (...) {
                    if (stopping_) throw;
                    LOG_PANEL_WARN(log_context, "Panel report unavailable: operation=push reason=unknown error");
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
        if (stopping_) co_return;
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
    const PanelLogContext log_context{panel_name, panel.config.APIHost, node_id, panel.config.NodeType};

    controller::NodeRuntime runtime(io_context_, workers_, panel.config, panel.node, stopping_);

    // One pull attempt is made for each scheduler invocation.
    // Cleanup depends only on retained local snapshots, so a failing or
    // unavailable panel cannot indefinitely retain orphan resources.
    if (panel.node.HasPendingCleanup()) {
        auto lease = co_await node_mutations_.Acquire(panel.mutation);
        ThrowIfStopping();
        co_await controller::CleanPendingNodeRuntime(runtime, panel.node);
    }
    ThrowIfStopping();
    const auto old_state = panel.node.committed;
    auto config_result = co_await panel.client->GetNodeInfo(
        old_state ? old_state->config_etag : std::string{});
    ThrowIfStopping();
    if (!config_result.Ok()) {
        throw std::runtime_error(ErrorMessage(config_result.error, config_result.error_msg));
    }

    if (config_result.not_modified && !old_state) {
        throw std::runtime_error("node not modified without a committed snapshot");
    }
    const api::NodeInfo& fetched_config = config_result.not_modified
        ? old_state->config : *config_result.node_info;
    const std::string& protocol = fetched_config.NodeType;
    const std::string tag = naming::BuildPanelNodeTag(
        panel_name, node_id, protocol, fetched_config.Port);

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
        LOG_PANEL_INFO(log_context, "Panel configuration changed; recreating inbound");
    }

    const bool replace_rules = !config_result.not_modified || transitioning;

    auto users_result = co_await panel.client->GetUserList(
        old_state ? old_state->users_etag : std::string{});
    ThrowIfStopping();
    std::optional<std::vector<api::UserInfo>> next_users;
    if (!users_result.Ok()) {
        if (transitioning) {
            throw std::runtime_error(ErrorMessage(
                users_result.error, users_result.error_msg));
        }
        LOG_PANEL_WARN(log_context, "Panel sync degraded: operation=pull resource=users reason={}",
                 users_result.error_msg.empty()
                    ? ErrorCodeToString(users_result.error)
                    : users_result.error_msg);
    } else if (users_result.not_modified) {
        if (!old_state) {
            throw std::runtime_error(
                "panel returned users not modified without a committed user snapshot");
        }
    } else {
        next_users = std::move(users_result.users);
    }

    if (!transitioning && config_result.not_modified && !next_users) {
        panel.state = users_result.Ok() ? PanelState::Ready : PanelState::Degraded;
        co_return;
    }
    auto candidate = std::make_shared<controller::NodeSnapshot>();
    candidate->config = fetched_config;
    candidate->config_etag = config_result.not_modified
        ? old_state->config_etag : std::move(config_result.etag);
    candidate->protocol = protocol;
    candidate->tag = tag;
    candidate->users = next_users ? std::move(*next_users) : old_state->users;
    candidate->users_etag = next_users
        ? std::move(users_result.etag) : old_state->users_etag;
    candidate->rules = config_result.not_modified
        ? old_state->rules : std::move(config_result.rules);
    const bool rebuild_settings = !old_state ||
        controller::NodeConfigChanged(old_state->config, candidate->config);
    if (rebuild_settings) {
        candidate->inbound = std::make_shared<const PreparedInbound>(PrepareInbound(
            controller::MapPanelInbound(panel.config, candidate->config, candidate->users)));
        candidate->outbound =
            std::make_shared<const proxyman::outbound::PreparedOutboundConfig>(
                BuildPanelAutoOutbound(tag, panel.config));
    } else if (next_users) {
        // Only the users changed: keep every prepared setting and rebuild the
        // authentication payload through the same per-protocol builder.
        auto inbound = std::make_shared<PreparedInbound>(*old_state->inbound);
        inbound->users = PrepareInboundUsers(
            inbound->build_request,
            controller::MapPanelUsers(candidate->config, candidate->users));
        candidate->inbound = std::move(inbound);
        candidate->outbound = old_state->outbound;
    } else {
        candidate->inbound = old_state->inbound;
        candidate->outbound = old_state->outbound;
    }
    controller::PreparedNodeChange change;
    change.replace_users = next_users.has_value() || transitioning;
    change.replace_rules = replace_rules;
    change.next = std::move(candidate);
    // Candidate data and authentication payloads are complete before
    // entering the transaction's first runtime mutation.
    // Hold fair admission before checking endpoints: another panel may
    // commit or retain recovery reservations while this one waits.
    auto lease = co_await node_mutations_.Acquire(panel.mutation);
    ThrowIfStopping();
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
    ThrowIfStopping();
    if (transitioning) {
        LOG_PANEL_INFO(log_context, "Panel configuration ready: tag={} replaced={}",
            tag, old_state ? "yes" : "no");
    }
    panel.state = users_result.Ok() ? PanelState::Ready : PanelState::Degraded;
}

void Controller::Impl::logPanelStatus(const PanelRuntime& panel) const {
    const PanelLogContext log_context{panel.config.Name, panel.config.APIHost,
        panel.config.NodeIDs.Front(), panel.config.NodeType};
    const std::string_view state_text = [&]() -> std::string_view {
        switch (panel.state) {
            case PanelState::Connecting: return "connecting";
            case PanelState::Ready: return "ready";
            case PanelState::Degraded: return "degraded";
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
        LOG_PANEL_INFO(log_context, "Panel status: state={} inbound={} protocol={}",
            state_text, runtime_text, panel.config.NodeType);
        return;
    }

    const auto& committed_state = *panel.node.committed;
    const auto& protocol = committed_state.protocol;
    const auto pull_interval = controller::PanelInterval(
        committed_state.config.PullInterval,
        defaults::kPanelPullInterval);
    const auto push_interval = controller::PanelInterval(
        committed_state.config.PushInterval,
        defaults::kPanelPushInterval);
    LOG_PANEL_INFO(log_context,
        "Panel status: state={} inbound={} protocol={} port={} network={} users={} rules={} pull={}s push={}s",
        state_text,
        runtime_text,
        protocol,
        committed_state.config.Port,
        ResolvedNodeNetwork(committed_state),
        committed_state.users.size(),
        committed_state.rules.size(),
        pull_interval.count(),
        push_interval.count());
}

