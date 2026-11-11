#include "service/controller/controller.hpp"

#include "app/worker_batch.hpp"
#include "common/monitor_loop.hpp"
#include "service/controller/node_transaction.hpp"
#include "service/controller/traffic_journal.hpp"

#include "api/api.hpp"
#include "app/prepared_inbound.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/proxyman/outbound/handler.hpp"
#include "app/worker.hpp"
#include "common/asio_types.hpp"
#include "core/constants.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config.hpp"
#include "infra/json.hpp"
#include "infra/log.hpp"
#include "transport/internet/http_headers.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <format>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace controller {

namespace {

[[nodiscard]] StreamSettings MapPanelStreamSettings(
    const PanelConfig& panel_config,
    const api::NodeInfo& node_config) {
    StreamSettings stream;
    stream.network_mode = ParseNetworkMode(node_config.TransportProtocol);
    stream.http.force_http2 = EqualsAsciiCI(node_config.TransportProtocol, "h2");

    // The panel permits local TLS termination; the protocol's registered
    // requirement and node setting decide whether this inbound uses it.
    if (node_config.EnableReality) {
        stream.security_mode = SecurityMode::Reality;
        stream.reality = node_config.Reality;
    } else if (ShouldEnableInboundTls(panel_config, node_config)) {
        stream.security_mode = SecurityMode::Tls;
        stream.tls.cert_file = panel_config.TLSCert;
        stream.tls.key_file = panel_config.TLSKey;
        stream.tls.server_name = node_config.TLSServerName;
        stream.tls.pem = panel_config.TLSPem;
    }

    // Fill the transport sub-config first: normalization derives cached
    // fields (gRPC request path, XHTTP path, Host) from it.
    switch (stream.network_mode) {
    case NetworkMode::Ws:
        stream.ws.path = node_config.Path;
        if (!node_config.Host.empty()) {
            stream.ws.headers.emplace(
                LowerAscii("Host"),
                node_config.Host);
        }
        break;
    case NetworkMode::HttpUpgrade:
        stream.http_upgrade.path = node_config.Path;
        stream.http_upgrade.host = node_config.Host;
        break;
    case NetworkMode::Http:
        stream.http.path = node_config.Path;
        stream.http.host = node_config.Host;
        break;
    case NetworkMode::Grpc:
        stream.grpc.service_name = node_config.ServiceName;
        stream.grpc.authority = node_config.Host;
        break;
    case NetworkMode::XHttp:
        stream.xhttp.path = node_config.Path;
        stream.xhttp.host = node_config.Host;
        break;
    default:
        break;
    }

    stream = NormalizeStreamSettings(stream);
    if (stream.network_mode == NetworkMode::Unsupported ||
        stream.security_mode == SecurityMode::Unsupported) {
        throw std::invalid_argument("panel inbound has unsupported stream settings");
    }
    return stream;
}
}  // namespace

std::vector<InboundUserSpec> MapPanelUsers(
    const api::NodeInfo& node_config,
    std::span<const api::UserInfo> users) {
    std::vector<InboundUserSpec> specs;
    specs.reserve(users.size());
    for (const auto& user : users) {
        specs.push_back(InboundUserSpec{
            .user_id = user.UID,
            .email = user.Email,
            .credential = user.UUID,
            .flow = user.Flow.empty() ? node_config.Flow : user.Flow,
            .speed_limit = user.SpeedLimit,
            .device_limit = user.DeviceLimit,
        });
    }
    return specs;
}

InboundSpec MapPanelInbound(
    const PanelConfig& panel_config,
    const api::NodeInfo& node_config,
    std::span<const api::UserInfo> users) {
    const int node_id = panel_config.NodeIDs.Front();
    std::string tag = naming::BuildPanelNodeTag(
        panel_config.Name, node_id, node_config.NodeType, node_config.Port);
    std::vector<std::string> all_tags{tag, std::string(constants::protocol::kNode)};
    routing::OutboundSelectionPolicy outbound_policy{routing::RouteWithFallback(tag)};
    return InboundSpec{
        .tag = std::move(tag),
        .all_tags = std::move(all_tags),
        .accounting_key = naming::BuildPanelNodeAccountingKey(panel_config.Name, node_id),
        .protocol = node_config.NodeType,
        .listen = panel_config.ListenIP,
        .port = node_config.Port,
        .proxy_protocol = panel_config.ProxyProtocol,
        .settings = InboundProtocolSettings{
            .method = node_config.CypherMethod,
            .identity_password = node_config.ShadowsocksServerKey,
            .ss2022_user_key = Ss2022UserKey::UuidDerived,
            .padding_scheme = node_config.PaddingScheme,
            .vless_decryption = std::string(constants::protocol::kNone),
            .hysteria_up_mbps = node_config.HysteriaUpMbps,
            .hysteria_down_mbps = node_config.HysteriaDownMbps,
        },
        .users = MapPanelUsers(node_config, users),
        .stream_settings = MapPanelStreamSettings(panel_config, node_config),
        .sniffing = SniffConfig{},
        .outbound_policy = std::move(outbound_policy),
    };
}
}  // namespace controller

struct Controller::Impl : std::enable_shared_from_this<Controller::Impl> {
    struct PanelRuntime;
    class NodeRuntime;
    Impl(net::io_context& io_context,
         const std::vector<std::unique_ptr<Worker>>& workers);

    void AddPanel(std::unique_ptr<api::API> panel, const PanelConfig& panel_config);
    void Start();
    void RequestStop() noexcept;
    net::awaitable<void> AsyncJoin();
    net::awaitable<void> FlushTraffic();

    [[nodiscard]] std::vector<Controller::NodeStatsInfo> GetNodeStats() const;

    net::awaitable<void> PanelSyncLoop(PanelRuntime& panel);
    net::awaitable<void> PanelStatusLoop(const PanelRuntime& panel) const;
    net::awaitable<void> NodeInfoMonitor(PanelRuntime& panel);
    void LogPanelStatus(const PanelRuntime& panel) const;
    net::awaitable<void> UserInfoMonitor(PanelRuntime& panel,
                                         std::string tag);

    net::awaitable<void> CollectTraffic(PanelRuntime& panel,
                                        bool* appended_out = nullptr);
    net::awaitable<controller::OnlineSnapshot>
    GetOnlineSnapshot(const std::string& tag);

    net::io_context&                       io_context_;
    const std::vector<std::unique_ptr<Worker>>&  workers_;
    bool stopping_ = false;
    controller::NodeMutationGate node_mutations_;
    std::unique_ptr<controller::JournalExecutor> journal_executor_;

    enum class PanelState {
        Connecting,
        Ready,
        Degraded,
        Unavailable,
    };

    struct NodeStats {
        size_t   online_count = 0;
        uint64_t bytes_up     = 0;
        uint64_t bytes_down   = 0;
    };
    struct PanelRuntime {
        PanelRuntime(std::unique_ptr<api::API> api, const PanelConfig& source,
                     controller::NodeMutationGate& gate, net::any_io_executor executor);

        const std::unique_ptr<api::API> client;
        const PanelConfig config;
        const int node_id;
        const PanelLogContext log_context;
        const std::string accounting_key;
        PanelState state = PanelState::Connecting;
        controller::NodeState node;
        controller::NodeMutationGate::Participant mutation;
        NodeStats stats;
        std::unique_ptr<controller::TrafficJournal> traffic_journal;
        // Active loops retain Impl, which owns these address-stable entities.
        std::weak_ptr<MonitorLoop> sync_loop;
        std::weak_ptr<MonitorLoop> status_loop;
    };
    std::vector<std::unique_ptr<PanelRuntime>> panels_;
};
namespace {


[[nodiscard]] proxyman::outbound::PreparedOutboundConfig BuildPanelAutoOutbound(
    const std::string& tag,
    const PanelConfig& panel_config) {
    const auto strategy = panel_config.EnableDNS
        ? panel_config.DNSType
        : proxy::freedom::outbound::DomainStrategy::AsIs;
    infra::OutboundSourceConfig source{
        .tag = tag,
        .protocol = std::string(constants::protocol::kFreedom),
        .settings = infra::FreedomSettings{.domain_strategy = strategy},
        .stream_settings = {},
        // The panel sendIP is the auto outbound Handler's sendThrough.
        .send_through = panel_config.SendIP,
        .passthrough = false,
    };
    auto prepared = proxyman::outbound::PrepareOutboundConfig(source);
    if (!prepared) {
        throw std::logic_error("failed to prepare panel auto freedom outbound");
    }
    return std::move(*prepared);
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
        return state.inbound->receiver.stream_settings.NetworkName();
    }
    return state.config.TransportProtocol.empty()
        ? constants::protocol::kTcp
        : std::string_view(state.config.TransportProtocol);
}

}  // namespace

// The concrete cold-path boundary for all-Worker mutations. Each asynchronous
// operation joins every started Worker task before it completes or throws.
class Controller::Impl::NodeRuntime {
public:
    NodeRuntime(net::io_context& io_context,
                const std::vector<std::unique_ptr<Worker>>& workers,
                PanelRuntime& panel,
                const bool& stopping)
        : io_context_(io_context), workers_(workers), panel_(panel),
          stopping_(stopping) {}

    net::awaitable<void> RemoveInbound(const std::string& tag) {
        co_await PostToEachWorker(io_context_.get_executor(), workers_, stopping_,
            [&tag](Worker& worker, size_t) {
                return worker.PostTask(worker.UnregisterListenerTask(tag));
            });
    }

    net::awaitable<void> RemoveOutbound(const std::string& tag) {
        co_await PostToEachWorker(io_context_.get_executor(), workers_, stopping_,
            [&tag](Worker& worker, size_t) {
                return worker.PostCall([&worker, tag] { worker.RemoveOutbound(tag); });
            });
    }

    net::awaitable<void> AddOutbound(
        const proxyman::outbound::PreparedOutboundConfig& prepared) {
        co_await PostToEachWorker(io_context_.get_executor(), workers_, stopping_,
            [&prepared](Worker& worker, size_t) {
                return worker.PostCall([&worker, config = prepared]() mutable {
                    worker.AddOutbound(std::move(config));
                });
            });
    }

    net::awaitable<bool> AddInbound(const PreparedInbound& inbound) {
        const auto& log_context = panel_.log_context;
        const auto& tag = inbound.binding.tag;

        std::exception_ptr publish_failure;
        try {
            // Every Worker attempts the install even after another failed, so
            // the single RemoveInbound below sees one consistent outcome.
            const auto installed = co_await PostToEachWorkerInOrder(workers_, stopping_,
                [&inbound](Worker& worker, size_t) {
                    return worker.PostTask(InstallInbound(worker, inbound));
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
        ThrowIfStopping(stopping_);

        LOG_PANEL_INFO(log_context, "inbound ready: tag={} port={} protocol={} network={} workers={} accept=SO_REUSEPORT",
                       tag, inbound.binding.port, inbound.binding.protocol,
                       inbound.receiver.stream_settings.NetworkName(), workers_.size());
        co_return true;
    }

    net::awaitable<void> UpdateRules(
        const std::string& tag,
        std::shared_ptr<const std::vector<rule::DetectRule>> new_rule_list) {
        co_await PostToEachWorker(io_context_.get_executor(), workers_, stopping_,
            [&tag, &new_rule_list, last = workers_.size() - 1](Worker& worker, size_t index) {
                auto rules = index == last ? std::move(new_rule_list) : new_rule_list;
                return worker.PostCall([&worker, tag = tag, rules = std::move(rules)]() mutable {
                    worker.UpdateRule(tag, std::move(rules));
                });
            });
    }

    net::awaitable<void> RecoverUsers() {
        return ::RollbackUsers(
            io_context_.get_executor(), workers_, panel_.node.user_recovery, stopping_);
    }

    net::awaitable<void> ClearUsers(const std::string& tag, const std::string& protocol) {
        co_await RecoverUsers();
        const auto user_protocol = proxyman::inbound::RegisteredUserProtocol(protocol);
        if (!user_protocol) throw std::logic_error("node has no registered user protocol");
        co_await ::PublishUsers(io_context_.get_executor(), workers_,
            proxyman::inbound::UserStore::PrepareClearUsers(*user_protocol, tag),
            panel_.node.user_recovery, stopping_);
    }

    net::awaitable<void> ApplyUsers(
        const std::string& tag, const proxyman::inbound::UserSet& users) {
        co_await RecoverUsers();
        co_await ::PublishUsers(io_context_.get_executor(), workers_,
            proxyman::inbound::UserStore::PrepareUsers(tag, users),
            panel_.node.user_recovery, stopping_);
    }

    [[nodiscard]] bool IsStopping() const noexcept { return stopping_; }

private:
    net::io_context& io_context_;
    const std::vector<std::unique_ptr<Worker>>& workers_;
    PanelRuntime& panel_;
    const bool& stopping_;
};
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
    return impl_->AsyncJoin();
}

net::awaitable<void> Controller::FlushTraffic() {
    return impl_->FlushTraffic();
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
    , node_id(config.NodeIDs.Front())
    , log_context{config.Name, config.APIHost, node_id, config.NodeType}
    , accounting_key(naming::BuildPanelNodeAccountingKey(config.Name, node_id))
    , mutation(gate, std::move(executor), node) {
    traffic_journal = std::make_unique<controller::TrafficJournal>(config);
    const auto unknown = traffic_journal->UnknownCount();
    if (unknown != 0) {
        LOG_PANEL_ERROR(log_context, "Traffic accounting requires reconciliation: unknown_records={} directory={}",
                        unknown, traffic_journal->Directory().string());
    }
}

void Controller::Impl::AddPanel(std::unique_ptr<api::API> panel,
                                const PanelConfig& panel_config) {
    ThrowIfStopping(stopping_);
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
                panel->config.Name, panel->node_id,
                kind == LoopKind::Sync ? "sync" : "status");
            auto self = shared_from_this();
            auto loop = std::make_shared<MonitorLoop>(
                io_context_.get_executor(), name,
                [self, panel, kind] {
                    return kind == LoopKind::Sync
                        ? self->PanelSyncLoop(*panel) : self->PanelStatusLoop(*panel);
                },
                [self, panel, kind](std::string_view loop_name, std::exception_ptr failure) {
                    if (self->stopping_ && !failure) return;
                    if (kind == LoopKind::Sync) {
                        panel->state = PanelState::Unavailable;
                    }
                    if (!failure) {
                        LOG_PANEL_WARN(panel->log_context, "Panel monitor stopped unexpectedly: loop={}", loop_name);
                        return;
                    }
                    try {
                        std::rethrow_exception(failure);
                    } catch (const std::exception& error) {
                        LOG_PANEL_ERROR(panel->log_context, "Panel monitor failed: loop={} reason={}", loop_name, error.what());
                    } catch (...) {
                        LOG_PANEL_ERROR(panel->log_context, "Panel monitor failed: loop={} reason=unknown exception", loop_name);
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
        info.node_id     = panel->node_id;
        info.network      = std::string(ResolvedNodeNetwork(state));
        info.port       = state.config.Port;
        info.total_users  = state.users ? state.users->size() : 0;
        info.online_users = panel->stats.online_count;
        info.bytes_up     = panel->stats.bytes_up;
        info.bytes_down   = panel->stats.bytes_down;
        result.push_back(std::move(info));
    }
    return result;
}

net::awaitable<void> Controller::Impl::PanelSyncLoop(
    PanelRuntime& panel) {
    using Clock = std::chrono::steady_clock;
    const auto& log_context = panel.log_context;
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
                co_await NodeInfoMonitor(panel);
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
                    co_await UserInfoMonitor(panel, panel.node.committed->tag);
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

net::awaitable<void> Controller::Impl::PanelStatusLoop(const PanelRuntime& panel) const {
    using Clock = std::chrono::steady_clock;
    constexpr auto interval = std::chrono::seconds(defaults::kPanelStatusLogInterval);
    auto next_status = Clock::now();
    net::steady_timer timer(io_context_);
    for (;;) {
        if (stopping_) co_return;
        // Read the last committed state on the controller executor. No snapshot
        // reference crosses the wait, and no network request delays this loop.
        LogPanelStatus(panel);
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

net::awaitable<void> Controller::Impl::NodeInfoMonitor(PanelRuntime& panel) {
    const int node_id = panel.node_id;
    const auto& panel_name = panel.config.Name;
    const auto& log_context = panel.log_context;

    NodeRuntime runtime(io_context_, workers_, panel, stopping_);

    // One pull attempt is made for each scheduler invocation.
    // Cleanup depends only on retained local snapshots, so a failing or
    // unavailable panel cannot indefinitely retain orphan resources.
    if (panel.node.HasPendingCleanup()) {
        auto lease = co_await node_mutations_.Acquire(panel.mutation);
        ThrowIfStopping(stopping_);
        co_await controller::CleanPendingNodeRuntime(runtime, panel.node);
    }
    ThrowIfStopping(stopping_);
    const auto old_state = panel.node.committed;
    auto config_result = co_await panel.client->GetNodeInfo(
        old_state ? old_state->config_etag : std::string{});
    ThrowIfStopping(stopping_);
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
    ThrowIfStopping(stopping_);
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
    candidate->config = config_result.not_modified
        ? old_state->config : std::move(*config_result.node_info);
    candidate->config_etag = config_result.not_modified
        ? old_state->config_etag : std::move(config_result.etag);
    candidate->tag = tag;
    candidate->users = next_users
        ? std::make_shared<const std::vector<api::UserInfo>>(std::move(*next_users))
        : old_state->users;
    candidate->users_etag = next_users
        ? std::move(users_result.etag) : old_state->users_etag;
    candidate->rules = config_result.not_modified
        ? old_state->rules
        : std::make_shared<const std::vector<rule::DetectRule>>(
              std::move(config_result.rules));
    const bool rebuild_settings = !old_state ||
        controller::NodeConfigChanged(old_state->config, candidate->config);
    if (rebuild_settings) {
        candidate->inbound = std::make_shared<const PreparedInbound>(PrepareInbound(
            controller::MapPanelInbound(panel.config, candidate->config, *candidate->users)));
        candidate->outbound =
            std::make_shared<const proxyman::outbound::PreparedOutboundConfig>(
                BuildPanelAutoOutbound(tag, panel.config));
    } else if (next_users) {
        // Only the users changed: keep every prepared setting and rebuild the
        // authentication payload through the same per-protocol builder.
        auto inbound = std::make_shared<PreparedInbound>(*old_state->inbound);
        inbound->users = PrepareInboundUsers(
            inbound->build_request,
            controller::MapPanelUsers(candidate->config, *candidate->users));
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
    ThrowIfStopping(stopping_);
    if (panel.node.HasPendingCleanup()) {
        throw std::logic_error("node admission requires completed local cleanup");
    }
    for (const auto& other : panels_) {
        if (other.get() != &panel && other->node.ReservesPort(change.next->config.Port) &&
            other->config.ListenIP.Overlaps(panel.config.ListenIP)) {
            throw std::runtime_error(std::format(
                "panel listener endpoint conflict owner={}/{} port={}",
                other->config.Name, other->node_id, change.next->config.Port));
        }
    }
    co_await controller::ApplyNodeChange(runtime, panel.node, std::move(change));
    ThrowIfStopping(stopping_);
    if (transitioning) {
        LOG_PANEL_INFO(log_context, "Panel configuration ready: tag={} replaced={}",
            tag, old_state ? "yes" : "no");
    }
    panel.state = users_result.Ok() ? PanelState::Ready : PanelState::Degraded;
}

void Controller::Impl::LogPanelStatus(const PanelRuntime& panel) const {
    const auto& log_context = panel.log_context;
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
    const auto& protocol = committed_state.config.NodeType;
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
        committed_state.users ? committed_state.users->size() : 0,
        committed_state.rules ? committed_state.rules->size() : 0,
        pull_interval.count(),
        push_interval.count());
}

net::awaitable<void>
Controller::Impl::CollectTraffic(PanelRuntime& panel, bool* appended_out) {
    // Do not abandon a durable append before its matching Worker commit.
    // Shutdown joins this critical section before taking its final snapshot.
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    // Only this panel loop may snapshot/commit its accounting key. The disk
    // executor never touches Worker-owned state and has bounded admission.
    for (const auto& worker : workers_) {
        auto* w = worker.get();
        auto snapshot = co_await w->PostCall([w, &panel] {
            return w->SnapshotTraffic(panel.accounting_key);
        });
        if (snapshot.empty()) continue;
        std::exception_ptr append_failure;
        try {
            co_await journal_executor_->Run([&panel, &snapshot] {
                panel.traffic_journal->Append(snapshot);
                return true;
            });
        } catch (...) {
            append_failure = std::current_exception();
        }
        if (append_failure) {
            // The snapshot token may be the last owner after a connection has
            // closed. Return it to the Worker ledger before unwinding.
            try {
                co_await w->PostCall([w, &panel, &snapshot] {
                    w->RollbackTraffic(panel.accounting_key, snapshot);
                });
            } catch (...) {
                panel.traffic_journal->Suspend();
                throw;
            }
            std::rethrow_exception(append_failure);
        }
        if (appended_out) *appended_out = true;
        // A successful append is durable. A failed commit must suspend further
        // collection, otherwise the same in-memory delta could be persisted twice.
        try {
            co_await w->PostCall([w, &panel, &snapshot] {
                w->CommitTraffic(panel.accounting_key, snapshot);
            });
        } catch (...) {
            panel.traffic_journal->Suspend();
            throw;
        }
    }
}

net::awaitable<void> Controller::Impl::FlushTraffic() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    std::exception_ptr failure;
    for (const auto& panel : panels_) {
        try {
            co_await CollectTraffic(*panel);
        } catch (const std::exception& error) {
            if (!failure) failure = std::current_exception();
            LOG_PANEL_ERROR(panel->log_context, "Final traffic persistence failed: {}", error.what());
        } catch (...) {
            if (!failure) failure = std::current_exception();
            LOG_PANEL_ERROR(panel->log_context, "Final traffic persistence failed: unknown error");
        }
    }
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<controller::OnlineSnapshot>
Controller::Impl::GetOnlineSnapshot(const std::string& tag) {
    auto per_worker = co_await PostToEachWorker(io_context_.get_executor(), workers_, stopping_,
        [&tag](Worker& worker, size_t) {
            return worker.PostCall([&worker, t = std::string_view(tag)] {
                return worker.GetOnlineDevices(t);
            });
        });
    ThrowIfStopping(stopping_);

    size_t total_online = 0;
    for (const auto& online : per_worker) {
        total_online += online.size();
    }

    std::vector<OnlineDevice> devices;
    devices.reserve(total_online);
    for (auto& online : per_worker) {
        devices.insert(devices.end(),
                       std::make_move_iterator(online.begin()),
                       std::make_move_iterator(online.end()));
    }
    co_return controller::BuildOnlineSnapshot(std::move(devices));
}

net::awaitable<void> Controller::Impl::UserInfoMonitor(PanelRuntime& panel,
                                                       std::string tag) {
    const auto& log_context = panel.log_context;

    ThrowIfStopping(stopping_);
    // Drain never-attempted crash/backpressure records before collecting more;
    // otherwise a full journal of ready records could never free its capacity.
    auto& ns = panel.stats;
    controller::TrafficJournal::Batch batch;
    bool traffic_ok = false;
    bool journal_ok = true;
    try {
        batch = co_await journal_executor_->Run([&panel] {
            return panel.traffic_journal->Prepare();
        });
        if (batch.records.empty()) {
            // reset_cancellation_state in CollectTraffic applies to its entire
            // coroutine thread, not just that function. Join a shielded child so a
            // durable append always reaches CommitTraffic without disabling stop
            // cancellation for this loop's subsequent panel requests.
            bool appended = false;
            try {
                co_await net::co_spawn(io_context_,
                    CollectTraffic(panel, &appended),
                    net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
            } catch (const std::exception& e) {
                if (stopping_) throw;
                journal_ok = false;
                LOG_PANEL_WARN(log_context, "Traffic collection failed: operation=push reason={}", e.what());
            }
            ThrowIfStopping(stopping_);
            if (appended) {
                batch = co_await journal_executor_->Run([&panel] {
                    return panel.traffic_journal->Prepare();
                });
            }
        }
        ThrowIfStopping(stopping_);
        if (!batch.records.empty()) {
            co_await journal_executor_->Run([&panel, &batch] {
                panel.traffic_journal->Begin(batch);
                return true;
            });
        }
        const auto& traffic_data = batch.traffic;
        uint64_t batch_up = 0;
        uint64_t batch_down = 0;
        for (const auto& td : traffic_data) {
            batch_up += td.Upload;
            batch_down += td.Download;
        }
        if (!batch.records.empty() || journal_ok) {
            try {
                // Marked unknown durably BEFORE any network transmission. Even non-2xx
                // may follow partial server-side accounting; never retry these deltas.
                // An empty push still clears the panel's previous online-user count.
                traffic_ok = co_await panel.client->ReportUserTraffic(traffic_data);
            } catch (const std::exception& e) {
                if (stopping_) {
                    if (!traffic_ok && !batch.records.empty()) {
                        LOG_PANEL_ERROR(log_context, "Traffic accounting API acceptance unknown: records={} retained without retry; directory={}",
                                        batch.records.size(), panel.traffic_journal->Directory().string());
                    }
                    throw;
                }
                LOG_PANEL_WARN(log_context, "Traffic report failed: operation=push reason={}", e.what());
            }
        }
        if (!traffic_ok && !batch.records.empty()) {
            LOG_PANEL_ERROR(log_context, "Traffic accounting API acceptance unknown: records={} retained without retry; directory={}",
                            batch.records.size(), panel.traffic_journal->Directory().string());
        }
        if (traffic_ok) {
            ns.bytes_up += batch_up;
            ns.bytes_down += batch_down;
            if (!batch.records.empty()) {
                co_await journal_executor_->Run([&panel, &batch] {
                    panel.traffic_journal->Acknowledge(batch);
                    return true;
                });
            }
        }
        ThrowIfStopping(stopping_);
        if (traffic_ok) {
            LOG_PANEL_DEBUG(log_context, "Traffic report accepted: users={}", traffic_data.size());
        }
    } catch (const std::exception& e) {
        if (stopping_) throw;
        journal_ok = false;
        LOG_PANEL_ERROR(log_context, "Traffic journal failed: operation=push reason={}", e.what());
    }

    auto online = co_await GetOnlineSnapshot(tag);
    ns.online_count = online.user_count;
    const auto& traffic_data = batch.traffic;

    ThrowIfStopping(stopping_);
    bool online_ok = false;
    try {
        online_ok = co_await panel.client->ReportNodeOnlineUsers(online.entries);
        ThrowIfStopping(stopping_);
    } catch (const std::exception& e) {
        if (stopping_) throw;
        LOG_PANEL_WARN(log_context, "Online report failed: operation=push reason={}", e.what());
    }

    const bool report_ok = traffic_ok && journal_ok && online_ok;
    LOG_PANEL_INFO(log_context,
        "Panel report: state={} operation=push traffic={} traffic_users={} online={} online_users={} devices={}",
        report_ok ? "ok" : "degraded",
        (traffic_ok && journal_ok) ? "ok" : "failed",
        traffic_data.size(),
        online_ok ? "ok" : "failed",
        online.user_count,
        online.entries.size());
    co_return;
}

