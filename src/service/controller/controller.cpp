#include "controller_impl.hpp"

#include "acppnode/app/worker.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/log.hpp"

#include <algorithm>
#include <chrono>
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

const std::vector<std::string>& Controller::RegisteredTags() const {
    return impl_->RegisteredTags();
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

            for (auto& task : tasks) {
                co_await std::move(task);
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

            std::string protocol = naming::ResolveProtocolOrDefault(fetched_config.NodeType);
            std::string tag = naming::BuildPanelNodeTag(
                panel_name, protocol, fetched_config.Port);

            bool need_create   = (node_configs_.find(panel) == node_configs_.end());
            bool need_recreate = false;

            if (!need_create && !inbound_started_[panel]) {
                need_create = true;
            } else if (!need_create && ConfigChanged(node_configs_[panel], fetched_config)) {
                need_recreate = true;
                LOG_CONSOLE("node config_changed panel={} node={} action=recreate",
                            panel_name, node_id);
            }

            if (need_recreate) {
                std::string old_protocol =
                    naming::ResolveProtocolOrDefault(node_configs_[panel].NodeType);
                std::string old_tag = naming::BuildPanelNodeTag(
                    panel_name, old_protocol, node_configs_[panel].Port);
                if (old_tag != tag) {
                    co_await removeInbound(old_tag);
                    co_await removeOutbound(old_tag);
                    clearUsers(old_tag, old_protocol);
                    user_lists_.erase(panel);
                    inbound_started_[panel] = false;
                } else {
                    co_await removeOutbound(old_tag);
                    LOG_CONSOLE("node config_changed panel={} node={} action=update_in_place",
                                panel_name, node_id);
                }
            }

            node_configs_[panel] = fetched_config;

            auto rules_result = co_await panel->GetNodeRule();
            if (!rules_result.Ok()) {
                LOG_WARN("Panel {}/{}: GetNodeRule failed: {}",
                         panel_name, node_id,
                         rules_result.error_msg.empty()
                            ? ErrorCodeToString(rules_result.error)
                            : rules_result.error_msg);
            } else if (!rules_result.not_modified) {
                UpdateRule(tag, rules_result.rules);
            }

            auto users_result = co_await panel->GetUserList();
            if (users_result.Ok()) {
                if (!users_result.not_modified) {
                    syncUserList(
                        panel, tag, protocol, fetched_config, users_result.users,
                        need_create || need_recreate);
                } else if (need_create || need_recreate) {
                    if (auto cached_users = user_lists_.find(panel);
                            cached_users != user_lists_.end()) {
                        syncUserList(
                            panel, tag, protocol, fetched_config,
                            cached_users->second, true);
                    }
                }
                if (ban_tracking_tags_.insert(tag).second) {
                    for (const auto& worker : workers_) {
                        worker->EnableBanTrackingAsync(tag);
                    }
                    LOG_CONSOLE("node ban_tracking=enabled panel={} node={} tag={}",
                                panel_name, node_id, tag);
                }
            } else {
                LOG_WARN("Panel {}/{}: user sync skipped: {}",
                         panel_name, node_id,
                         users_result.error_msg.empty()
                            ? ErrorCodeToString(users_result.error)
                            : users_result.error_msg);
            }

            if (need_create || need_recreate) {
                (void)co_await addOutbound(panel, fetched_config, tag);
                bool ok = co_await addInbound(panel, fetched_config);
                inbound_started_[panel] = ok;
                if (!ok) {
                    LOG_WARN("Node {}/{} bind failed, will retry", panel_name, node_id);
                }
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

bool Controller::Impl::ConfigChanged(const api::NodeInfo& a, const api::NodeInfo& b) const {
    return a.Port != b.Port || a.NodeType != b.NodeType
        || a.TransportProtocol != b.TransportProtocol || a.Path != b.Path
        || a.Host != b.Host || a.EnableTLS != b.EnableTLS
        || a.TLSServerName != b.TLSServerName || a.TLSCert != b.TLSCert
        || a.TLSKey != b.TLSKey || a.CypherMethod != b.CypherMethod;
}

}  // namespace acpp
