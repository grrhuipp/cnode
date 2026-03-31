#include "acppnode/app/panel_sync.hpp"

#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/session_handler.hpp"
#include "acppnode/app/worker.hpp"
#include "acppnode/core/naming.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/panel/v2board_panel.hpp"
#include "acppnode/protocol/inbound_registry.hpp"
#include "acppnode/protocol/sniff_config.hpp"
#include "acppnode/transport/stream_settings.hpp"

#include <algorithm>
#include <chrono>
#include <stdexcept>

namespace acpp {

namespace {

std::string ResolveNodeTag(const std::string& panel_name, const NodeConfig& config) {
    return naming::BuildPanelNodeTag(
        panel_name,
        naming::ResolveProtocolOrDefault(config.protocol),
        config.port);
}

}  // namespace

cobalt::task<void> PanelSyncManager::SyncNode(IPanel* panel, int node_id) {
    constexpr int kMaxAttempts  = defaults::kPanelSyncMaxAttempts;
    constexpr int kRetryBaseSec = defaults::kPanelSyncRetryBaseSeconds;
    auto key = std::make_pair(panel, node_id);
    std::string stats_key = naming::BuildPanelNodeStatsKey(panel->Name(), node_id);

    for (int attempt = 0; attempt < kMaxAttempts; ++attempt) {
        if (attempt > 0) {
            const int delay = kRetryBaseSec * attempt;
            LOG_WARN("Panel {}/{}: retry {}/{} in {}s",
                     panel->Name(), node_id, attempt, kMaxAttempts - 1, delay);
            net::steady_timer timer(io_context_);
            timer.expires_after(std::chrono::seconds(delay));
            (void)co_await timer.async_wait(net::as_tuple(cobalt::use_op));
            if (!running_) co_return;
        }

        try {
            auto config_result = co_await panel->FetchNodeConfig(node_id);
            if (config_result.missing) {
                auto cfg_it = node_configs_.find(key);
                if (cfg_it != node_configs_.end()) {
                    std::string old_protocol =
                        naming::ResolveProtocolOrDefault(cfg_it->second.protocol);
                    std::string old_tag = naming::BuildPanelNodeTag(
                        panel->Name(), old_protocol, cfg_it->second.port);

                    co_await StopInbounds(old_tag);
                    ClearUsers(old_tag, old_protocol);
                    node_configs_.erase(cfg_it);
                    inbound_started_.erase(key);
                    node_stats_.erase(stats_key);

                    LOG_CONSOLE("Node {}/{} removed, stopped inbound {}",
                                panel->Name(), node_id, old_tag);
                }
                co_return;
            }

            if (!config_result.Ok()) {
                throw std::runtime_error(ErrorMessage(config_result.error, config_result.error_msg));
            }

            const NodeConfig& fetched_config = *config_result.config;

            std::string protocol = naming::ResolveProtocolOrDefault(fetched_config.protocol);
            std::string tag = naming::BuildPanelNodeTag(
                panel->Name(), protocol, fetched_config.port);

            bool need_create   = (node_configs_.find(key) == node_configs_.end());
            bool need_recreate = false;

            if (!need_create && !inbound_started_[key]) {
                need_create = true;
            } else if (!need_create && ConfigChanged(node_configs_[key], fetched_config)) {
                need_recreate = true;
                LOG_CONSOLE("Node {}/{} config changed, recreating", panel->Name(), node_id);
            }

            if (need_recreate) {
                std::string old_protocol =
                    naming::ResolveProtocolOrDefault(node_configs_[key].protocol);
                std::string old_tag = naming::BuildPanelNodeTag(
                    panel->Name(), old_protocol, node_configs_[key].port);
                if (old_tag != tag) {
                    co_await StopInbounds(old_tag);
                    ClearUsers(old_tag, old_protocol);
                    inbound_started_[key] = false;
                } else {
                    LOG_CONSOLE("Node {}/{} config changed, updating in place", panel->Name(), node_id);
                }
            }

            node_configs_[key] = fetched_config;

            auto users_result = co_await panel->FetchUsers(node_id);
            if (users_result.Ok()) {
                if (!users_result.not_modified) {
                    UpdateUsers(panel->Name(), node_id, users_result.users);
                }
                if (!limiter_->IsBanTrackingEnabledForTag(tag)) {
                    limiter_->EnableBanTrackingForTag(tag);
                    LOG_CONSOLE("Node {}/{}: IP ban tracking enabled for {}",
                                panel->Name(), node_id, tag);
                }
            } else {
                LOG_WARN("Panel {}/{}: user sync skipped: {}",
                         panel->Name(), node_id,
                         users_result.error_msg.empty()
                            ? ErrorCodeToString(users_result.error)
                            : users_result.error_msg);
            }

            if (need_create || need_recreate) {
                bool ok = co_await CreateInbounds(panel, node_id, fetched_config);
                inbound_started_[key] = ok;
                if (!ok) {
                    LOG_WARN("Node {}/{} bind failed, will retry", panel->Name(), node_id);
                }
            }

            auto traffic_data = co_await CollectTraffic(tag);
            {
                std::string ukey = naming::BuildPanelNodeStatsKey(panel->Name(), node_id);
                auto& ns = node_stats_[ukey];
                for (const auto& td : traffic_data) {
                    ns.bytes_up   += td.upload;
                    ns.bytes_down += td.download;
                }
            }

            auto online_users = co_await CollectOnlineUsers(tag, protocol);
            {
                std::string ukey = naming::BuildPanelNodeStatsKey(panel->Name(), node_id);
                node_stats_[ukey].online_count = online_users.size();
            }

            if (!traffic_data.empty()) {
                try {
                    bool ok = co_await panel->ReportTraffic(node_id, traffic_data);
                    if (ok) {
                        LOG_DEBUG("Panel {}/{}: reported traffic for {} users",
                                 panel->Name(), node_id, traffic_data.size());
                    }
                } catch (const std::exception& e) {
                    LOG_WARN("Panel {}/{}: ReportTraffic failed: {}",
                             panel->Name(), node_id, e.what());
                }
            }

            if (!online_users.empty()) {
                try {
                    co_await panel->ReportOnline(node_id, online_users);
                } catch (const std::exception& e) {
                    LOG_WARN("Panel {}/{}: ReportOnline failed: {}",
                             panel->Name(), node_id, e.what());
                }
            }

            co_return;

        } catch (const std::exception& e) {
            if (attempt + 1 < kMaxAttempts) {
                LOG_WARN("Panel {}/{}: attempt {}/{} failed: {}",
                         panel->Name(), node_id, attempt + 1, kMaxAttempts, e.what());
            } else {
                LOG_ERROR("Panel {}/{}: all {} attempts failed: {}",
                          panel->Name(), node_id, kMaxAttempts, e.what());
            }
        }
    }
}

cobalt::task<void> PanelSyncManager::StopInbounds(const std::string& tag) {
    for (const auto& worker : workers_) {
        worker->UnregisterListenerAsync(tag);
    }
    registered_tags_.erase(
        std::remove(registered_tags_.begin(), registered_tags_.end(), tag),
        registered_tags_.end());
    co_return;
}

cobalt::task<bool> PanelSyncManager::CreateInbounds(IPanel* panel, int node_id,
                                                      const NodeConfig& node_config) {
    std::string protocol = naming::ResolveProtocolOrDefault(node_config.protocol);
    std::string tag = ResolveNodeTag(panel->Name(), node_config);
    auto& inbound_factory = InboundFactory::Instance();

    if (!inbound_factory.Has(protocol)) {
        LOG_WARN("Node {}/{}: unsupported inbound protocol '{}'",
                 panel->Name(), node_id, protocol);
        co_return false;
    }

    const PanelConfig* panel_cfg = nullptr;
    if (auto it = panel_configs_.find(panel); it != panel_configs_.end())
        panel_cfg = &it->second;

    StreamSettings ss;
    ss.network = node_config.network.empty()
        ? std::string(constants::protocol::kTcp)
        : node_config.network;

    std::string cert_file  = node_config.tls_cert;
    std::string key_file   = node_config.tls_key;
    bool tls_enable        = node_config.tls_enabled;

    if (panel_cfg) {
        if (!panel_cfg->tls_enable) {
            tls_enable = false;
        } else {
            if (!panel_cfg->tls_cert.empty()) cert_file = panel_cfg->tls_cert;
            if (!panel_cfg->tls_key.empty())  key_file  = panel_cfg->tls_key;
        }
    }

    if (tls_enable) {
        ss.security      = std::string(constants::protocol::kTls);
        ss.tls.cert_file = cert_file;
        ss.tls.key_file  = key_file;
    }

    if (ss.network == constants::protocol::kWs) {
        ss.ws.path = node_config.path.empty()
            ? std::string(constants::binding::kRootPath)
            : node_config.path;
        if (!node_config.host.empty()) ss.ws.headers["Host"] = node_config.host;
    }
    ss.RecomputeModes();

    SniffConfig sniff;
    sniff.enabled       = node_config.sniff_enabled;
    sniff.dest_override = node_config.dest_override;

    InboundBuildRequest req;
    req.tag      = tag;
    req.protocol = protocol;
    req.cipher_method = node_config.cipher.empty()
        ? std::string(constants::protocol::kAes256Gcm)
        : node_config.cipher;

    for (const auto& worker : workers_) {
        auto deps = worker->GetInboundProtocolDeps();

        auto handler = inbound_factory.CreateTcpHandler(
            protocol, deps, limiter_, req);
        if (!handler) {
            LOG_WARN("Node {}/{}: create inbound handler failed, protocol={}",
                     panel->Name(), node_id, protocol);
            for (const auto& w : workers_) {
                w->UnregisterListenerAsync(tag);
            }
            co_return false;
        }

        auto lc = MakeListenerContext(
            tag,
            std::vector<std::string>{tag, std::string(constants::protocol::kNode)},
            protocol,
            ss,
            sniff,
            limiter_);

        worker->RegisterListenerAsync(std::move(lc), std::move(handler));
    }

    auto binding = MakePortBinding(
        node_config.port,
        protocol,
        tag,
        std::string(constants::network::kAnyIpv4));

    for (const auto& worker : workers_) {
        worker->AddListenerAsync(binding);
        auto deps = worker->GetInboundProtocolDeps();

        auto udp_handler = inbound_factory.CreateUdpHandler(
            protocol, deps, limiter_, req);
        if (udp_handler) {
            worker->AddUdpListenerAsync(binding, std::move(udp_handler));
        }
    }

    if (std::find(registered_tags_.begin(), registered_tags_.end(), tag)
            == registered_tags_.end()) {
        registered_tags_.push_back(tag);
    }

    LOG_CONSOLE("Inbound {} on port {} ({}): {} workers (SO_REUSEPORT)",
                tag, node_config.port, protocol, workers_.size());
    co_return true;
}

void PanelSyncManager::ClearUsers(const std::string& tag, const std::string& protocol) {
    auto& inbound_factory = InboundFactory::Instance();
    if (!inbound_factory.Has(protocol)) {
        return;
    }

    inbound_factory.ClearUsers(protocol, tag);
    for (const auto& worker : workers_) {
        auto deps = worker->GetInboundProtocolDeps();
        inbound_factory.SyncWorkerUsers(protocol, deps, tag);
    }
}

void PanelSyncManager::UpdateUsers(const std::string& panel_name, int node_id,
                                    const std::vector<PanelUser>& panel_users) {
    auto key = std::make_pair(
        std::find_if(panels_.begin(), panels_.end(),
            [&](const auto& p) { return p->Name() == panel_name; })->get(),
        node_id);

    auto it = node_configs_.find(key);
    if (it == node_configs_.end()) return;

    const auto& node_config = it->second;
    std::string protocol = naming::ResolveProtocolOrDefault(node_config.protocol);
    std::string tag = naming::BuildPanelNodeTag(panel_name, protocol, node_config.port);

    std::string stats_key = naming::BuildPanelNodeStatsKey(panel_name, node_id);
    node_stats_[stats_key].user_count = panel_users.size();

    auto& inbound_factory = InboundFactory::Instance();
    if (!inbound_factory.Has(protocol)) {
        LOG_WARN("UpdateUsers: unsupported protocol '{}'", protocol);
        return;
    }

    inbound_factory.UpdatePanelUsers(protocol, tag, node_config, panel_users);
    for (const auto& worker : workers_) {
        auto deps = worker->GetInboundProtocolDeps();
        inbound_factory.SyncWorkerUsers(protocol, deps, tag);
    }
}

bool PanelSyncManager::ConfigChanged(const NodeConfig& a, const NodeConfig& b) const {
    return a.port != b.port || a.protocol != b.protocol
        || a.network != b.network || a.path != b.path
        || a.host != b.host || a.tls_enabled != b.tls_enabled
        || a.tls_sni != b.tls_sni || a.tls_cert != b.tls_cert
        || a.tls_key != b.tls_key || a.cipher != b.cipher;
}

}  // namespace acpp
