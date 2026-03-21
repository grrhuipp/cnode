#include "acppnode/app/panel_sync.hpp"

#include "acppnode/protocol/inbound_registry.hpp"
#include "acppnode/transport/stream_settings.hpp"
#include "acppnode/protocol/sniff_config.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/session_handler.hpp"

#include <algorithm>
#include <format>
#include <unordered_map>
#include <unordered_set>

using namespace acpp;

// ============================================================================
// 构造函数
// ============================================================================
PanelSyncManager::PanelSyncManager(net::io_context& io_context,
                                    std::vector<std::unique_ptr<Worker>>& workers,
                                    ConnectionLimiterPtr limiter)
    : io_context_(io_context)
    , workers_(workers)
    , limiter_(std::move(limiter)) {}

// ============================================================================
// 公开接口
// ============================================================================

void PanelSyncManager::AddPanel(std::unique_ptr<IPanel> panel,
                                 const PanelConfig& panel_config) {
    auto* p = panel.get();
    panels_.push_back(std::move(panel));
    panel_configs_[p] = panel_config;
    for (int nid : panel_config.node_ids) {
        panel_nodes_.push_back({p, nid});
    }
}

void PanelSyncManager::Start() {
    running_ = true;
    cobalt::spawn(io_context_.get_executor(), SyncLoop(), net::detached);
}

void PanelSyncManager::Stop() { running_ = false; }

std::vector<PanelSyncManager::NodeStatsInfo> PanelSyncManager::GetNodeStats() const {
    std::vector<NodeStatsInfo> result;
    result.reserve(node_configs_.size());
    for (const auto& [key, cfg] : node_configs_) {
        NodeStatsInfo info;
        info.panel_name  = key.first->Name();
        info.node_id     = key.second;
        info.network     = cfg.network;
        info.port        = cfg.port;
        std::string ukey = std::format("{}-{}", info.panel_name, info.node_id);
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

// ============================================================================
// 同步循环
// ============================================================================

cobalt::task<void> PanelSyncManager::SyncLoop() {
    co_await DoSync();

    while (running_) {
        net::steady_timer timer(io_context_);
        timer.expires_after(std::chrono::seconds(60));
        (void)co_await timer.async_wait(net::as_tuple(cobalt::use_op));
        if (!running_) break;
        co_await DoSync();
    }
}

cobalt::task<void> PanelSyncManager::DoSync() {
    if (panel_nodes_.empty()) {
        co_return;
    }

    // 控制冷路径并发扇出，避免大量节点在同一秒同时触发 HTTP/TLS 握手，
    // 导致面板侧、DNS、证书校验与本进程内存出现瞬时尖峰。
    const size_t batch_size = std::min(
        panel_nodes_.size(),
        std::max<size_t>(workers_.size() * 2, 1));

    for (size_t offset = 0; offset < panel_nodes_.size(); offset += batch_size) {
        std::vector<cobalt::task<void>> tasks;
        tasks.reserve(std::min(batch_size, panel_nodes_.size() - offset));

        const size_t end = std::min(panel_nodes_.size(), offset + batch_size);
        for (size_t i = offset; i < end; ++i) {
            const auto& [panel, node_id] = panel_nodes_[i];
            tasks.push_back(SyncNode(panel, node_id));
        }

        co_await cobalt::join(tasks);
    }
}

cobalt::task<void> PanelSyncManager::SyncNode(IPanel* panel, int node_id) {
    constexpr int kMaxAttempts  = 4;
    constexpr int kRetryBaseSec = 5;
    auto key = std::make_pair(panel, node_id);
    std::string stats_key = std::format("{}-{}", panel->Name(), node_id);

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
                    std::string old_protocol = cfg_it->second.protocol.empty()
                                             ? "vmess" : cfg_it->second.protocol;
                    std::string old_tag = std::format("{}-{}-{}", panel->Name(), old_protocol, cfg_it->second.port);

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
                throw std::runtime_error(
                    config_result.error_msg.empty()
                        ? std::string(ErrorCodeToString(config_result.error))
                        : config_result.error_msg);
            }

            const NodeConfig& fetched_config = *config_result.config;

            std::string protocol = fetched_config.protocol.empty() ? "vmess" : fetched_config.protocol;
            std::string tag = std::format("{}-{}-{}", panel->Name(), protocol, fetched_config.port);

            bool need_create   = (node_configs_.find(key) == node_configs_.end());
            bool need_recreate = false;

            if (!need_create && !inbound_started_[key]) {
                need_create = true;
            } else if (!need_create && ConfigChanged(node_configs_[key], fetched_config)) {
                need_recreate = true;
                LOG_CONSOLE("Node {}/{} config changed, recreating", panel->Name(), node_id);
            }

            if (need_recreate) {
                std::string old_protocol = node_configs_[key].protocol.empty()
                                         ? "vmess" : node_configs_[key].protocol;
                std::string old_tag = std::format("{}-{}-{}", panel->Name(), old_protocol, node_configs_[key].port);
                if (old_tag != tag) {
                    co_await StopInbounds(old_tag);
                    ClearUsers(old_tag, old_protocol);
                    inbound_started_[key] = false;
                } else {
                    LOG_CONSOLE("Node {}/{} config changed, updating in place", panel->Name(), node_id);
                }
            }

            // 必须在 FetchUsers 之前存储配置：UpdateUsers 依赖 node_configs_
            // 来确定协议类型和 tag，否则首次同步时 node_configs_.find(key) 返回 end()
            // 导致 UpdateUsers 直接 return，用户不会被加载到 SharedStore
            node_configs_[key] = fetched_config;

            // 先拉取用户列表，确保 SharedStore 就绪后再开放端口
            // 避免启动时 listener 已接收连接但用户未加载导致全量认证失败
            auto users_result = co_await panel->FetchUsers(node_id);
            if (users_result.Ok()) {
                UpdateUsers(panel->Name(), node_id, users_result.users);
                // 该节点用户同步完成，启用 IP ban 追踪
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

            // ── 数据收集（跨 Worker，不涉及面板 HTTP）─────────────────
            auto traffic_data = co_await CollectTraffic(tag);
            {
                std::string ukey = std::format("{}-{}", panel->Name(), node_id);
                auto& ns = node_stats_[ukey];
                for (const auto& td : traffic_data) {
                    ns.bytes_up   += td.upload;
                    ns.bytes_down += td.download;
                }
            }

            auto online_users = co_await CollectOnlineUsers(tag, protocol);
            {
                std::string ukey = std::format("{}-{}", panel->Name(), node_id);
                node_stats_[ukey].online_count = online_users.size();
            }

            // ── 数据上报（各自独立 try-catch，互不阻塞）───────────────
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

// ============================================================================
// 数据收集
// ============================================================================

cobalt::task<std::vector<TrafficData>>
PanelSyncManager::CollectTraffic(const std::string& tag) {
    using TrafficMap = std::unordered_map<int64_t, Worker::UserTraffic>;
    std::vector<TrafficMap> per_worker(workers_.size());

    std::vector<cobalt::task<void>> tasks;
    tasks.reserve(workers_.size());
    for (size_t i = 0; i < workers_.size(); ++i) {
        tasks.push_back(
            [](Worker* w, const std::string& t, TrafficMap& out) -> cobalt::task<void> {
                out = co_await cobalt::spawn(
                    w->GetExecutor(), w->CollectTrafficTask(t), cobalt::use_op);
            }(workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await cobalt::join(tasks);

    size_t merged_hint = 0;
    for (const auto& traffic : per_worker) {
        merged_hint += traffic.size();
    }

    std::unordered_map<int64_t, TrafficData> merged;
    merged.reserve(merged_hint);
    for (const auto& traffic : per_worker) {
        for (const auto& [uid, t] : traffic) {
            auto& m   = merged[uid];
            m.user_id  = uid;
            m.upload  += t.upload;
            m.download += t.download;
        }
    }

    std::vector<TrafficData> result;
    result.reserve(merged.size());
    for (const auto& [uid, td] : merged) {
        if (td.upload > 0 || td.download > 0) {
            result.push_back(td);
        }
    }
    co_return result;
}

cobalt::task<std::vector<int64_t>>
PanelSyncManager::CollectOnlineUsers(const std::string& tag,
                                      const std::string& /*protocol*/) {
    std::vector<std::vector<int64_t>> per_worker(workers_.size());

    std::vector<cobalt::task<void>> tasks;
    tasks.reserve(workers_.size());
    for (size_t i = 0; i < workers_.size(); ++i) {
        tasks.push_back(
            [](Worker* w, const std::string& t,
               std::vector<int64_t>& out) -> cobalt::task<void> {
                out = co_await cobalt::spawn(
                    w->GetExecutor(), w->CollectOnlineUsersTask(t),
                    cobalt::use_op);
            }(workers_[i].get(), tag, per_worker[i])
        );
    }
    co_await cobalt::join(tasks);

    size_t total_online = 0;
    for (const auto& online : per_worker) {
        total_online += online.size();
    }

    std::unordered_set<int64_t> users;
    users.reserve(total_online);
    for (const auto& online : per_worker) {
        users.insert(online.begin(), online.end());
    }
    co_return std::vector<int64_t>(users.begin(), users.end());
}

// ============================================================================
// 入站生命周期
// ============================================================================

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
    std::string protocol = node_config.protocol.empty() ? "vmess" : node_config.protocol;
    std::string tag = std::format("{}-{}-{}", panel->Name(), protocol, node_config.port);
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
    ss.network = node_config.network.empty() ? "tcp" : node_config.network;

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
        ss.security      = "tls";
        ss.tls.cert_file = cert_file;
        ss.tls.key_file  = key_file;
    }

    if (ss.network == "ws") {
        ss.ws.path = node_config.path.empty() ? "/" : node_config.path;
        if (!node_config.host.empty()) ss.ws.headers["Host"] = node_config.host;
    }
    ss.RecomputeModes();

    SniffConfig sniff;
    sniff.enabled       = node_config.sniff_enabled;
    sniff.dest_override = node_config.dest_override;

    InboundBuildRequest req;
    req.tag      = tag;
    req.protocol = protocol;
    req.cipher_method = node_config.cipher.empty() ? "aes-256-gcm" : node_config.cipher;

    for (const auto& worker : workers_) {
        InboundProtocolDeps deps;
        deps.vmess_user_manager  = &worker->GetUserManager();
        deps.trojan_user_manager = &worker->GetTrojanUserManager();
        deps.ss_user_manager     = &worker->GetSsUserManager();
        deps.stats               = &worker->Stats();

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

        ListenerContext lc;
        lc.inbound_tag     = tag;
        // 面板入站 2 个标签：主标签 + "node"（路由隐式匹配用）
        lc.inbound_tags    = {tag, "node"};
        lc.protocol        = protocol;
        lc.stream_settings = ss;
        lc.sniff_config    = sniff;
        lc.proxy_protocol  = true;
        lc.limiter         = limiter_;

        worker->RegisterListenerAsync(std::move(lc), std::move(handler));
    }

    PortBinding binding;
    binding.port     = node_config.port;
    binding.protocol = protocol;
    binding.tag      = tag;
    binding.listen   = "0.0.0.0";

    for (const auto& worker : workers_) {
        worker->AddListenerAsync(binding);
        InboundProtocolDeps deps;
        deps.vmess_user_manager  = &worker->GetUserManager();
        deps.trojan_user_manager = &worker->GetTrojanUserManager();
        deps.ss_user_manager     = &worker->GetSsUserManager();
        deps.stats               = &worker->Stats();

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

// ============================================================================
// 用户管理
// ============================================================================

void PanelSyncManager::ClearUsers(const std::string& tag, const std::string& protocol) {
    auto& inbound_factory = InboundFactory::Instance();
    if (!inbound_factory.Has(protocol)) {
        return;
    }

    inbound_factory.ClearUsers(protocol, tag);
    for (const auto& worker : workers_) {
        InboundProtocolDeps deps;
        deps.vmess_user_manager  = &worker->GetUserManager();
        deps.trojan_user_manager = &worker->GetTrojanUserManager();
        deps.ss_user_manager     = &worker->GetSsUserManager();
        deps.stats               = &worker->Stats();
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
    std::string protocol = node_config.protocol.empty() ? "vmess" : node_config.protocol;
    std::string tag = std::format("{}-{}-{}", panel_name, protocol, node_config.port);

    std::string stats_key = std::format("{}-{}", panel_name, node_id);
    node_stats_[stats_key].user_count = panel_users.size();

    auto& inbound_factory = InboundFactory::Instance();
    if (!inbound_factory.Has(protocol)) {
        LOG_WARN("UpdateUsers: unsupported protocol '{}'", protocol);
        return;
    }

    inbound_factory.UpdatePanelUsers(protocol, tag, node_config, panel_users);
    for (const auto& worker : workers_) {
        InboundProtocolDeps deps;
        deps.vmess_user_manager  = &worker->GetUserManager();
        deps.trojan_user_manager = &worker->GetTrojanUserManager();
        deps.ss_user_manager     = &worker->GetSsUserManager();
        deps.stats               = &worker->Stats();
        inbound_factory.SyncWorkerUsers(protocol, deps, tag);
    }
}

// ============================================================================
// 配置变更检测
// ============================================================================

bool PanelSyncManager::ConfigChanged(const NodeConfig& a, const NodeConfig& b) const {
    return a.port != b.port || a.protocol != b.protocol
        || a.network != b.network || a.path != b.path
        || a.host != b.host || a.tls_enabled != b.tls_enabled
        || a.tls_sni != b.tls_sni || a.tls_cert != b.tls_cert
        || a.tls_key != b.tls_key || a.cipher != b.cipher;
}
