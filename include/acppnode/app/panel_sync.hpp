#pragma once

// ============================================================================
// panel_sync.hpp — 面板同步管理器
//
// 职责：
//   - 定期（60s）拉取面板节点配置与用户列表
//   - 根据节点配置动态创建/销毁入站监听
//   - 收集各 Worker 用户流量并上报面板
//   - 收集在线用户列表并上报面板
//   - 每个节点首次用户同步完成后独立启用 IP ban 追踪
//
// 线程模型：
//   - 运行在 main_ctx（主线程）
//   - 跨 Worker 数据访问通过 cobalt::spawn(worker_exec) 序列化到 Worker 线程
//   - 无 mutex / lock
// ============================================================================

#include "acppnode/common.hpp"

namespace acpp {

class ConnectionLimiter;
struct PanelConfig;

// ============================================================================
// PanelSyncManager
// ============================================================================
class PanelSyncManager {
public:
    PanelSyncManager(net::io_context& io_context,
                     std::vector<std::unique_ptr<Worker>>& workers,
                     std::shared_ptr<ConnectionLimiter> limiter);

    // 注册面板（必须在 Start() 之前调用）
    void AddPanel(std::unique_ptr<IPanel> panel, const PanelConfig& panel_config);

    // 启动同步循环（首次立即同步，之后每 60s 循环）
    void Start();

    // 停止同步循环
    void Stop();

    // 供统计输出使用：读取已知节点的概要信息（主线程只读，近似值）
    struct NodeStatsInfo {
        std::string panel_name;
        int         node_id      = 0;
        std::string network;
        uint16_t    port         = 0;
        size_t      total_users  = 0;
        size_t      online_users = 0;
        uint64_t    bytes_up     = 0;   // 自启动累计上行
        uint64_t    bytes_down   = 0;   // 自启动累计下行
    };
    [[nodiscard]] std::vector<NodeStatsInfo> GetNodeStats() const;

    // 已注册的 inbound tag 列表（供关闭时批量 RemoveListenerAsync 使用）
    [[nodiscard]] const std::vector<std::string>& RegisteredTags() const {
        return registered_tags_;
    }

private:
    // ── 同步循环 ─────────────────────────────────────────────────────────────
    cobalt::task<void> SyncLoop();
    cobalt::task<void> SyncNode(IPanel* panel, int node_id);
    cobalt::task<void> DoSync();

    // ── 数据收集（跨 Worker，lock-free）─────────────────────────────────────
    cobalt::task<std::vector<TrafficData>> CollectTraffic(const std::string& tag);
    cobalt::task<std::vector<int64_t>>     CollectOnlineUsers(const std::string& tag,
                                                               const std::string& protocol);

    // ── 入站生命周期 ─────────────────────────────────────────────────────────
    cobalt::task<void> StopInbounds(const std::string& tag);
    cobalt::task<bool> CreateInbounds(IPanel* panel, int node_id,
                                      const NodeConfig& node_config);

    // ── 用户管理 ─────────────────────────────────────────────────────────────
    void UpdateUsers(const std::string& panel_name, int node_id,
                     const std::vector<PanelUser>& panel_users);
    void ClearUsers(const std::string& tag, const std::string& protocol);

    // ── 配置变更检测 ─────────────────────────────────────────────────────────
    bool ConfigChanged(const NodeConfig& a, const NodeConfig& b) const;

    // ── 成员 ─────────────────────────────────────────────────────────────────
    net::io_context&                       io_context_;
    std::vector<std::unique_ptr<Worker>>&  workers_;
    std::shared_ptr<ConnectionLimiter>     limiter_;

    std::vector<std::unique_ptr<IPanel>>              panels_;
    std::map<IPanel*, PanelConfig>                    panel_configs_;
    std::vector<std::pair<IPanel*, int>>              panel_nodes_;
    std::map<std::pair<IPanel*, int>, NodeConfig>     node_configs_;
    std::map<std::pair<IPanel*, int>, bool>           inbound_started_;
    // 节点统计（合并 user_count/online_count/traffic 到单一 map，减少查询次数）
    struct NodeStats {
        size_t   user_count    = 0;
        size_t   online_count  = 0;
        uint64_t bytes_up      = 0;
        uint64_t bytes_down    = 0;
    };
    std::map<std::string, NodeStats>                  node_stats_;
    std::vector<std::string>                          registered_tags_;

    bool running_ = false;
};

}  // namespace acpp
