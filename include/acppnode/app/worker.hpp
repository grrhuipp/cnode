#pragma once

#include "acppnode/common.hpp"
#include "acppnode/infra/config.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/dns/dns_service.hpp"
#include "acppnode/geo/geodata.hpp"
#include "acppnode/protocol/sniff_config.hpp"
#include "acppnode/protocol/outbound.hpp"
#include "acppnode/protocol/vmess/vmess_protocol.hpp"
#include "acppnode/protocol/trojan/trojan_protocol.hpp"
#include "acppnode/protocol/shadowsocks/shadowsocks_protocol.hpp"
#include "acppnode/panel/v2board_panel.hpp"
#include "acppnode/router/router.hpp"
#include "acppnode/app/session_handler.hpp"
#include "acppnode/handlers/inbound_handler.hpp"
#include "acppnode/protocol/shadowsocks/ss_udp_inbound.hpp"

#include <atomic>
#include <functional>
#include <memory>
#include <unordered_map>
#include <vector>

namespace acpp {

// ============================================================================
// Worker - 工作线程上下文（SO_REUSEPORT 架构：每 Worker 独立 AcceptLoop）
//
// 线程模型：
//   热路径  — accept → spawn → session → relay，完全在 Worker 线程，zero cross-thread
//   冷路径  — 面板同步通过 net::post / cobalt::spawn(worker_exec) 序列化到 Worker 线程
//
// 所有 public *Async 方法均线程安全（内部 net::post 到 Worker io_context）。
// Worker 私有数据结构（acceptors_、listener_contexts_、local_traffic_ 等）
// 只在 Worker io_context 上访问，无需任何锁。
// ============================================================================
class Worker {
public:
    Worker(uint32_t id, net::io_context& io_context,
           const Config& config, ShardedStats& global_stats,
           geo::GeoManager* geo_manager = nullptr);
    ~Worker();

    // ── 基本访问 ─────────────────────────────────────────────────────────────

    [[nodiscard]] uint32_t Id() const noexcept { return id_; }
    [[nodiscard]] net::any_io_executor GetExecutor() { return io_context_.get_executor(); }
    [[nodiscard]] net::io_context& GetIoContext() { return io_context_; }
    [[nodiscard]] StatsShard& Stats() { return global_stats_.GetShard(id_); }
    [[nodiscard]] IDnsService* GetDnsService() { return dns_service_.get(); }
    [[nodiscard]] OutboundManager* GetOutboundManager() { return outbound_manager_.get(); }
    [[nodiscard]] vmess::VMessUserManager& GetUserManager() { return user_manager_; }
    [[nodiscard]] const vmess::VMessUserManager& GetUserManager() const { return user_manager_; }
    [[nodiscard]] trojan::TrojanUserManager& GetTrojanUserManager() { return trojan_user_manager_; }
    [[nodiscard]] const trojan::TrojanUserManager& GetTrojanUserManager() const { return trojan_user_manager_; }
    [[nodiscard]] ss::SsUserManager& GetSsUserManager() { return ss_user_manager_; }
    [[nodiscard]] const ss::SsUserManager& GetSsUserManager() const { return ss_user_manager_; }

    [[nodiscard]] UDPSessionManager& GetUDPSessionManager() { return *udp_session_manager_; }

    // 活跃连接数（atomic，供 stats 读取，近似值）
    [[nodiscard]] uint32_t GetActiveConnectionCount() const noexcept {
        return active_connections_.load(std::memory_order_relaxed);
    }

    // ── 监听管理（线程安全，内部 net::post 到 Worker 线程）─────────────────

    // 添加监听：SO_REUSEPORT bind，为该 tag 启动一个独立 AcceptLoop
    void AddListenerAsync(PortBinding binding);

    // 停止监听：关闭该 tag 对应的监听 socket，接收循环自然退出
    void RemoveListenerAsync(std::string tag);

    // 添加 UDP 监听（同端口 UDP socket，SO_REUSEPORT）
    // handler 封装所有协议细节（SS AEAD 解密、ban 检查、认证失败记录）
    void AddUdpListenerAsync(PortBinding binding,
                             std::unique_ptr<ss::SsUdpInboundHandler> handler);

    // 注册监听上下文 + 协议处理器（线程安全）
    void RegisterListenerAsync(ListenerContext ctx,
                               std::shared_ptr<IInboundHandler> handler);

    // 注销监听上下文（线程安全）
    void UnregisterListenerAsync(std::string tag);

    // ── Per-Worker 流量统计（无锁，仅 Worker 线程写）────────────────────────

    struct UserTraffic {
        uint64_t upload   = 0;
        uint64_t download = 0;
    };

    // ── 跨线程数据收集（供面板同步协程 cobalt::spawn 到 Worker 线程后调用）──

    // 收集并清空指定 tag 的用户流量（在 Worker 线程执行，无竞争）
    cobalt::task<std::unordered_map<int64_t, UserTraffic>>
        CollectTrafficTask(std::string tag);

    // 收集指定 tag 的在线用户 ID（在 Worker 线程执行，无竞争）
    // 协议类型由 listener_contexts_[tag].protocol 自动判断，无需外部传入
    cobalt::task<std::vector<int64_t>>
        CollectOnlineUsersTask(std::string tag);

    // Worker 热路径写入（仅 Worker 线程调用）
    void AddUserTraffic(const std::string& tag, int64_t user_id,
                        uint64_t upload, uint64_t download) {
        if (user_id <= 0) return;
        auto& t = local_traffic_[tag][user_id];
        t.upload   += upload;
        t.download += download;
    }

    // ── 在线用户（仅 Worker 线程调用）──────────────────────────────────────

    [[nodiscard]] std::vector<int64_t> GetOnlineUserIds(
        const std::string& tag, const std::string& protocol) const {
        if (protocol == "trojan") return trojan_user_manager_.GetOnlineUserIds(tag);
        if (protocol == "shadowsocks") return ss_user_manager_.GetOnlineUserIds(tag);
        return user_manager_.GetOnlineUserIds(tag);
    }

    // ── 内存统计（近似，主线程 stats_coro 读取）──────────────────────────────

    struct MemoryStats {
        size_t dns_entries          = 0;
        size_t dns_estimated_bytes  = 0;
        size_t udp_sessions         = 0;
        size_t udp_estimated_bytes  = 0;
        size_t vmess_users          = 0;
        size_t trojan_users         = 0;
        size_t users_estimated_bytes = 0;
        size_t total_estimated_bytes = 0;
    };
    [[nodiscard]] MemoryStats GetMemoryStats() const;

private:
    // ── 初始化 ──────────────────────────────────────────────────────────────
    void InitDnsService();
    void InitUDPSessionManager();
    void InitOutbounds();
    void InitRouter();

    // ── 监听（仅在 Worker io_context 上调用）────────────────────────────────

    // SO_REUSEPORT bind + spawn AcceptLoop（Worker 线程调用）
    void StartListening(PortBinding binding);

    // 关闭 acceptor，结束 AcceptLoop（Worker 线程调用）
    void StopListening(const std::string& tag);

    // 关闭 UDP socket、注销回包回调并清理客户端会话（Worker 线程调用）
    void StopUdpListening(const std::string& tag);

    // 注销指定 tag 下所有 UDP 客户端会话的回调并释放状态（Worker 线程调用）
    void CleanupUdpClientSessions(const std::string& tag);

    // 每个 tag 一个独立的 accept 协程
    cobalt::task<void> AcceptLoop(std::string tag);

    // 处理已 accept 的连接（spawn 出去的 per-connection 协程）
    cobalt::task<void> ProcessReceivedConnection(
        tcp::socket socket, tcp::endpoint remote_ep, std::string tag);

    // UDP 监听（Worker 线程调用）：bind SO_REUSEPORT UDP socket + spawn UdpReceiveLoop
    void StartUdpListening(PortBinding binding,
                           std::unique_ptr<ss::SsUdpInboundHandler> handler);

    // 通用 UDP 接收循环（协议无关，通过 IUdpInboundHandler 委托）
    cobalt::task<void> UdpReceiveLoop(std::string tag);

    // ── 成员 ────────────────────────────────────────────────────────────────

    uint32_t           id_;
    net::io_context&   io_context_;
    const Config&      config_;
    ShardedStats&      global_stats_;
    geo::GeoManager*   geo_manager_;

    std::atomic<uint32_t> active_connections_{0};

    // Worker 私有：只在 Worker io_context 上访问，无锁
    std::unordered_map<std::string, tcp::acceptor>              acceptors_;
    std::unordered_map<std::string, ListenerContext>            listener_contexts_;
    // shared_ptr：ListenerContext 中的 inbound_handler 与此 map 共享所有权
    std::unordered_map<std::string, std::shared_ptr<IInboundHandler>> inbound_handlers_;

    // UDP：每个 tag 一个 UDP socket（SO_REUSEPORT）
    std::unordered_map<std::string, std::shared_ptr<udp::socket>> udp_sockets_;

    // UDP：每个 tag 对应的协议处理器（直接持有具体类型，无虚调用开销）
    std::unordered_map<std::string, std::unique_ptr<ss::SsUdpInboundHandler>> udp_inbound_handlers_;

    // UDP 客户端会话（Cone 模式：每个客户端 IP:port 维持一个出站 UDPSession）
    struct UdpClientSession {
        UDPDialResult udp_dial;
        uint64_t     callback_id   = 0;
        int64_t      user_id       = 0;
        std::string  fixed_outbound;  // 固定出站（静态入站用）
        std::chrono::steady_clock::time_point last_active;
    };
    // tag → (client_endpoint_str → session)
    std::unordered_map<std::string,
        std::unordered_map<std::string, UdpClientSession>>       udp_client_sessions_;

    // Per-Worker 用户流量（无锁）：tag → (user_id → traffic)
    std::unordered_map<std::string,
        std::unordered_map<int64_t, UserTraffic>>               local_traffic_;

    // 活跃会话追踪（无锁，仅 Worker 线程访问）
    // 用于 CollectTrafficTask 实时读取活跃连接的流量增量
    struct ActiveSession {
        const SessionContext* ctx;         // 协程栈上的 ctx，relay 期间有效
        uint64_t last_reported_up = 0;    // 上次收集时的 bytes_up 快照
        uint64_t last_reported_down = 0;  // 上次收集时的 bytes_down 快照
    };
    std::unordered_map<uint64_t, ActiveSession> active_sessions_; // conn_id → session

    std::unique_ptr<IDnsService>       dns_service_;
    std::unique_ptr<UDPSessionManager> udp_session_manager_;
    std::unique_ptr<OutboundManager>  outbound_manager_;
    std::unique_ptr<Router>            router_;
    std::unique_ptr<SessionHandler>    session_handler_;

    vmess::VMessUserManager   user_manager_;
    trojan::TrojanUserManager trojan_user_manager_;
    ss::SsUserManager         ss_user_manager_;
};

}  // namespace acpp
