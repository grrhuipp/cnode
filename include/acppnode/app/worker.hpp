#pragma once

#include "acppnode/app/rate_limiter_fwd.hpp"
#include "acppnode/common/asio_types.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

namespace proxyman::inbound {
struct BuildRequest;
struct ReceiverSettings;
class UdpHandler;
}
namespace proxyman::outbound {
struct PreparedOutboundConfig;
}
namespace geo {
class GeoManager;
}
namespace app {
struct UserTraffic;
struct UserTrafficSnapshot;
}
class Inbound;
struct OnlineDevice;
struct PortBinding;
struct StatsShard;
struct RoutingConfig;
struct WorkerRuntimeConfig;
struct WorkerMemoryStats;
struct WorkerRuntimeStatsSnapshot;
namespace rule {
struct DetectRule;
struct DetectResult;
}

// ============================================================================
// Worker - 工作线程上下文（SO_REUSEPORT 架构：每 Worker 独立 accept 协程）
//
// 线程模型：
//   热路径  — accept → spawn → session → relay，完全在 Worker 线程，zero cross-thread
//   冷路径  — 面板同步通过异步投递序列化到 Worker 线程
//
// 所有 public *Async 方法均线程安全（内部 net::post 到 Worker io_context）。
// Worker 私有数据结构只在 Worker io_context 上访问，无需任何锁。
// 只在 Worker io_context 上访问，无需任何锁。
// ============================================================================
class Worker {
public:
    Worker(uint32_t id, net::io_context& io_context,
           const WorkerRuntimeConfig& runtime_config, StatsShard& stats,
           geo::GeoManager* geo_manager = nullptr);
    ~Worker();

    // ── 基本访问 ─────────────────────────────────────────────────────────────

    [[nodiscard]] uint32_t Id() const noexcept { return id_; }
    [[nodiscard]] net::io_context::executor_type GetExecutor();

    // ── 监听管理（线程安全，内部 net::post 到 Worker 线程）─────────────────

    // 动态控制面使用：必须在 Worker executor 上执行，并返回真实 bind 结果。
    net::awaitable<bool> AddListenerTask(PortBinding binding);

    // 进程关闭冷路径：在 Worker 线程关闭全部监听和 UDP 会话，并等待取消事件入队。
    net::awaitable<void> ShutdownTask();

    // 注册 receiver settings + 协议处理器。Task 必须在 Worker executor 上执行。
    net::awaitable<bool> RegisterInboundTask(
        std::string protocol,
        ConnectionLimiterPtr limiter,
        proxyman::inbound::BuildRequest req,
        proxyman::inbound::ReceiverSettings receiver);

    // 添加 UDP 监听（同端口 UDP socket，SO_REUSEPORT）。协议 handler 在
    // Worker 线程内构造，避免跨线程触碰 Worker-local validator / allocator。
    net::awaitable<bool> AddUdpListenerTask(
        PortBinding binding,
        std::string protocol,
        ConnectionLimiterPtr limiter,
        proxyman::inbound::BuildRequest req);

    // 动态出站（线程安全）：XrayR Controller 面板节点 addOutbound/removeOutbound。
    net::awaitable<bool> AddOutboundTask(
        proxyman::outbound::PreparedOutboundConfig config);
    net::awaitable<void> RemoveOutboundTask(std::string tag);

    // 动态控制面使用：必须在 Worker executor 上执行，完成后才返回。
    net::awaitable<void> UnregisterListenerTask(std::string tag);

    net::awaitable<void> UpdateRuleTask(
        std::string tag,
        std::vector<rule::DetectRule> rules);

    // ── Per-Worker 流量统计（无锁，仅 Worker 线程写）────────────────────────

    using UserTraffic = app::UserTraffic;
    using UserTrafficSnapshot = app::UserTrafficSnapshot;

    // ── 跨线程数据收集（供面板同步协程投递到 Worker 线程后调用）──

    // 收集并清空指定 tag 的用户流量（在 Worker 线程执行，无竞争）
    net::awaitable<UserTrafficSnapshot> GetTrafficTask(std::string tag);

    // 收集指定 tag 的在线设备（在 Worker 线程执行，无竞争）
    // 协议类型由 inbound handler 的 ReceiverSettings 自动判断，无需外部传入
    net::awaitable<std::vector<OnlineDevice>>
        GetOnlineDeviceTask(std::string tag);

    net::awaitable<std::vector<rule::DetectResult>>
        GetDetectResultTask(std::string tag);

    // Worker 热路径写入（仅 Worker 线程调用）
    void AddUserTraffic(std::string_view tag, int64_t user_id,
                        uint64_t upload, uint64_t download);

    // ── 运行时统计（通过 CollectRuntimeStatsTask 投递到 Worker 线程读取）──

    using MemoryStats = WorkerMemoryStats;
    using RuntimeStatsSnapshot = WorkerRuntimeStatsSnapshot;

    net::awaitable<RuntimeStatsSnapshot> CollectRuntimeStatsTask() const;

private:
    struct ListenerSlot;
    struct ListenerState;
    struct RuntimeState;

    [[nodiscard]] bool RegisterInboundOnWorkerThread(
        std::string_view protocol,
        ConnectionLimiterPtr limiter,
        const proxyman::inbound::BuildRequest& req,
        proxyman::inbound::ReceiverSettings receiver);

    void UnregisterListenerOnWorkerThread(std::string_view tag);

    [[nodiscard]] bool AddOutboundOnWorkerThread(
        proxyman::outbound::PreparedOutboundConfig config);
    void RemoveOutboundOnWorkerThread(std::string_view tag);

    [[nodiscard]] MemoryStats GetMemoryStats() const;

    // ── 成员 ────────────────────────────────────────────────────────────────

    uint32_t              id_;
    std::unique_ptr<RuntimeState> runtime_;

};

}  // namespace acpp
