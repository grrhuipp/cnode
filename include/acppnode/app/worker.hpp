#pragma once

#include "acppnode/app/rate_limiter_fwd.hpp"
#include "acppnode/app/worker_mailbox.hpp"
#include "acppnode/common/asio_types.hpp"

#include <cstdint>
#include <future>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

namespace proxyman::inbound {
struct BuildRequest;
struct ReceiverSettings;
}
namespace proxyman::outbound {
struct PreparedOutboundConfig;
}
namespace geo {
class GeoManager;
}
namespace app::dns {
class DNSWorker;
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
// Worker - 同构运行时边界（SO_REUSEPORT：每 Worker 独立 accept）
//
// 每个 Worker 持有同一套 live 能力，由 RuntimeState 统一构造和启动。
// 热路径只在所属 io_context 上运行。跨线程控制面只能经有界 mailbox 投递。
// ============================================================================
class Worker {
public:
    Worker(uint32_t id, net::io_context& io_context,
           const WorkerRuntimeConfig& runtime_config, StatsShard& stats,
           app::dns::DNSWorker& dns_worker,
           geo::GeoManager* geo_manager = nullptr);
    ~Worker();

    // ── 基本访问 ─────────────────────────────────────────────────────────────

    [[nodiscard]] uint32_t Id() const noexcept { return id_; }

    // Cross-thread control-plane entry. Full mailbox throws WorkerMailboxFull.
    // *Task methods themselves must still run on this Worker's executor.
    template <typename T>
    net::awaitable<T> PostTask(net::awaitable<T> task) {
        return mailbox_->Post(std::move(task));
    }
    template <typename T>
    std::future<T> PostForFuture(net::awaitable<T> task) {
        return mailbox_->PostForFuture(std::move(task));
    }

    // Static startup transaction. Must run on this Worker's executor before
    // inbound registration; failures propagate through the startup future.
    net::awaitable<void> StartRuntimeTask();

    // ── 监听管理（必须在所属 Worker 上执行；跨线程经 PostTask）──────────

    // 动态控制面使用：必须在 Worker executor 上执行，并返回真实 bind 结果。
    net::awaitable<bool> AddListenerTask(PortBinding binding);

    // 注册 receiver settings + 协议处理器。Task 必须在 Worker executor 上执行。
    net::awaitable<bool> RegisterInboundTask(
        ConnectionLimiterPtr limiter,
        proxyman::inbound::BuildRequest req,
        proxyman::inbound::ReceiverSettings receiver);

    // 添加 UDP 监听（同端口 UDP socket，SO_REUSEPORT）。协议 handler 在
    // Worker 线程内构造，避免跨线程触碰 Worker-local validator / allocator。
    net::awaitable<bool> AddUdpListenerTask(
        PortBinding binding,
        ConnectionLimiterPtr limiter,
        proxyman::inbound::BuildRequest req);

    // 动态出站：XrayR Controller 面板节点 addOutbound/removeOutbound。
    net::awaitable<void> AddOutboundTask(
        proxyman::outbound::PreparedOutboundConfig config);
    net::awaitable<void> RemoveOutboundTask(std::string tag);

    // 动态控制面使用：必须在所属 Worker 上执行，完成后才返回。
    net::awaitable<void> UnregisterListenerTask(std::string tag);

    net::awaitable<void> UpdateRuleTask(
        std::string tag,
        std::vector<rule::DetectRule> rules);

    // ── Per-Worker 流量统计（无锁，仅 Worker 线程写）────────────────────────

    using UserTraffic = app::UserTraffic;
    using UserTrafficSnapshot = app::UserTrafficSnapshot;

    // ── 数据收集（经 PostTask 投递到所属 Worker 后调用）──

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
    net::awaitable<void> CollectHeapTask(bool force);

private:
    struct ListenerSlot;
    struct ListenerState;
    struct RuntimeState;

    [[nodiscard]] bool RegisterInboundOnWorkerThread(
        ConnectionLimiterPtr limiter,
        const proxyman::inbound::BuildRequest& req,
        proxyman::inbound::ReceiverSettings receiver);

    void UnregisterListenerOnWorkerThread(std::string_view tag);

    void AddOutboundOnWorkerThread(
        proxyman::outbound::PreparedOutboundConfig config);
    void RemoveOutboundOnWorkerThread(std::string_view tag);

    [[nodiscard]] MemoryStats GetMemoryStats() const;

    // ── 成员 ────────────────────────────────────────────────────────────────

    uint32_t              id_;
    std::unique_ptr<RuntimeState> runtime_;
    std::unique_ptr<WorkerMailbox> mailbox_;

};

}  // namespace acpp
