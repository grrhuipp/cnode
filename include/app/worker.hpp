#pragma once

#include "app/worker_mailbox.hpp"
#include "app/user_store.hpp"
#include "app/outbound_handler.hpp"
#include "infra/config_types.hpp"
#include "common/asio_types.hpp"
#include <cstdint>
#include <atomic>
#include <exception>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace geo {
class GeoDatabase;
}
namespace common {

struct OnlineDevice;
struct DetectRule;

}  // namespace common
namespace app {

class GroupCoordinator;
struct BuildRequest;
struct ReceiverSettings;
struct PreparedOutboundConfig;
class DNSWorker;
class Router;
struct PortBinding;
struct StatsShard;
struct WorkerRuntimeConfig {
    infra::TimeoutsConfig timeouts;
    infra::LimitsConfig limits;
    infra::RoutingConfig routing;
    std::vector<PreparedOutboundConfig> outbounds;
    std::shared_ptr<const app::Router> router;
    uint32_t workers = 0;
    uint32_t pressure_threshold = 1;
    uint32_t pressure_idle_timeout = 0;
};
struct WorkerRuntimeStatsSnapshot;

// ============================================================================
// Worker - 同构运行时边界（SO_REUSEPORT：每 Worker 独立 accept）
//
// 每个 Worker 持有同一套 live 能力，由 RuntimeState 统一构造和启动。
// 热路径只在所属 io_context 上运行。跨线程控制面只能经有界 mailbox 投递。
// ============================================================================

class Worker {
public:
    // coordinator 是整个 Worker 池共享的有界全局准入协调器，必须由调用方提供
    // （运行在主控事件循环上）；构造即完成本 Worker 的路由登记。
    Worker(uint32_t id, net::io_context& io_context,
           const WorkerRuntimeConfig& runtime_config, StatsShard& stats,
           app::DNSWorker& dns_worker,
           std::shared_ptr<GroupCoordinator> coordinator,
           geo::GeoDatabase* geo_database = nullptr);
    ~Worker();

    // 停机收尾前供运行时 owner 取得协调器；StopRuntime 完成后释放。
    [[nodiscard]] std::shared_ptr<GroupCoordinator> Coordinator() const noexcept {
        return group_coordinator_;
    }

    // ── 基本访问 ─────────────────────────────────────────────────────────────

    [[nodiscard]] uint32_t Id() const noexcept { return id_; }

    // Cross-thread control-plane entries. Full mailbox throws WorkerMailboxFull;
    // after RequestStop admission throws operation_aborted. PostTask carries a
    // coroutine that genuinely suspends on this Worker; PostCall carries a
    // self-contained synchronous callable. Both bodies run on this Worker.
    template <typename T>
    net::awaitable<T> PostTask(net::awaitable<T> task) {
        return mailbox_->Post(std::move(task));
    }
    template <typename Fn>
    auto PostCall(Fn fn) {
        return mailbox_->PostCall(std::move(fn));
    }

    // Static startup transaction. Must run on this Worker's executor before
    // inbound registration; failures propagate to the caller.
    void StartRuntime();

    // Lifecycle notification has one reserved pending slot, independent of
    // ordinary admission. The shell remains alive through the global join.
    void RequestStop() noexcept;
    // Stop data admission/work but keep accounting/control admission available.
    void RequestDrain() noexcept;
    net::awaitable<void> AsyncDrain();
    // After RequestStop, one observer awaits all accepted work and live state.
    // Repeated joins after completion are harmless.
    net::awaitable<void> AsyncJoin();
    // 运行时故障通知：无捕获函数指针 + context，与 UdpAssociationReclaimer 同一风格。
    // 必须在数据线程启动前安装；context 由调用方保证覆盖 Worker 运行期。
    using FailureHandler = void (*)(void*, std::exception_ptr) noexcept;
    void SetFailureHandler(void* context, FailureHandler handler) noexcept;
    // Called exactly once on the data thread; catches loop failures, requests
    // global cancellation, and keeps driving completion until live teardown.
    void RunEventLoop() noexcept;

    // ── 冷路径变更：必须在所属 Worker executor 上执行（跨线程经 PostCall/PostTask）──

    // 返回真实 bind 结果。
    [[nodiscard]] bool AddListener(PortBinding binding);

    // 注册 receiver settings + 协议处理器。
    [[nodiscard]] bool RegisterInbound(
        BuildRequest req,
        ReceiverSettings receiver);

    // 添加 UDP 监听（同端口 UDP socket，SO_REUSEPORT）。协议 handler 在
    // Worker 线程内构造，避免跨线程触碰 Worker-local validator / allocator。
    // 替换旧 socket 时等待旧原生分发任务实际结束，因此是协程。
    net::awaitable<bool> AddUdpListenerTask(
        PortBinding binding,
        BuildRequest req);

    // 动态出站：XrayR Controller 面板节点 addOutbound/removeOutbound。
    void AddOutbound(PreparedOutboundConfig config);
    void RemoveOutbound(std::string_view tag);

    // 注销监听与 handler；等待 UDP 原生分发任务实际结束后才返回。
    net::awaitable<void> UnregisterListenerTask(std::string tag);

    void UpdateRule(std::string_view tag, std::shared_ptr<const std::vector<common::DetectRule>> rules);
    void InstallUserView(UserStore::WorkerView view);

    // ── 数据收集（在所属 Worker 线程执行，无竞争）──

    // Snapshot on this Worker; acknowledge only after off-thread durable storage.
    [[nodiscard]] app::UserTrafficCounters SnapshotTraffic(std::string_view tag);
    void CommitTraffic(std::string_view tag, const app::UserTrafficCounters& snapshot);
    void RollbackTraffic(std::string_view tag, const app::UserTrafficCounters& snapshot);

    // 协议类型由 inbound handler 的 ReceiverSettings 自动判断，无需外部传入。
    [[nodiscard]] std::vector<common::OnlineDevice> GetOnlineDevices(std::string_view tag) const;

    // Resource traversal is requested only by the low-frequency diagnostics loop.
    [[nodiscard]] WorkerRuntimeStatsSnapshot CollectRuntimeStats(bool include_resources) const;

private:
    struct ListenerSlot;
    struct ListenerState;
    struct RuntimeState;
    class ColdMutation;
    // 冷路径变更统一前导：停机/排空中拒绝（operation_aborted），并独占冷变更槽位。
    void ThrowIfStopping() const;
    [[nodiscard]] ColdMutation BeginColdMutation();
    void BeginStopOnWorker() noexcept;
    net::awaitable<void> StopRuntimeTask();
    net::awaitable<void> DrainRuntimeTask();
    void ReportFailure(std::exception_ptr error) noexcept;

    // ── 成员 ────────────────────────────────────────────────────────────────

    uint32_t              id_;
    net::io_context& io_context_;
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> drain_requested_{false};
    std::atomic<bool> joined_{false};
    bool stop_notification_delivered_ = false; // owner executor only
    void* failure_context_ = nullptr;
    FailureHandler failure_handler_ = nullptr;
    std::unique_ptr<RuntimeState> runtime_;
    std::unique_ptr<WorkerMailbox> mailbox_;
    std::shared_ptr<GroupCoordinator> group_coordinator_;
};

}  // namespace app

