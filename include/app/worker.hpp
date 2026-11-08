#pragma once

#include "app/worker_mailbox.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "common/asio_types.hpp"

#include <cstdint>
#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>


class GroupCoordinator;

namespace proxyman::inbound {
struct BuildRequest;
struct ReceiverSettings;
}
namespace proxyman::outbound {
struct PreparedOutboundConfig;
}
namespace geo {
class GeoDatabase;
}
namespace app::dns {
class DNSWorker;
}
namespace app {
struct UserTrafficSnapshot;
}
struct OnlineDevice;
struct PortBinding;
struct StatsShard;
struct WorkerRuntimeConfig;
struct WorkerRuntimeStatsSnapshot;
namespace rule {
struct DetectRule;
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
           geo::GeoDatabase* geo_database = nullptr);
    ~Worker();

    // Shared, bounded control directory for this pool; installed before startup.
    void SetGroupCoordinator(std::shared_ptr<GroupCoordinator> coordinator);
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
    void SetFailureHandler(std::function<void(std::exception_ptr)> handler);
    // Called exactly once on the data thread; catches loop failures, requests
    // global cancellation, and keeps driving completion until live teardown.
    void RunEventLoop() noexcept;

    // ── 冷路径变更：必须在所属 Worker executor 上执行（跨线程经 PostCall/PostTask）──

    // 返回真实 bind 结果。
    [[nodiscard]] bool AddListener(PortBinding binding);

    // 注册 receiver settings + 协议处理器。
    [[nodiscard]] bool RegisterInbound(
        proxyman::inbound::BuildRequest req,
        proxyman::inbound::ReceiverSettings receiver);

    // 添加 UDP 监听（同端口 UDP socket，SO_REUSEPORT）。协议 handler 在
    // Worker 线程内构造，避免跨线程触碰 Worker-local validator / allocator。
    // 替换旧 socket 时等待旧原生分发任务实际结束，因此是协程。
    net::awaitable<bool> AddUdpListenerTask(
        PortBinding binding,
        proxyman::inbound::BuildRequest req);

    // 动态出站：XrayR Controller 面板节点 addOutbound/removeOutbound。
    void AddOutbound(proxyman::outbound::PreparedOutboundConfig config);
    void RemoveOutbound(std::string_view tag);

    // 注销监听与 handler；等待 UDP 原生分发任务实际结束后才返回。
    net::awaitable<void> UnregisterListenerTask(std::string tag);

    void UpdateRule(std::string_view tag, std::vector<rule::DetectRule> rules);
    void InstallUserView(proxyman::inbound::UserStore::WorkerView view);

    // ── 数据收集（在所属 Worker 线程执行，无竞争）──

    // Snapshot on this Worker; acknowledge only after off-thread durable storage.
    [[nodiscard]] net::awaitable<app::UserTrafficSnapshot> SnapshotTraffic(std::string tag);
    net::awaitable<void> CommitTraffic(std::string tag, const app::UserTrafficSnapshot& snapshot);
    net::awaitable<void> RollbackTraffic(std::string tag, const app::UserTrafficSnapshot& snapshot);

    // 协议类型由 inbound handler 的 ReceiverSettings 自动判断，无需外部传入。
    [[nodiscard]] net::awaitable<std::vector<OnlineDevice>> GetOnlineDevices(std::string tag) const;

    // Resource traversal is requested only by the low-frequency diagnostics loop.
    [[nodiscard]] net::awaitable<WorkerRuntimeStatsSnapshot> CollectRuntimeStats(bool include_resources) const;
    void CollectHeap();

private:
    struct ListenerSlot;
    struct ListenerState;
    struct RuntimeState;
    void BeginStopOnWorker() noexcept;
    net::awaitable<void> StopRuntimeTask();
    net::awaitable<void> DrainRuntimeTask();
    WorkerRuntimeStatsSnapshot CollectNativeRuntimeStats(bool include_resources) const;
    void ReportFailure(std::exception_ptr error) noexcept;

    // ── 成员 ────────────────────────────────────────────────────────────────

    uint32_t              id_;
    net::io_context& io_context_;
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> drain_requested_{false};
    std::atomic<bool> joined_{false};
    bool stop_notification_delivered_ = false; // owner executor only
    std::function<void(std::exception_ptr)> failure_handler_;
    std::unique_ptr<RuntimeState> runtime_;
    std::unique_ptr<WorkerMailbox> mailbox_;
    std::shared_ptr<GroupCoordinator> group_coordinator_;
    bool owns_group_coordinator_ = false;

};

