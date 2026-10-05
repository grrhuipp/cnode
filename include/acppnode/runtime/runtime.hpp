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
}
namespace proxyman::outbound {
struct PreparedOutboundConfig;
}
namespace geo {
class GeoManager;
}
namespace app::dns {
class DNSService;
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
struct RuntimeConfig;
struct RuntimeMemoryStats;
struct RuntimeStatsSnapshot;
namespace rule {
struct DetectRule;
struct DetectResult;
}

// ============================================================================
// Runtime owns the single listener/control state on its strand. Accepted
// physical connections receive a fresh strand on the shared io_context.
// ============================================================================
class Runtime {
public:
    Runtime(net::any_io_executor shared_executor,
           const RuntimeConfig& runtime_config, StatsShard& stats,
           app::dns::DNSService& dns_service,
           geo::GeoManager* geo_manager = nullptr);
    ~Runtime();

    // All public operations are bounded cross-strand entries. Inputs are owned
    // before dispatch and execution takes place on the Runtime owner strand.
    net::awaitable<void> Initialize();
    net::awaitable<void> Run();
    net::awaitable<void> Stop();

    // ── 监听管理 ─────────────────────────────────────────────────────────────

    net::awaitable<bool> AddListener(PortBinding binding);

    net::awaitable<bool> RegisterInbound(
        ConnectionLimiterPtr limiter,
        proxyman::inbound::BuildRequest req,
        proxyman::inbound::ReceiverSettings receiver);

    // Add one owner-strand UDP listener for this inbound endpoint.
    net::awaitable<bool> AddUdpListener(
        PortBinding binding,
        ConnectionLimiterPtr limiter,
        proxyman::inbound::BuildRequest req);

    // 动态出站：XrayR Controller 面板节点 addOutbound/removeOutbound。
    net::awaitable<void> AddOutbound(
        proxyman::outbound::PreparedOutboundConfig config);
    net::awaitable<void> RemoveOutbound(std::string tag);

    net::awaitable<void> UnregisterListener(std::string tag);

    net::awaitable<void> UpdateRule(
        std::string tag,
        std::vector<rule::DetectRule> rules);

    // ── 流量统计（经所有者 channel 读取）────────────────────────────────────

    using UserTraffic = app::UserTraffic;
    using UserTrafficSnapshot = app::UserTrafficSnapshot;

    net::awaitable<UserTrafficSnapshot> GetTraffic(std::string tag);

    // 收集指定 tag 的在线设备（由在线设备服务 strand 串行处理）
    // 协议类型由 inbound handler 的 ReceiverSettings 自动判断，无需外部传入
    net::awaitable<std::vector<OnlineDevice>>
        GetOnlineDevices(std::string tag);

    net::awaitable<std::vector<rule::DetectResult>>
        GetDetectResults(std::string tag);

    using MemoryStats = RuntimeMemoryStats;
    using RuntimeStatsSnapshot = ::acpp::RuntimeStatsSnapshot;

    net::awaitable<RuntimeStatsSnapshot> CollectRuntimeStats(
        bool include_resources) const;

private:
    struct ListenerSlot;
    struct ListenerState;
    struct RuntimeState;

    template <typename T>
    net::awaitable<T> Dispatch(net::awaitable<T> task) const;

    net::awaitable<void> InitializeOnOwner();
    net::awaitable<void> RunOnOwner();
    net::awaitable<void> StopOnOwner();

    net::awaitable<bool> AddListenerOnOwner(PortBinding binding);
    net::awaitable<bool> RegisterInboundOnOwner(
        ConnectionLimiterPtr limiter,
        proxyman::inbound::BuildRequest req,
        proxyman::inbound::ReceiverSettings receiver);
    net::awaitable<bool> AddUdpListenerOnOwner(
        PortBinding binding,
        ConnectionLimiterPtr limiter,
        proxyman::inbound::BuildRequest req);
    net::awaitable<void> AddOutboundOnOwner(
        proxyman::outbound::PreparedOutboundConfig config);
    net::awaitable<void> RemoveOutboundOnOwner(std::string tag);
    net::awaitable<void> UnregisterListenerOnOwner(std::string tag);
    net::awaitable<void> UpdateRuleOnOwner(
        std::string tag,
        std::vector<rule::DetectRule> rules);
    net::awaitable<UserTrafficSnapshot> GetTrafficOnOwner(std::string tag);
    net::awaitable<std::vector<OnlineDevice>>
        GetOnlineDevicesOnOwner(std::string tag);
    net::awaitable<std::vector<rule::DetectResult>>
        GetDetectResultsOnOwner(std::string tag);
    net::awaitable<RuntimeStatsSnapshot>
        CollectRuntimeStatsOnOwner(bool include_resources) const;

    [[nodiscard]] bool InstallInboundOnOwner(
        ConnectionLimiterPtr limiter,
        const proxyman::inbound::BuildRequest& req,
        proxyman::inbound::ReceiverSettings receiver);

    [[nodiscard]] MemoryStats GetMemoryStats() const;

    // ── 成员 ────────────────────────────────────────────────────────────────

    std::unique_ptr<RuntimeState> runtime_;

};

}  // namespace acpp
