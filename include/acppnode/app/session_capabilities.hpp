#pragma once

#include "acppnode/app/session_group_executor.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/proxyman/outbound/prepared_config.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/infra/runtime_config_types.hpp"

#include <atomic>
#include <mutex>
#include <memory>
#include <optional>
#include <vector>

namespace acpp {
class AsyncStream;
class ConnectionLimiter;
struct StatsShard;
struct WorkerRuntimeConfig;
namespace session { struct Context; }
namespace rule { class DetectRulePolicy; }
namespace app {
class RequestLoadState;
class SessionTrackingState;
namespace router { class Router; }
namespace dns { class DNSWorker; }

class OutboundPoolHost;
class OutboundConfiguration final {
public:
    struct Configuration final : proxyman::outbound::PreparedOutboundConfig {
        explicit Configuration(const proxyman::outbound::PreparedOutboundConfig& config)
            : PreparedOutboundConfig(config) {}
        std::shared_ptr<OutboundPoolHost> host;
    };
    using Entry = std::shared_ptr<const Configuration>;
    using Snapshot = std::vector<Entry>;
    explicit OutboundConfiguration(
        const std::vector<proxyman::outbound::PreparedOutboundConfig>& configurations);
    ~OutboundConfiguration();
    // Cold Worker setup/publication only; no Worker state is captured by hosts.
    void BindHosts(net::io_context& reactor, uint32_t worker_id,
                   std::shared_ptr<GroupCoordinator> coordinator,
                   dns::DNSWorker& dns_worker, std::chrono::seconds dial_timeout);
    // Called only after the Worker's requests have drained.
    net::awaitable<void> AsyncJoinHosts();
    [[nodiscard]] std::shared_ptr<const Snapshot> Capture() const noexcept;
    void Replace(const proxyman::outbound::PreparedOutboundConfig& configuration);
    void Remove(std::string_view tag);
private:
    struct Hosts;
    std::unique_ptr<Hosts> hosts_;
    Entry Prepare(const proxyman::outbound::PreparedOutboundConfig& configuration);
    std::mutex publication_mutex_;
    std::atomic<std::shared_ptr<const Snapshot>> snapshot_;
};

// Cold routing/outbound configuration. Stateful tags own independent stable
// hosts; stateless handlers remain local to their requesting physical domain.
struct SessionConfiguration final {
    SessionConfiguration(const WorkerRuntimeConfig& config,
                         std::shared_ptr<const router::Router> router,
                         std::shared_ptr<rule::DetectRulePolicy> policy);
    const TimeoutsConfig timeouts;
    const std::shared_ptr<OutboundConfiguration> outbounds;
    const std::shared_ptr<const router::Router> router;
    const std::shared_ptr<rule::DetectRulePolicy> policy;
};

class PhysicalSessionCapabilities final : public ExecutionDomain::Hooks {
public:
    static std::shared_ptr<PhysicalSessionCapabilities> Create(
        std::shared_ptr<const SessionConfiguration> configuration,
        std::shared_ptr<ConnectionLimiter> limiter,
        std::shared_ptr<RequestLoadState> request_load,
        dns::DNSWorker& dns_worker,
        std::shared_ptr<const proxyman::inbound::BuildRequest> prepared,
        proxyman::inbound::ReceiverSettings receiver);
    ~PhysicalSessionCapabilities() override;
    PhysicalSessionCapabilities(const PhysicalSessionCapabilities&) = delete;
    PhysicalSessionCapabilities& operator=(const PhysicalSessionCapabilities&) = delete;

    void BindDomain(const std::shared_ptr<ExecutionDomain>& domain);
    [[nodiscard]] std::shared_ptr<ExecutionDomain> Domain() const noexcept;
    [[nodiscard]] bool Initialized() const noexcept { return bool(impl_); }
    [[nodiscard]] bool HasPendingTraffic() const noexcept;
    // Must run in the domain before constructing its socket/Context payload.
    void Initialize(net::io_context& native_reactor);
    net::awaitable<void> ProcessTCP(std::unique_ptr<AsyncStream> stream,
                                  session::Context& context);
    void RequestStop() noexcept;
    // Called after ProcessTCP has finished; releases its cancellation executor,
    // joins resident work and releases transport hosts, retaining only accounting.
    net::awaitable<void> AsyncJoin();
    [[nodiscard]] SessionTrackingState& Tracking() noexcept;
    [[nodiscard]] StatsShard& Stats() noexcept;
    [[nodiscard]] std::vector<OnlineDevice> GetOnlineDevices(std::string_view tag) const;
    void UpdateUserView(proxyman::inbound::UserStore::WorkerView view) noexcept;

    void Enter() noexcept override;
    void Leave() noexcept override;
    void OnFailure(std::exception_ptr error) noexcept override;

private:
    PhysicalSessionCapabilities(std::shared_ptr<const SessionConfiguration> configuration,
        std::shared_ptr<ConnectionLimiter> limiter,
        std::shared_ptr<RequestLoadState> request_load, dns::DNSWorker& dns_worker,
        std::shared_ptr<const proxyman::inbound::BuildRequest> prepared,
        proxyman::inbound::ReceiverSettings receiver);
    struct Impl;
    memory::AllocationDomain allocation_;
    std::optional<memory::ScopedAllocationDomain> allocation_scope_;
    std::weak_ptr<ExecutionDomain> domain_;
    std::shared_ptr<const SessionConfiguration> configuration_;
    std::shared_ptr<ConnectionLimiter> limiter_;
    std::shared_ptr<RequestLoadState> request_load_;
    dns::DNSWorker& dns_worker_;
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared_;
    proxyman::inbound::ReceiverSettings receiver_;
    proxyman::inbound::UserStore::WorkerView user_view_;
    proxyman::inbound::UserStore::WorkerView previous_user_view_;
    std::unique_ptr<Impl> impl_;
    bool stopping_ = false;
};
} // namespace app
} // namespace acpp
