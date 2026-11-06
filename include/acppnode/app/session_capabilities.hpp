#pragma once

#include "acppnode/app/session_group_executor.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/proxyman/inbound/user_store.hpp"
#include "acppnode/app/proxyman/outbound/handler.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/infra/runtime_config_types.hpp"
#include "acppnode/app/session_tracking.hpp"
#include "acppnode/app/stats.hpp"

#include <memory>
#include <optional>
#include <vector>

namespace acpp {
class AsyncStream;
class ConnectionLimiter;
namespace session { struct Context; }
struct WorkerRuntimeConfig;
namespace rule { class DetectRulePolicy; }
namespace app {
class RequestLoadState;
namespace router { class Router; }
namespace dns { class DNSWorker; }

// Cold routing/outbound configuration. The outbound publication is shared with
// Worker-level dispatch; stateful tags own independent stable hosts while
// stateless handlers remain local to their requesting physical domain.
struct SessionConfiguration final {
    SessionConfiguration(const WorkerRuntimeConfig& config,
                         std::shared_ptr<const router::Router> router,
                         std::shared_ptr<rule::DetectRulePolicy> policy);
    const TimeoutsConfig timeouts;
    const std::shared_ptr<proxyman::outbound::OutboundConfiguration> outbounds;
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
        std::shared_ptr<const proxyman::inbound::ReceiverSettings> receiver);
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
    [[nodiscard]] const proxyman::inbound::ReceiverSettings& Receiver() const noexcept { return *receiver_; }
    [[nodiscard]] bool Initialized() const noexcept { return initialized_; }
    [[nodiscard]] bool IsJoined() const noexcept { return joined_; }
    // Must run in the domain before constructing its socket/Context payload.
    void Initialize(net::io_context& native_reactor);
    net::awaitable<void> ProcessTCP(std::unique_ptr<AsyncStream> stream,
                                  session::Context& context);
    void RequestStop() noexcept;
    // Called after ProcessTCP has finished; releases every physical-domain
    // resource. Accounting snapshots retain only their independent ledger.
    net::awaitable<void> AsyncJoin();
    [[nodiscard]] SessionTrackingState& Tracking() noexcept;
    [[nodiscard]] std::shared_ptr<SessionTrackingState> TrackingOwner() const noexcept;
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
        std::shared_ptr<const proxyman::inbound::ReceiverSettings> receiver);
    struct Impl;
    memory::AllocationDomain allocation_;
    std::optional<memory::ScopedAllocationDomain> allocation_scope_;
    std::weak_ptr<ExecutionDomain> domain_;
    std::shared_ptr<const SessionConfiguration> configuration_;
    std::shared_ptr<ConnectionLimiter> limiter_;
    std::shared_ptr<RequestLoadState> request_load_;
    dns::DNSWorker& dns_worker_;
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared_;
    std::shared_ptr<const proxyman::inbound::ReceiverSettings> receiver_;
    proxyman::inbound::UserStore::WorkerView user_view_;
    proxyman::inbound::UserStore::WorkerView previous_user_view_;
    std::unique_ptr<Impl> impl_;
    std::shared_ptr<SessionTrackingState> tracking_;
    StatsShard stats_;
    bool initialized_ = false;
    bool stopping_ = false;
    bool joined_ = false;
};
} // namespace app
} // namespace acpp
