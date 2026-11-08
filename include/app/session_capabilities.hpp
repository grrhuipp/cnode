#pragma once

#include "app/session_group_executor.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/proxyman/outbound/handler.hpp"
#include "common/allocator.hpp"
#include "common/online_device.hpp"
#include "infra/runtime_config_types.hpp"
#include "app/session_tracking.hpp"
#include "app/stats.hpp"
#include "app/rate_limiter_fwd.hpp"
#include "transport/link.hpp"

#include <atomic>
#include <unordered_map>
#include <memory>
#include <optional>
#include <vector>

class AsyncStream;
class ConnectionLimiter;
class AwaitableTaskGroup;
class UserOnlineTracker;
class InboundTransportStreamHandler;
struct UserProfile;
namespace session { struct Context; }
struct WorkerRuntimeConfig;
namespace rule { class DetectRulePolicy; }
namespace app {
class RequestLoadState;
class PhysicalSessionRegistry;
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
struct DatagramSessionEnvironment final {
    std::shared_ptr<const SessionConfiguration> configuration;
    std::shared_ptr<ConnectionLimiter> limiter;
    std::shared_ptr<RequestLoadState> request_load;
    dns::DNSWorker* dns_worker = nullptr;
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared;
    std::shared_ptr<const proxyman::inbound::ReceiverSettings> receiver;
    std::shared_ptr<GroupCoordinator> coordinator;
    std::shared_ptr<PhysicalSessionRegistry> registry;
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
    [[nodiscard]] memory::AllocationDomain& Allocation() noexcept { return allocation_; }
    [[nodiscard]] const proxyman::inbound::ReceiverSettings& Receiver() const noexcept { return *receiver_; }
    [[nodiscard]] bool Initialized() const noexcept { return initialized_; }
    [[nodiscard]] bool IsJoined() const noexcept { return joined_; }
    // Must run in the domain before constructing its socket/Context payload.
    void Initialize(net::io_context& native_reactor);
    // The caller owns and joins this structured scope before AsyncJoin().
    void Initialize(net::io_context& native_reactor, AwaitableTaskGroup& tasks);
    [[nodiscard]] UserOnlineTracker& Tracker();
    [[nodiscard]] std::shared_ptr<InboundTransportStreamHandler>
    MakeAuthenticatedStreamSink(const session::Context& context,
                                std::shared_ptr<ConnectionFamily> family);
    net::awaitable<void> ProcessNativeDatagram(
        transport::Link link, const UserProfile& profile, session::Context& context);
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

// Registration stays at admission, independently of the current execution
// owner. Control-plane sampling therefore observes every session exactly once.
struct PhysicalSessionRecord final {
    std::shared_ptr<ExecutionDomain> domain;
    std::shared_ptr<PhysicalSessionCapabilities> capabilities;
    std::string inbound_tag;
    std::string accounting_key;
    uint64_t conn_id = 0;
    std::atomic<bool> initialized{false};
    std::atomic<bool> finished{false};
    UserTrafficCounters completed_traffic;
    StatsSnapshot final_stats;
};

class PhysicalSessionRegistry final {
public:
    using Records = std::unordered_map<PhysicalSessionRecord*,
                                      std::shared_ptr<PhysicalSessionRecord>>;
    PhysicalSessionRegistry(net::io_context& io, uint32_t worker_id,
        StatsShard& totals, SessionTrackingState& traffic, Records& records);
    [[nodiscard]] std::shared_ptr<PhysicalSessionRecord> Register(
        std::shared_ptr<PhysicalSessionCapabilities> capabilities,
        std::shared_ptr<ExecutionDomain> domain);
    // Called within the session domain after its business and native I/O join.
    net::awaitable<void> Retire(std::shared_ptr<PhysicalSessionRecord> record);
    void CompleteOnOwner(const std::shared_ptr<PhysicalSessionRecord>& record);
    void CancelRegistration(const std::shared_ptr<PhysicalSessionRecord>& record) noexcept;
    net::awaitable<void> AsyncJoin();
private:
    net::awaitable<void> RetireOnOwner(std::shared_ptr<PhysicalSessionRecord> record);
    net::io_context& io_;
    uint32_t worker_id_;
    StatsShard& totals_;
    SessionTrackingState& traffic_;
    Records& records_;
    SignalChannel changed_;
    bool closing_ = false;
};
} // namespace app
