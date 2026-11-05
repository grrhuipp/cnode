#include "acppnode/app/session_capabilities.hpp"

#include "acppnode/app/dispatcher/default_dispatcher.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/request_load_state.hpp"
#include "acppnode/app/router/router.hpp"
#include "acppnode/app/session_tracking.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker_runtime_config.hpp"
#include "acppnode/common/rule.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/features/outbound/outbound.hpp"
#include "../common/awaitable_task_group.hpp"
#include "../transport/internet/xhttp_session.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/this_coro.hpp>
#include <stdexcept>
#include <algorithm>

namespace acpp::app {

// A stateful outbound is a resource domain, not an inbound or Worker owner.
// Requests join it before accessing its mutable state. Resident work always
// runs with this host's executor and allocation arena, even when the first
// borrowing physical connection has already finished.
class OutboundPoolHost final : public ExecutionDomain::Hooks,
                               public std::enable_shared_from_this<OutboundPoolHost> {
public:
    OutboundPoolHost(const proxyman::outbound::PreparedOutboundConfig& config,
                     dns::DNSWorker& dns_worker, std::chrono::seconds dial_timeout)
        : config_(config), dns_worker_(dns_worker), dial_timeout_(dial_timeout) {}

    void Bind(const std::shared_ptr<ExecutionDomain>& domain) {
        domain_ = domain;
        allocation_.SetLeaseGroup(domain->LeaseIdentity(), &ExecutionDomain::SharesLeaseIdentity);
    }
    std::shared_ptr<ExecutionDomain> Domain() const { return domain_.lock(); }
    std::string_view Tag() const noexcept { return config_.tag; }

    net::awaitable<OutboundProcessResult> Process(
        const tcp::endpoint* local, session::Context& context,
        const TimeoutsConfig& timeouts, transport::Link inbound, StatsShard& stats,
        const RelayConfig& relay, buf::MultiBufferBatch payload,
        std::chrono::seconds idle_timeout, std::chrono::seconds write_timeout) {
        auto request = ExecutionDomain::Current();
        auto domain = Domain();
        if (!request || !domain) throw IoSystemError(net::error::operation_aborted);
        co_await request->Join(domain);
        // This is a continuation inside the now unified group, not a packet
        // handoff to an owner. Source Context/accounting and streams stay put.
        co_return co_await net::co_spawn(domain->Executor(),
            Run(local, context, timeouts, inbound, stats, relay,
                std::move(payload), idle_timeout, write_timeout), net::use_awaitable);
    }

    void Retire() {
        auto domain = Domain();
        if (!domain) return;
        domain->Execute([self = shared_from_this()] {
            self->retired_ = true;
            self->CancelIfIdle();
        });
    }

    net::awaitable<void> AsyncJoin() {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        retired_ = true;
        std::exception_ptr failure;
        if (tasks_) {
            try { co_await tasks_->AsyncJoin(); }
            catch (...) { failure = std::current_exception(); }
        }
        auto domain = Domain();
        try { co_await transport::internet::JoinXHttpClientTasks(domain->Services()); }
        catch (...) { if (!failure) failure = std::current_exception(); }
        handler_.reset();
        tasks_.reset();
        dns_.reset();
        try { co_await TimeoutScheduler::AsyncReleaseForIoContext(domain->Reactor()); }
        catch (...) { if (!failure) failure = std::current_exception(); }
        if (failure) std::rethrow_exception(failure);
    }

    void Enter() noexcept override { allocation_scope_.emplace(allocation_); }
    void Leave() noexcept override { allocation_scope_.reset(); }
    void OnFailure(std::exception_ptr) noexcept override {
        retired_ = true;
        if (tasks_) tasks_->Tasks().Cancel();
    }

private:
    void CancelIfIdle() {
        if (retired_ && active_ == 0 && tasks_) tasks_->Tasks().Cancel();
    }
    net::awaitable<OutboundProcessResult> Run(
        const tcp::endpoint* local, session::Context& context,
        const TimeoutsConfig& timeouts, transport::Link inbound, StatsShard& stats,
        const RelayConfig& relay, buf::MultiBufferBatch payload,
        std::chrono::seconds idle_timeout, std::chrono::seconds write_timeout) {
        if (retired_) throw IoSystemError(net::error::operation_aborted);
        if (!handler_) {
            auto domain = Domain();
            dns_ = std::make_unique<dns::DNS>(dns_worker_);
            tasks_ = std::make_unique<ResidentTaskGroup>(domain->Executor());
            handler_ = proxyman::outbound::NewHandler(
                config_, domain->Reactor(), *dns_, dial_timeout_, tasks_->Tasks());
            if (!handler_) throw std::runtime_error("cannot instantiate pooled outbound");
        }
        struct Borrow {
            OutboundPoolHost& host;
            explicit Borrow(OutboundPoolHost& host) : host(host) { ++host.active_; }
            ~Borrow() { --host.active_; host.CancelIfIdle(); }
        } borrow(*this);
        co_return co_await handler_->Process(Domain()->Reactor(), local, context,
            timeouts, inbound, stats, relay, std::move(payload), idle_timeout, write_timeout);
    }

    const proxyman::outbound::PreparedOutboundConfig config_;
    dns::DNSWorker& dns_worker_;
    const std::chrono::seconds dial_timeout_;
    memory::AllocationDomain allocation_;
    std::optional<memory::ScopedAllocationDomain> allocation_scope_;
    std::weak_ptr<ExecutionDomain> domain_;
    std::unique_ptr<dns::DNS> dns_;
    std::unique_ptr<ResidentTaskGroup> tasks_;
    std::unique_ptr<Outbound> handler_;
    size_t active_ = 0;
    bool retired_ = false;
};

namespace {
// Physical-domain handle contains only a lifetime lease; no cross-domain raw
// handler pointer escapes the host.
class PooledOutbound final : public Outbound {
public:
    explicit PooledOutbound(std::shared_ptr<OutboundPoolHost> host) : host_(std::move(host)) {}
    std::string_view Tag() const noexcept override { return host_->Tag(); }
    net::awaitable<OutboundProcessResult> Process(
        net::io_context&, const tcp::endpoint* local, session::Context& context,
        const TimeoutsConfig& timeouts, transport::Link inbound, StatsShard& stats,
        const RelayConfig& relay, buf::MultiBufferBatch payload,
        std::chrono::seconds idle_timeout, std::chrono::seconds write_timeout) override {
        return host_->Process(local, context, timeouts, inbound, stats, relay,
                              std::move(payload), idle_timeout, write_timeout);
    }
private:
    std::shared_ptr<OutboundPoolHost> host_;
};
}

struct OutboundConfiguration::Hosts {
    struct Resident {
        std::shared_ptr<OutboundPoolHost> host;
        std::shared_ptr<ExecutionDomain> domain;
    };
    net::io_context& reactor;
    uint32_t worker_id;
    std::shared_ptr<GroupCoordinator> coordinator;
    dns::DNSWorker& dns_worker;
    std::chrono::seconds dial_timeout;
    std::vector<Resident> residents;

    std::shared_ptr<OutboundPoolHost> Create(
        const proxyman::outbound::PreparedOutboundConfig& config) {
        auto host = std::make_shared<OutboundPoolHost>(config, dns_worker, dial_timeout);
        auto domain = ExecutionDomain::Create(
            reactor, worker_id, reactor.get_executor(), host, coordinator);
        host->Bind(domain);
        residents.push_back({host, std::move(domain)});
        return host;
    }
};

OutboundConfiguration::~OutboundConfiguration() = default;

OutboundConfiguration::Entry OutboundConfiguration::Prepare(
    const proxyman::outbound::PreparedOutboundConfig& configuration) {
    auto entry = std::make_shared<Configuration>(configuration);
    if (hosts_ && configuration.create.persistent_state)
        entry->host = hosts_->Create(configuration);
    return entry;
}

void OutboundConfiguration::BindHosts(net::io_context& reactor, uint32_t worker_id,
    std::shared_ptr<GroupCoordinator> coordinator, dns::DNSWorker& dns_worker,
    std::chrono::seconds dial_timeout) {
    const std::lock_guard lock(publication_mutex_);
    if (hosts_) throw std::logic_error("outbound hosts already bound");
    hosts_ = std::make_unique<Hosts>(Hosts{
        reactor, worker_id, std::move(coordinator), dns_worker, dial_timeout, {}});
    auto snapshot = std::make_shared<Snapshot>();
    const auto previous = Capture();
    snapshot->reserve(previous->size());
    for (const auto& config : *previous) snapshot->push_back(Prepare(*config));
    snapshot_.store(std::move(snapshot), std::memory_order_release);
}

net::awaitable<void> OutboundConfiguration::AsyncJoinHosts() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (!hosts_) co_return;
    std::exception_ptr failure;
    for (const auto& resident : hosts_->residents) {
        try {
            co_await net::co_spawn(resident.domain->Executor(),
                resident.host->AsyncJoin(), net::use_awaitable);
        } catch (...) { if (!failure) failure = std::current_exception(); }
    }
    // Release all domain roots before the coordinator's Finalize barrier.
    hosts_.reset();
    if (failure) std::rethrow_exception(failure);
}

OutboundConfiguration::OutboundConfiguration(
    const std::vector<proxyman::outbound::PreparedOutboundConfig>& configurations) {
    auto snapshot = std::make_shared<Snapshot>();
    snapshot->reserve(configurations.size());
    for (const auto& config : configurations)
        snapshot->push_back(Prepare(config));
    snapshot_.store(std::move(snapshot), std::memory_order_release);
}

std::shared_ptr<const OutboundConfiguration::Snapshot>
OutboundConfiguration::Capture() const noexcept {
    return snapshot_.load(std::memory_order_acquire);
}

void OutboundConfiguration::Replace(
    const proxyman::outbound::PreparedOutboundConfig& configuration) {
    const std::lock_guard lock(publication_mutex_);
    auto candidate = Prepare(configuration);
    auto snapshot = std::make_shared<Snapshot>(*Capture());
    for (auto& entry : *snapshot) {
        if (entry->tag != configuration.tag) continue;
        if (entry->host) entry->host->Retire();
        entry = std::move(candidate);
        snapshot_.store(std::move(snapshot), std::memory_order_release);
        return;
    }
    snapshot->push_back(std::move(candidate));
    snapshot_.store(std::move(snapshot), std::memory_order_release);
}

void OutboundConfiguration::Remove(std::string_view tag) {
    const std::lock_guard lock(publication_mutex_);
    auto snapshot = std::make_shared<Snapshot>(*Capture());
    std::erase_if(*snapshot, [tag](const Entry& entry) {
        if (entry->tag != tag) return false;
        if (entry->host) entry->host->Retire();
        return true;
    });
    snapshot_.store(std::move(snapshot), std::memory_order_release);
}

SessionConfiguration::SessionConfiguration(const WorkerRuntimeConfig& config,
    std::shared_ptr<const router::Router> router_value,
    std::shared_ptr<rule::DetectRulePolicy> policy_value)
    : timeouts(config.timeouts),
      outbounds(std::make_shared<OutboundConfiguration>(config.outbounds)),
      router(std::move(router_value)), policy(std::move(policy_value)) {
    if (!router || !policy) throw std::invalid_argument("missing session configuration");
}

struct PhysicalSessionCapabilities::Impl final : memory::ThreadAllocated,
                                                proxyman::inbound::Handler::ProtocolProvider {
    // Stateless tags remain physical-local. Stateful tags return a lease that
    // joins their independent host before entering the real protocol handler.
    class Outbounds final : public features::outbound::HandlerLookup {
    public:
        Outbounds(const SessionConfiguration& config, net::io_context& io,
                  dns::DNS& dns, AwaitableTaskGroup& tasks)
            : config_(config), io_(io), dns_(dns), tasks_(tasks) {}
        HandlerPtr GetHandler(std::string_view tag) override {
            const auto snapshot = config_.outbounds->Capture();
            for (const auto& config : *snapshot) {
                if (config->tag != tag) continue;
                Entry* cached = nullptr;
                for (auto& entry : live_) {
                    if (entry.config->tag != tag) continue;
                    if (entry.config == config) return entry.handler;
                    cached = &entry;
                    break;
                }
                auto handler = config->host
                    ? std::unique_ptr<Outbound>(std::make_unique<PooledOutbound>(config->host))
                    : proxyman::outbound::NewHandler(
                        *config, io_, dns_, config_.timeouts.DialTimeout(), tasks_);
                if (!handler) throw std::runtime_error("cannot instantiate domain outbound");
                HandlerPtr shared(handler.release(), std::default_delete<Outbound>{},
                                  memory::ThreadLocalAllocator<Outbound>{});
                if (cached) *cached = Entry{config, shared};
                else live_.push_back(Entry{config, shared});
                return shared;
            }
            std::erase_if(live_, [tag](const Entry& entry) { return entry.config->tag == tag; });
            return {};
        }
    private:
        struct Entry {
            OutboundConfiguration::Entry config;
            HandlerPtr handler;
        };
        const SessionConfiguration& config_;
        net::io_context& io_;
        dns::DNS& dns_;
        AwaitableTaskGroup& tasks_;
        memory::ThreadLocalVector<Entry> live_;
    };

    Impl(PhysicalSessionCapabilities& owner_value, net::io_context& io)
        : owner(owner_value), reactor(io), dns(owner.dns_worker_),
          tasks(std::make_unique<ResidentTaskGroup>(owner.Domain()->Executor())) {
        handler = memory::AllocateShared<proxyman::inbound::Handler>(
            owner.receiver_, *this, *owner.limiter_);
        outbounds = std::make_unique<Outbounds>(*owner.configuration_, io, dns, tasks->Tasks());
        dispatcher = std::make_unique<dispatcher::DefaultDispatcher>(
            *owner.configuration_->router, *outbounds, *owner.configuration_->policy,
            tracking, dns, *owner.request_load_);
    }

    Inbound& GetProxy() override {
        if (!proxy) {
            if (!protocol)
                protocol = proxyman::inbound::NewProtocolRuntime(owner.prepared_->protocol);
            if (!protocol) throw std::invalid_argument("missing session protocol runtime");
            proxy = proxyman::inbound::NewHandler(owner.prepared_->protocol,
                *protocol, stats, owner.limiter_.get(), *owner.prepared_);
            if (!proxy) throw std::invalid_argument("missing session inbound handler");
        }
        return *proxy;
    }

    PhysicalSessionCapabilities& owner;
    net::io_context& reactor;
    StatsShard stats;
    SessionTrackingState tracking;
    dns::DNS dns;
    std::unique_ptr<ResidentTaskGroup> tasks;
    std::unique_ptr<proxyman::inbound::ProtocolRuntime> protocol;
    std::unique_ptr<Inbound> proxy;
    std::shared_ptr<proxyman::inbound::Handler> handler;
    std::unique_ptr<Outbounds> outbounds;
    std::unique_ptr<dispatcher::DefaultDispatcher> dispatcher;
    net::cancellation_signal stop;
};

std::shared_ptr<PhysicalSessionCapabilities> PhysicalSessionCapabilities::Create(
    std::shared_ptr<const SessionConfiguration> configuration,
    std::shared_ptr<ConnectionLimiter> limiter,
    std::shared_ptr<RequestLoadState> request_load, dns::DNSWorker& dns_worker,
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared,
    proxyman::inbound::ReceiverSettings receiver) {
    return std::shared_ptr<PhysicalSessionCapabilities>(new PhysicalSessionCapabilities(
        std::move(configuration), std::move(limiter), std::move(request_load),
        dns_worker, std::move(prepared), std::move(receiver)));
}

PhysicalSessionCapabilities::PhysicalSessionCapabilities(
    std::shared_ptr<const SessionConfiguration> configuration,
    std::shared_ptr<ConnectionLimiter> limiter,
    std::shared_ptr<RequestLoadState> request_load, dns::DNSWorker& dns_worker,
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared,
    proxyman::inbound::ReceiverSettings receiver)
    : configuration_(std::move(configuration)), limiter_(std::move(limiter)),
      request_load_(std::move(request_load)), dns_worker_(dns_worker),
      prepared_(std::move(prepared)), receiver_(std::move(receiver)),
      user_view_(proxyman::inbound::UserStore::CaptureWorkerView()) {
    if (!configuration_ || !limiter_ || !request_load_ || !prepared_)
        throw std::invalid_argument("missing domain capability");
}

PhysicalSessionCapabilities::~PhysicalSessionCapabilities() {
    memory::ScopedAllocationDomain scope(allocation_);
    impl_.reset();
}

void PhysicalSessionCapabilities::BindDomain(const std::shared_ptr<ExecutionDomain>& domain) {
    if (!domain || !domain_.expired()) throw std::logic_error("invalid domain binding");
    domain_ = domain;
    allocation_.SetLeaseGroup(domain->LeaseIdentity(), &ExecutionDomain::SharesLeaseIdentity);
}

std::shared_ptr<ExecutionDomain> PhysicalSessionCapabilities::Domain() const noexcept {
    return domain_.lock();
}

void PhysicalSessionCapabilities::Initialize(net::io_context& reactor) {
    if (stopping_) throw IoSystemError(net::error::operation_aborted);
    if (!impl_) impl_ = std::make_unique<Impl>(*this, reactor);
}

net::awaitable<void> PhysicalSessionCapabilities::ProcessTCP(
    std::unique_ptr<AsyncStream> stream, session::Context& context) {
    if (stopping_) throw IoSystemError(net::error::operation_aborted);
    if (!impl_) throw std::logic_error("domain not initialized");
    RequestLoadState::PhysicalConnectionScope physical(*request_load_);
    co_await net::co_spawn(Domain()->Executor(), impl_->handler->ProcessAcceptedTCP(
        impl_->reactor, *impl_->dispatcher, impl_->stats, *request_load_,
        configuration_->timeouts, std::move(stream), context, &impl_->dns),
        net::bind_cancellation_slot(impl_->stop.slot(), net::use_awaitable));
}

void PhysicalSessionCapabilities::RequestStop() noexcept {
    if (stopping_) return;
    stopping_ = true;
    if (impl_) {
        impl_->stop.emit(net::cancellation_type::all);
        if (impl_->tasks) impl_->tasks->Tasks().Cancel();
    }
}

net::awaitable<void> PhysicalSessionCapabilities::AsyncJoin() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (!impl_) co_return;
    RequestStop();
    // ProcessTCP has joined its co_spawn. The installed cancellation handler
    // still owns a GroupExecutor until cleared: retaining it cycles the domain
    // through this host and keeps the admission actor alive after pool shutdown.
    impl_->stop.slot().clear();
    std::exception_ptr failure;
    if (impl_->tasks) {
        try { co_await impl_->tasks->AsyncJoin(); }
        catch (...) { failure = std::current_exception(); }
    }
    try { co_await transport::internet::JoinXHttpClientTasks(Domain()->Services()); }
    catch (...) { if (!failure) failure = std::current_exception(); }
    // Break transport/executor leases only after real completion callbacks.
    impl_->dispatcher.reset();
    impl_->handler.reset();
    impl_->outbounds.reset();
    impl_->proxy.reset();
    impl_->protocol.reset();
    impl_->tasks.reset();
    try { co_await TimeoutScheduler::AsyncReleaseForIoContext(impl_->reactor); }
    catch (...) { if (!failure) failure = std::current_exception(); }
    if (failure) std::rethrow_exception(failure);
}

SessionTrackingState& PhysicalSessionCapabilities::Tracking() noexcept { return impl_->tracking; }
StatsShard& PhysicalSessionCapabilities::Stats() noexcept { return impl_->stats; }
bool PhysicalSessionCapabilities::HasPendingTraffic() const noexcept {
    return impl_ && impl_->tracking.HasPendingTraffic();
}
std::vector<OnlineDevice> PhysicalSessionCapabilities::GetOnlineDevices(std::string_view tag) const {
    return impl_ && impl_->protocol ? impl_->protocol->GetOnlineDevices(tag)
                                   : std::vector<OnlineDevice>{};
}
void PhysicalSessionCapabilities::UpdateUserView(
    proxyman::inbound::UserStore::WorkerView view) noexcept {
    user_view_ = std::move(view);
    proxyman::inbound::UserStore::InstallWorkerView(user_view_);
}
void PhysicalSessionCapabilities::Enter() noexcept {
    allocation_scope_.emplace(allocation_);
    previous_user_view_ = proxyman::inbound::UserStore::ExchangeWorkerView(user_view_);
}
void PhysicalSessionCapabilities::Leave() noexcept {
    (void)proxyman::inbound::UserStore::ExchangeWorkerView(std::move(previous_user_view_));
    allocation_scope_.reset();
}
void PhysicalSessionCapabilities::OnFailure(std::exception_ptr error) noexcept {
    RequestStop();
    try {
        try { if (error) std::rethrow_exception(error); }
        catch (const IoSystemError& failure) {
            if (failure.code() != net::error::operation_aborted &&
                failure.code() != net::error::eof)
                LOG_ERROR("session domain failed > {}", failure.what());
        }
        catch (const std::exception& failure) {
            LOG_ERROR("session domain failed > {}", failure.what());
        }
        catch (...) { LOG_ERROR("session domain failed > unknown error"); }
    } catch (...) {} // Failure reporting must remain noexcept, including under OOM.
}

} // namespace acpp::app
