#include "acppnode/app/session_capabilities.hpp"

#include "acppnode/app/dispatcher/default_dispatcher.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/app/rate_limiter.hpp"
#include "acppnode/app/request_load_state.hpp"
#include "acppnode/app/router/router.hpp"
#include "acppnode/app/session_tracking.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/app/worker_runtime_config.hpp"
#include "acppnode/app/worker_stats.hpp"
#include "acppnode/common/rule.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "../common/awaitable_task_group.hpp"
#include "../transport/internet/xhttp_session.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/redirect_error.hpp>
#include <asio/this_coro.hpp>
#include <stdexcept>
#include <algorithm>
#include <vector>
namespace acpp::app {

SessionConfiguration::SessionConfiguration(const WorkerRuntimeConfig& config,
    std::shared_ptr<const router::Router> router_value,
    std::shared_ptr<rule::DetectRulePolicy> policy_value)
    : timeouts(config.timeouts),
      outbounds(std::make_shared<proxyman::outbound::OutboundConfiguration>(config.outbounds)),
      router(std::move(router_value)), policy(std::move(policy_value)) {
    if (!router || !policy) throw std::invalid_argument("missing session configuration");
}

struct PhysicalSessionCapabilities::Impl final : memory::ThreadAllocated {
    using HandlerLookup = proxyman::outbound::HandlerLookup;

    Impl(PhysicalSessionCapabilities& owner_value, net::io_context& io)
        : owner(owner_value), reactor(io), dns(owner.dns_worker_),
          tasks(owner.Domain()->Executor()) {
        handler = memory::AllocateShared<proxyman::inbound::Handler>(
            owner.receiver_,
            proxyman::inbound::Handler::LazyProtocol{
                owner.prepared_, &owner.stats_, owner.limiter_.get()},
            *owner.limiter_);
        // Stateless tags stay physical-local; stateful tags join their host.
        outbounds = std::make_unique<HandlerLookup>(
            *owner.configuration_->outbounds, io, dns,
            owner.configuration_->timeouts.DialTimeout(), tasks.Tasks(),
            HandlerLookup::StatefulTags::JoinHost);
        dispatcher = std::make_unique<dispatcher::DefaultDispatcher>(
            *owner.configuration_->router, *outbounds, *owner.configuration_->policy,
            *owner.tracking_, dns, *owner.request_load_);
    }

    PhysicalSessionCapabilities& owner;
    net::io_context& reactor;
    dns::DNS dns;
    ResidentTaskGroup tasks;
    std::shared_ptr<proxyman::inbound::Handler> handler;
    std::unique_ptr<HandlerLookup> outbounds;
    std::unique_ptr<dispatcher::DefaultDispatcher> dispatcher;
    net::cancellation_signal stop;
};

std::shared_ptr<PhysicalSessionCapabilities> PhysicalSessionCapabilities::Create(
    std::shared_ptr<const SessionConfiguration> configuration,
    std::shared_ptr<ConnectionLimiter> limiter,
    std::shared_ptr<RequestLoadState> request_load, dns::DNSWorker& dns_worker,
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared,
    std::shared_ptr<const proxyman::inbound::ReceiverSettings> receiver) {
    return std::shared_ptr<PhysicalSessionCapabilities>(new PhysicalSessionCapabilities(
        std::move(configuration), std::move(limiter), std::move(request_load),
        dns_worker, std::move(prepared), std::move(receiver)));
}

std::shared_ptr<PhysicalSessionCapabilities> PhysicalSessionCapabilities::Create(
    std::shared_ptr<const SessionConfiguration> configuration,
    std::shared_ptr<ConnectionLimiter> limiter,
    std::shared_ptr<RequestLoadState> request_load, dns::DNSWorker& dns_worker,
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared,
    proxyman::inbound::ReceiverSettings receiver) {
    return Create(
        std::move(configuration), std::move(limiter), std::move(request_load),
        dns_worker, std::move(prepared),
        std::make_shared<const proxyman::inbound::ReceiverSettings>(std::move(receiver)));
}

PhysicalSessionCapabilities::PhysicalSessionCapabilities(
    std::shared_ptr<const SessionConfiguration> configuration,
    std::shared_ptr<ConnectionLimiter> limiter,
    std::shared_ptr<RequestLoadState> request_load, dns::DNSWorker& dns_worker,
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared,
    std::shared_ptr<const proxyman::inbound::ReceiverSettings> receiver)
    : configuration_(std::move(configuration)), limiter_(std::move(limiter)),
      request_load_(std::move(request_load)), dns_worker_(dns_worker),
      prepared_(std::move(prepared)), receiver_(std::move(receiver)),
      user_view_(proxyman::inbound::UserStore::CaptureWorkerView()),
      tracking_(std::make_shared<SessionTrackingState>()) {
    if (!configuration_ || !limiter_ || !request_load_ || !prepared_ || !receiver_)
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
    initialized_ = true;
}

net::awaitable<void> PhysicalSessionCapabilities::ProcessTCP(
    std::unique_ptr<AsyncStream> stream, session::Context& context) {
    if (stopping_) throw IoSystemError(net::error::operation_aborted);
    if (!impl_) throw std::logic_error("domain not initialized");
    RequestLoadState::PhysicalConnectionScope physical(*request_load_);
    co_await net::co_spawn(Domain()->Executor(), impl_->handler->ProcessAcceptedTCP(
        impl_->reactor, *impl_->dispatcher, stats_, *request_load_,
        configuration_->timeouts, std::move(stream), context, &impl_->dns),
        net::bind_cancellation_slot(impl_->stop.slot(), net::use_awaitable));
}

void PhysicalSessionCapabilities::RequestStop() noexcept {
    if (stopping_) return;
    stopping_ = true;
    if (impl_) {
        impl_->stop.emit(net::cancellation_type::all);
        impl_->tasks.Tasks().Cancel();
    }
}

net::awaitable<void> PhysicalSessionCapabilities::AsyncJoin() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (!impl_) {
        joined_ = true;
        co_return;
    }
    RequestStop();
    // ProcessTCP has joined its co_spawn. The installed cancellation handler
    // still owns a GroupExecutor until cleared: retaining it cycles the domain
    // through this host and keeps the admission actor alive after pool shutdown.
    impl_->stop.slot().clear();
    std::exception_ptr failure;
    try { co_await impl_->tasks.AsyncJoin(); }
    catch (...) { failure = std::current_exception(); }
    try { co_await transport::internet::JoinXHttpClientTasks(Domain()->Services()); }
    catch (...) { if (!failure) failure = std::current_exception(); }
    // Break transport/executor leases only after real completion callbacks.
    impl_->dispatcher.reset();
    // The handler's lazily built protocol state goes with the protocol layer:
    // after outbounds, before the reactor's timeout scheduler is released.
    auto handler = std::move(impl_->handler);
    impl_->outbounds.reset();
    handler->ReleaseProtocol();
    handler.reset();
    auto& reactor = impl_->reactor;
    try { co_await TimeoutScheduler::AsyncReleaseForIoContext(reactor); }
    catch (...) { if (!failure) failure = std::current_exception(); }
    joined_ = true;
    user_view_.reset();
    impl_.reset();
    if (failure) std::rethrow_exception(failure);
}

SessionTrackingState& PhysicalSessionCapabilities::Tracking() noexcept {
    return *tracking_;
}
std::shared_ptr<SessionTrackingState>
PhysicalSessionCapabilities::TrackingOwner() const noexcept {
    return tracking_;
}
StatsShard& PhysicalSessionCapabilities::Stats() noexcept { return stats_; }
std::vector<OnlineDevice> PhysicalSessionCapabilities::GetOnlineDevices(std::string_view tag) const {
    const auto* runtime = impl_ && impl_->handler ? impl_->handler->Runtime() : nullptr;
    return runtime ? runtime->GetOnlineDevices(tag) : std::vector<OnlineDevice>{};
}
void PhysicalSessionCapabilities::UpdateUserView(
    proxyman::inbound::UserStore::WorkerView view) noexcept {
    if (stopping_) return;
    user_view_ = std::move(view);
    if (allocation_scope_.has_value()) {
        proxyman::inbound::UserStore::InstallWorkerView(user_view_);
    }
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
