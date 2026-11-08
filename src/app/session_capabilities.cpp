#include "app/session_capabilities.hpp"

#include "app/dispatcher/default_dispatcher.hpp"
#include "app/dns/dns.hpp"
#include "app/proxyman/inbound/factory.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "app/rate_limiter.hpp"
#include "app/request_load_state.hpp"
#include "app/router/router.hpp"
#include "app/session_tracking.hpp"
#include "app/stats.hpp"
#include "app/worker_runtime_config.hpp"
#include "app/worker_stats.hpp"
#include "common/rule.hpp"
#include "common/container_util.hpp"
#include "common/session.hpp"
#include "infra/log.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/timeout_scheduler.hpp"
#include "../common/awaitable_task_group.hpp"
#include "../transport/internet/xhttp_session.hpp"
#include "../proxy/inbound_admission.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/redirect_error.hpp>
#include <asio/this_coro.hpp>
#include <stdexcept>
#include <algorithm>
#include <vector>
namespace app {

PhysicalSessionRegistry::PhysicalSessionRegistry(
    net::io_context& io, uint32_t worker_id, StatsShard& totals,
    SessionTrackingState& traffic, Records& records)
    : io_(io), worker_id_(worker_id), totals_(totals),
      traffic_(traffic), records_(records), changed_(io, 1) {}

std::shared_ptr<PhysicalSessionRecord> PhysicalSessionRegistry::Register(
    std::shared_ptr<PhysicalSessionCapabilities> capabilities,
    std::shared_ptr<ExecutionDomain> domain) {
    if (!capabilities || !domain || !io_.get_executor().running_in_this_thread())
        throw std::logic_error("session registration requires admission owner");
    if (closing_) throw IoSystemError(net::error::operation_aborted);
    auto record = std::make_shared<PhysicalSessionRecord>();
    record->inbound_tag = capabilities->Receiver().inbound_tag;
    record->accounting_key = capabilities->Receiver().accounting_key;
    record->capabilities = std::move(capabilities);
    record->domain = std::move(domain);
    records_.emplace(record.get(), record);
    return record;
}

net::awaitable<void> PhysicalSessionRegistry::Retire(
    std::shared_ptr<PhysicalSessionRecord> record) {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (!record || ExecutionDomain::Current() != record->domain)
        throw std::logic_error("session retirement requires its execution domain");
    record->final_stats = record->capabilities->Stats().Snapshot();
    record->completed_traffic =
        record->capabilities->Tracking().ExtractAvailableTraffic(record->accounting_key);
    co_await net::co_spawn(io_, RetireOnOwner(std::move(record)), net::use_awaitable);
}

void PhysicalSessionRegistry::CompleteOnOwner(
    const std::shared_ptr<PhysicalSessionRecord>& record) {
    if (!record || record->finished.load(std::memory_order_acquire)) return;
    traffic_.MergeCompletedTraffic(record->accounting_key, record->completed_traffic);
    totals_.hot.bytes_in += record->final_stats.bytes_in;
    totals_.hot.bytes_out += record->final_stats.bytes_out;
    totals_.cold.connections_total += record->final_stats.connections_total;
    totals_.cold.errors += record->final_stats.errors;
    record->finished.store(true, std::memory_order_release);
    records_.erase(record.get());
    MaybeShrinkHashContainer(records_);
    if (record->domain && !record->domain->CanDestroyDirectlyOn(worker_id_)) {
        record->capabilities.reset();
        auto* domain = record->domain.get();
        domain->Execute([domain = std::move(record->domain)]() mutable {
            domain.reset();
        });
    }
    (void)changed_.try_send(IoErrorCode{});
}

void PhysicalSessionRegistry::CancelRegistration(
    const std::shared_ptr<PhysicalSessionRecord>& record) noexcept {
    if (!record) return;
    records_.erase(record.get());
    MaybeShrinkHashContainer(records_);
    (void)changed_.try_send(IoErrorCode{});
}

net::awaitable<void> PhysicalSessionRegistry::RetireOnOwner(
    std::shared_ptr<PhysicalSessionRecord> record) {
    CompleteOnOwner(record);
    co_return;
}

net::awaitable<void> PhysicalSessionRegistry::AsyncJoin() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    closing_ = true;
    while (std::any_of(records_.begin(), records_.end(), [](const auto& entry) {
        return !entry.second->finished.load(std::memory_order_acquire);
    })) {
        co_await changed_.async_receive(net::use_awaitable);
    }
}

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

    Impl(PhysicalSessionCapabilities& owner_value, net::io_context& io,
         AwaitableTaskGroup* external_tasks = nullptr)
        : owner(owner_value), reactor(io), dns(owner.dns_worker_),
          resident_tasks(external_tasks ? nullptr :
              std::make_unique<ResidentTaskGroup>(owner.Domain()->Executor())),
          tasks(external_tasks ? *external_tasks : resident_tasks->Tasks()) {
        handler = memory::AllocateShared<proxyman::inbound::Handler>(
            owner.receiver_,
            proxyman::inbound::Handler::LazyProtocol{
                owner.prepared_, &owner.stats_, owner.limiter_.get()},
            *owner.limiter_);
        outbounds = std::make_unique<HandlerLookup>(
            *owner.configuration_->outbounds, io, dns,
            owner.configuration_->timeouts.DialTimeout(), tasks);
        dispatcher = std::make_unique<dispatcher::DefaultDispatcher>(
            *owner.configuration_->router, *outbounds, *owner.configuration_->policy,
            *owner.tracking_, dns, *owner.request_load_);
    }

    PhysicalSessionCapabilities& owner;
    net::io_context& reactor;
    dns::DNS dns;
    std::unique_ptr<ResidentTaskGroup> resident_tasks;
    AwaitableTaskGroup& tasks;
    std::unique_ptr<UserOnlineTracker> tracker;
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

void PhysicalSessionCapabilities::Initialize(net::io_context& reactor,
                                             AwaitableTaskGroup& tasks) {
    if (stopping_) throw IoSystemError(net::error::operation_aborted);
    if (!impl_) impl_ = std::make_unique<Impl>(*this, reactor, &tasks);
    initialized_ = true;
}

UserOnlineTracker& PhysicalSessionCapabilities::Tracker() {
    if (!impl_) throw std::logic_error("domain not initialized");
    if (!impl_->tracker) impl_->tracker = std::make_unique<UserOnlineTracker>();
    return *impl_->tracker;
}

std::shared_ptr<InboundTransportStreamHandler>
PhysicalSessionCapabilities::MakeAuthenticatedStreamSink(
    const session::Context& context, std::shared_ptr<ConnectionFamily> family) {
    if (stopping_) throw IoSystemError(net::error::operation_aborted);
    if (!impl_) throw std::logic_error("domain not initialized");
    return impl_->handler->NewAuthenticatedStreamSink(
        Domain()->Reactor(), *impl_->dispatcher, stats_, *request_load_,
        configuration_->timeouts, context, std::move(family));
}

net::awaitable<void> PhysicalSessionCapabilities::ProcessNativeDatagram(
    transport::Link link, const UserProfile& profile, session::Context& context) {
    if (stopping_) throw IoSystemError(net::error::operation_aborted);
    if (!impl_) throw std::logic_error("domain not initialized");
    ConnectionStatsScope connection_stats(stats_);
    auto admission = co_await proxy::AdmitNativeAssociation(
        context, profile, &Tracker(), limiter_.get(), stats_);
    if (!admission || stopping_) co_return;
    auto result = co_await impl_->dispatcher->Dispatch(
        Domain()->Reactor(), receiver_->dispatch_policy, nullptr, link,
        InitialPayload{}, context, stats_, configuration_->timeouts);
    if (result.error != ErrorCode::OK) {
        LOG_CONN_DEBUG(context, "UDP dispatcher ended > {} up={}B down={}B",
                       ErrorCodeToString(result.error), result.bytes_up,
                       result.bytes_down);
    }
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
        impl_->tasks.Cancel();
    }
}

net::awaitable<void> PhysicalSessionCapabilities::AsyncJoin() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (!impl_) {
        joined_ = true;
        co_return;
    }
    if (impl_->resident_tasks) RequestStop();
    else stopping_ = true; // The caller already joined the borrowed scope.
    // ProcessTCP has joined its co_spawn. The installed cancellation handler
    // still owns a GroupExecutor until cleared: retaining it cycles the domain
    // through this host and keeps the admission actor alive after pool shutdown.
    impl_->stop.slot().clear();
    std::exception_ptr failure;
    try {
        if (impl_->resident_tasks) co_await impl_->resident_tasks->AsyncJoin();
    }
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
    auto devices = runtime ? runtime->GetOnlineDevices(tag) : std::vector<OnlineDevice>{};
    if (impl_ && impl_->tracker) {
        auto native_devices = impl_->tracker->GetOnlineDevices(tag);
        devices.insert(devices.end(),
            std::make_move_iterator(native_devices.begin()),
            std::make_move_iterator(native_devices.end()));
    }
    return devices;
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

} // namespace app
