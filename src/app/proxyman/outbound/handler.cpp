#include "app/proxyman/outbound/handler.hpp"

#include "app/dns/dns.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "app/session_group_executor.hpp"
#include "app/worker_stats.hpp"
#include "infra/log.hpp"
#include "../../../common/awaitable_task_group.hpp"
#include "../../../transport/internet/xhttp_session.hpp"

#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/redirect_error.hpp>
#include <asio/steady_timer.hpp>
#include <asio/this_coro.hpp>
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace proxyman::outbound {

// The host serializes cache creation and retirement, never request execution.
// Protocol pools lease independent physical domains to individual requests.
class OutboundPoolHost final : public ExecutionDomain::Hooks,
                               public std::enable_shared_from_this<OutboundPoolHost> {
public:
    explicit OutboundPoolHost(const PreparedOutboundConfig& config) : config_(config) {}
    ~OutboundPoolHost() override {
        memory::ScopedAllocationDomain scope(allocation_);
        ReleaseInstance();
    }

    void Bind(const std::shared_ptr<ExecutionDomain>& domain) {
        domain_ = domain;
        allocation_.SetLeaseGroup(domain->LeaseIdentity(), &ExecutionDomain::SharesLeaseIdentity);
    }
    std::shared_ptr<ExecutionDomain> Domain() const { return domain_.lock(); }

    net::awaitable<OutboundProcessResult> Process(
        session::Context& context, transport::Link inbound, OutboundDialer& dialer,
        const TimeoutsConfig& timeouts, StatsShard& stats, const RelayConfig& relay,
        buf::MultiBufferBatch payload, std::chrono::seconds idle_timeout,
        std::chrono::seconds write_timeout) {
        auto domain = Domain();
        if (!ExecutionDomain::Current() || !domain)
            throw IoSystemError(net::error::operation_aborted);
        auto* proxy = co_await net::co_spawn(domain->Executor(), Acquire(),
            net::bind_cancellation_slot(net::cancellation_slot{}, net::use_awaitable));
        struct Borrow {
            std::shared_ptr<OutboundPoolHost> host;
            ~Borrow() {
                if (auto domain = host->Domain()) {
                    domain->Execute([host = std::move(host)] {
                        --host->active_;
                        host->CancelIfIdle();
                    });
                }
            }
        } borrow{shared_from_this()};
        co_return co_await proxy->Process(context, inbound, dialer, timeouts, stats,
            relay, std::move(payload), idle_timeout, write_timeout);
    }

    void Retire() {
        auto domain = Domain();
        if (!domain) return;
        domain->Execute([self = shared_from_this()] {
            self->retired_ = true;
            self->CancelIfIdle();
        });
    }

    [[nodiscard]] bool IsJoined() const noexcept {
        return joined_.load(std::memory_order_acquire);
    }

    [[nodiscard]] WorkerRuntimeStatsSnapshot CollectRuntimeStats(
        bool /*include_resources*/) const noexcept {
        // Worker-level collection accounts the shared scheduler exactly once.
        return {};
    }

    net::awaitable<void> AsyncJoin() {
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        retired_ = true;
        if (joined_.load(std::memory_order_acquire)) {
            if (join_failure_) std::rethrow_exception(join_failure_);
            co_return;
        }
        if (joining_) {
            auto timer = std::make_shared<net::steady_timer>(
                co_await net::this_coro::executor);
            timer->expires_at(net::steady_timer::time_point::max());
            join_waiters_.push_back(timer);
            while (!joined_.load(std::memory_order_acquire)) {
                IoErrorCode ec;
                co_await timer->async_wait(asio::bind_cancellation_slot(
                    asio::cancellation_slot{},
                    net::redirect_error(net::use_awaitable, ec)));
            }
            if (join_failure_) std::rethrow_exception(join_failure_);
            co_return;
        }
        joining_ = true;
        std::exception_ptr failure;
        if (tasks_) {
            try { co_await tasks_->AsyncJoin(); }
            catch (...) { failure = std::current_exception(); }
        }
        auto domain = Domain();
        if (domain) {
            try { co_await transport::internet::JoinXHttpClientTasks(domain->Services()); }
            catch (...) { if (!failure) failure = std::current_exception(); }
        }
        ReleaseInstance();
        join_failure_ = failure;
        joined_.store(true, std::memory_order_release);
        for (auto& waiter : join_waiters_) waiter->cancel();
        join_waiters_.clear();
        if (failure) std::rethrow_exception(failure);
    }

    void Enter() noexcept override { allocation_scope_.emplace(allocation_); }
    void Leave() noexcept override { allocation_scope_.reset(); }
    void OnFailure(std::exception_ptr error) noexcept override {
        retired_ = true;
        if (tasks_) tasks_->Tasks().Cancel();
        try { CancelIfIdle(); } catch (...) {}
        try {
            try { if (error) std::rethrow_exception(error); }
            catch (const IoSystemError& failure) {
                if (failure.code() != net::error::operation_aborted &&
                    failure.code() != net::error::eof)
                    LOG_ERROR("outbound pool host failed tag={} > {}", config_.tag, failure.what());
            }
            catch (const std::exception& failure) {
                LOG_ERROR("outbound pool host failed tag={} > {}", config_.tag, failure.what());
            }
            catch (...) {
                LOG_ERROR("outbound pool host failed tag={} > unknown error", config_.tag);
            }
        } catch (...) {}
    }

private:
    void ReleaseInstance() noexcept {
        proxy_.reset();
        tasks_.reset();
    }

    void CancelIfIdle() {
        if (!retired_ || active_ != 0) return;
        if (tasks_) tasks_->Tasks().Cancel();
        if (cancel_join_spawned_ || joining_ || joined_.load(std::memory_order_relaxed)) return;
        if (auto domain = Domain()) {
            cancel_join_spawned_ = true;
            try {
                net::co_spawn(domain->Executor(),
                    [self = shared_from_this()]() -> net::awaitable<void> {
                        try { co_await self->AsyncJoin(); }
                        catch (...) {}
                    }, net::detached);
            } catch (...) {
                cancel_join_spawned_ = false;
            }
        }
    }

    net::awaitable<::Outbound*> Acquire() {
        if (retired_) throw IoSystemError(net::error::operation_aborted);
        if (!proxy_) {
            try {
                auto domain = Domain();
                tasks_ = std::make_unique<ResidentTaskGroup>(domain->Executor());
                proxy_ = NewProxy(config_, domain->Reactor(), tasks_->Tasks());
            } catch (...) {
                ReleaseInstance();
                throw;
            }
        }
        ++active_;
        co_return proxy_.get();
    }

    const PreparedOutboundConfig config_;
    memory::AllocationDomain allocation_;
    std::optional<memory::ScopedAllocationDomain> allocation_scope_;
    std::weak_ptr<ExecutionDomain> domain_;
    std::unique_ptr<ResidentTaskGroup> tasks_;
    std::unique_ptr<::Outbound> proxy_;
    size_t active_ = 0;
    bool retired_ = false;
    bool cancel_join_spawned_ = false;
    bool joining_ = false;
    std::vector<std::shared_ptr<net::steady_timer>> join_waiters_;
    std::exception_ptr join_failure_;
    std::atomic<bool> joined_{false};
};

// ============================================================================
// Handler
// ============================================================================

Handler::Handler(OutboundConfiguration::Entry config, net::io_context& io_context,
                 app::dns::DNS& dns, std::chrono::seconds dial_timeout,
                 AwaitableTaskGroup& tasks)
    : config_(std::move(config)) {
    dialer_.emplace(io_context, dns, config_->sender, dial_timeout);
    if (config_->host) host_ = config_->host;
    else proxy_ = NewProxy(*config_, io_context, tasks);
}


Handler::~Handler() = default;

net::awaitable<OutboundProcessResult> Handler::Dispatch(
    session::Context& ctx,
    transport::Link inbound,
    const TimeoutsConfig& timeouts,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBufferBatch first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    // Not a coroutine: the callee frame is the request's outbound frame.
    if (host_) {
        return host_->Process(ctx, inbound, *dialer_, timeouts, stats, relay_config,
                              std::move(first_payload), relay_idle_timeout,
                              relay_write_timeout);
    }
    return proxy_->Process(ctx, inbound, *dialer_, timeouts, stats, relay_config,
                           std::move(first_payload), relay_idle_timeout,
                           relay_write_timeout);
}

// ============================================================================
// HandlerLookup
// ============================================================================

HandlerLookup::HandlerLookup(const OutboundConfiguration& configuration,
                             net::io_context& io_context, app::dns::DNS& dns,
                             std::chrono::seconds dial_timeout, AwaitableTaskGroup& tasks)
    : configuration_(configuration), io_context_(io_context), dns_(dns),
      dial_timeout_(dial_timeout), tasks_(tasks) {}

std::shared_ptr<Handler> HandlerLookup::GetHandler(std::string_view tag) {
    if (const auto generation = configuration_.Generation(); generation != generation_) {
        Sync(generation);
    }
    for (auto& entry : entries_) {
        if (entry.config->tag != tag) continue;
        if (!entry.handler) entry.handler = Instantiate(entry.config);
        return entry.handler;
    }
    return {};
}

void HandlerLookup::Refresh() noexcept {
    try {
        Sync(configuration_.Generation());
    } catch (...) {
        // Only allocation can fail; clearing releases every retired handler.
        entries_.clear();
        generation_ = 0;
    }
}

void HandlerLookup::Sync(uint64_t generation) {
    memory::ScopedWorkerAllocation worker_allocation;
    const auto snapshot = configuration_.Capture();
    memory::ThreadLocalVector<Entry> next;
    next.reserve(snapshot->size());
    for (const auto& config : *snapshot) {
        std::shared_ptr<Handler> handler;
        for (auto& entry : entries_) {
            if (entry.config == config) {
                handler = std::move(entry.handler);
                break;
            }
        }
        next.push_back(Entry{config, std::move(handler)});
    }
    // In-flight requests keep retired handlers through their own handles.
    entries_.swap(next);
    generation_ = generation;
}

std::shared_ptr<Handler> HandlerLookup::Instantiate(const OutboundConfiguration::Entry& config) {
    memory::ScopedWorkerAllocation worker_allocation;
    return memory::AllocateShared<Handler>(config, io_context_, dns_, dial_timeout_, tasks_);
}

// ============================================================================
// OutboundConfiguration
// ============================================================================

struct OutboundConfiguration::Hosts {
    struct Resident {
        std::shared_ptr<OutboundPoolHost> host;
        std::shared_ptr<ExecutionDomain> domain;
    };
    net::io_context& reactor;
    uint32_t worker_id;
    std::shared_ptr<GroupCoordinator> coordinator;
    std::vector<Resident> residents;

    std::shared_ptr<OutboundPoolHost> Create(const PreparedOutboundConfig& config) {
        auto host = std::make_shared<OutboundPoolHost>(config);
        auto domain = ExecutionDomain::Create(
            reactor, worker_id, reactor.get_executor(), host, coordinator);
        host->Bind(domain);
        residents.push_back({host, std::move(domain)});
        return host;
    }

    void Prune() {
        std::erase_if(residents, [this](Resident& resident) {
            if (!resident.host || !resident.host->IsJoined()) return false;
            if (resident.domain && !resident.domain->CanDestroyDirectlyOn(worker_id)) {
                resident.host.reset();
                auto* domain = resident.domain.get();
                domain->Execute([domain = std::move(resident.domain)]() mutable {
                    domain.reset();
                });
            }
            return true;
        });
    }
};

OutboundConfiguration::OutboundConfiguration(
    const std::vector<PreparedOutboundConfig>& configurations) {
    auto snapshot = std::make_shared<Snapshot>();
    snapshot->reserve(configurations.size());
    for (const auto& config : configurations)
        snapshot->push_back(Prepare(config));
    Publish(std::move(snapshot));
}

OutboundConfiguration::~OutboundConfiguration() = default;

OutboundConfiguration::Entry OutboundConfiguration::Prepare(
    const PreparedOutboundConfig& configuration) {
    if (configuration.tag.empty() || !configuration.create) {
        throw std::logic_error(
            "prepared outbound '" + configuration.tag + "' has no tag or creator");
    }
    auto entry = std::make_shared<Configuration>(configuration);
    if (hosts_ && configuration.create.persistent_state)
        entry->host = hosts_->Create(configuration);
    return entry;
}

void OutboundConfiguration::Publish(std::shared_ptr<const Snapshot> snapshot) noexcept {
    snapshot_.store(std::move(snapshot), std::memory_order_release);
    // Pairs with the acquire load in Generation(): a reader seeing this value
    // also sees the snapshot stored above.
    generation_.fetch_add(1, std::memory_order_release);
}

uint64_t OutboundConfiguration::Generation() const noexcept {
    return generation_.load(std::memory_order_acquire);
}

std::shared_ptr<const OutboundConfiguration::Snapshot>
OutboundConfiguration::Capture() const noexcept {
    return snapshot_.load(std::memory_order_acquire);
}

void OutboundConfiguration::BindHosts(net::io_context& reactor, uint32_t worker_id,
    std::shared_ptr<GroupCoordinator> coordinator, app::dns::DNSWorker& /*dns_worker*/,
    std::chrono::seconds /*dial_timeout*/) {
    const std::lock_guard lock(publication_mutex_);
    if (hosts_) throw std::logic_error("outbound hosts already bound");
    hosts_ = std::make_unique<Hosts>(Hosts{
        reactor, worker_id, std::move(coordinator), {}});
    auto snapshot = std::make_shared<Snapshot>();
    const auto previous = Capture();
    snapshot->reserve(previous->size());
    for (const auto& config : *previous) snapshot->push_back(Prepare(*config));
    Publish(std::move(snapshot));
}

net::awaitable<void> OutboundConfiguration::AsyncJoinHosts() {
    co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
    if (!hosts_) co_return;
    std::exception_ptr failure;
    for (auto& resident : hosts_->residents) {
        try {
            co_await net::co_spawn(resident.domain->Executor(),
                resident.host->AsyncJoin(), net::use_awaitable);
        } catch (...) { if (!failure) failure = std::current_exception(); }
        if (resident.domain && !resident.domain->CanDestroyDirectlyOn(hosts_->worker_id)) {
            auto* domain = resident.domain.get();
            domain->Execute([host = std::move(resident.host),
                             domain = std::move(resident.domain)]() mutable {
                host.reset();
                domain.reset();
            });
        }
    }
    // Release all domain roots before the coordinator's Finalize barrier.
    hosts_.reset();
    if (failure) std::rethrow_exception(failure);
}

net::awaitable<void> OutboundConfiguration::CollectRuntimeStats(
    WorkerRuntimeStatsSnapshot& result, bool include_resources) {
    struct Sample {
        std::weak_ptr<OutboundPoolHost> host;
        std::weak_ptr<ExecutionDomain> domain;
    };
    std::vector<Sample> samples;
    {
        const std::lock_guard lock(publication_mutex_);
        if (!hosts_) co_return;
        hosts_->Prune();
        samples.reserve(hosts_->residents.size());
        for (const auto& resident : hosts_->residents) {
            if (resident.host && !resident.host->IsJoined() && resident.domain) {
                samples.push_back(Sample{
                    .host = resident.host,
                    .domain = resident.domain,
                });
            }
        }
    }
    for (const auto& sample : samples) {
        auto domain = sample.domain.lock();
        if (!domain) continue;
        auto executor = domain->Executor();
        const auto values = co_await net::co_spawn(std::move(executor),
            [weak_host = sample.host, domain = std::move(domain), include_resources]() mutable
                -> net::awaitable<WorkerRuntimeStatsSnapshot> {
                WorkerRuntimeStatsSnapshot snapshot;
                auto host = weak_host.lock();
                if (host && !host->IsJoined()) {
                    snapshot = host->CollectRuntimeStats(include_resources);
                }
                host.reset();
                domain.reset();
                co_return snapshot;
            }, net::use_awaitable);
        result.memory.pool_mapped_bytes += values.memory.pool_mapped_bytes;
        result.memory.pool_direct_bytes += values.memory.pool_direct_bytes;
        result.memory.pool_idle_bytes += values.memory.pool_idle_bytes;
        result.memory.pool_chunks += values.memory.pool_chunks;
        if (values.resources && result.resources) {
            result.resources->timeout_events += values.resources->timeout_events;
            result.resources->timeout_heap_capacity += values.resources->timeout_heap_capacity;
            result.resources->timeout_waiters += values.resources->timeout_waiters;
        }
    }
}

void OutboundConfiguration::Replace(const PreparedOutboundConfig& configuration) {
    const std::lock_guard lock(publication_mutex_);
    if (hosts_) hosts_->Prune();
    auto snapshot = std::make_shared<Snapshot>(*Capture());
    snapshot->reserve(snapshot->size() + 1);
    const size_t previous_residents = hosts_ ? hosts_->residents.size() : 0;
    try {
        auto candidate = Prepare(configuration);
        for (auto& entry : *snapshot) {
            if (entry->tag != configuration.tag) continue;
            if (entry->host) entry->host->Retire();
            entry = std::move(candidate);
            Publish(std::move(snapshot));
            return;
        }
        snapshot->push_back(std::move(candidate));
        Publish(std::move(snapshot));
    } catch (...) {
        if (hosts_) hosts_->residents.resize(previous_residents);
        throw;
    }
}

void OutboundConfiguration::Remove(std::string_view tag) {
    const std::lock_guard lock(publication_mutex_);
    if (hosts_) hosts_->Prune();
    auto snapshot = std::make_shared<Snapshot>(*Capture());
    std::erase_if(*snapshot, [tag](const Entry& entry) {
        if (entry->tag != tag) return false;
        if (entry->host) entry->host->Retire();
        return true;
    });
    Publish(std::move(snapshot));
}

}  // namespace proxyman::outbound
