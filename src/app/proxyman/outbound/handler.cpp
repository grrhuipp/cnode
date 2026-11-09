#include "app/proxyman/outbound/handler.hpp"

#include "app/dns/dns.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include "infra/log.hpp"
#include "../../../common/awaitable_task_group.hpp"

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
class OutboundPoolHost final : public std::enable_shared_from_this<OutboundPoolHost> {
public:
    OutboundPoolHost(const PreparedOutboundConfig& config, net::io_context& reactor)
        : config_(config), reactor_(reactor) {}
    ~OutboundPoolHost() {
        ReleaseInstance();
    }

    net::awaitable<OutboundProcessResult> Process(
        session::Context& context, transport::Link inbound, OutboundDialer& dialer,
        const TimeoutsConfig& timeouts, StatsShard& stats, const RelayConfig& relay,
        buf::MultiBufferBatch payload, std::chrono::seconds idle_timeout,
        std::chrono::seconds write_timeout) {
        auto* proxy = Acquire();
        struct Borrow {
            std::shared_ptr<OutboundPoolHost> host;
            ~Borrow() {
                --host->active_;
                host->CancelIfIdle();
            }
        } borrow{shared_from_this()};
        co_return co_await proxy->Process(context, inbound, dialer, timeouts, stats,
            relay, std::move(payload), idle_timeout, write_timeout);
    }

    void Retire() {
        retired_ = true;
        CancelIfIdle();
    }

    [[nodiscard]] bool IsJoined() const noexcept {
        return joined_.load(std::memory_order_acquire);
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
        ReleaseInstance();
        join_failure_ = failure;
        joined_.store(true, std::memory_order_release);
        for (auto& waiter : join_waiters_) waiter->cancel();
        join_waiters_.clear();
        if (failure) std::rethrow_exception(failure);
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
        cancel_join_spawned_ = true;
        try {
            net::co_spawn(reactor_.get_executor(),
                [self = shared_from_this()]() -> net::awaitable<void> {
                    try { co_await self->AsyncJoin(); }
                    catch (...) {}
                }, net::detached);
        } catch (...) {
            cancel_join_spawned_ = false;
        }
    }

    ::Outbound* Acquire() {
        if (retired_) throw IoSystemError(net::error::operation_aborted);
        if (!proxy_) {
            try {
                tasks_ = std::make_unique<ResidentTaskGroup>(reactor_.get_executor());
                proxy_ = NewProxy(config_, reactor_, tasks_->Tasks());
            } catch (...) {
                ReleaseInstance();
                throw;
            }
        }
        ++active_;
        return proxy_.get();
    }

    const PreparedOutboundConfig config_;
    net::io_context& reactor_;
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
    return memory::AllocateShared<Handler>(config, io_context_, dns_, dial_timeout_, tasks_);
}

// ============================================================================
// OutboundConfiguration
// ============================================================================

struct OutboundConfiguration::Hosts {
    struct Resident {
        std::shared_ptr<OutboundPoolHost> host;
    };
    net::io_context& reactor;
    std::vector<Resident> residents;

    std::shared_ptr<OutboundPoolHost> Create(const PreparedOutboundConfig& config) {
        auto host = std::make_shared<OutboundPoolHost>(config, reactor);
        residents.push_back({host});
        return host;
    }

    void Prune() {
        std::erase_if(residents, [](Resident& resident) {
            return resident.host && resident.host->IsJoined();
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
    snapshot_ = std::move(snapshot);
    ++generation_;
}

uint64_t OutboundConfiguration::Generation() const noexcept {
    return generation_;
}

std::shared_ptr<const OutboundConfiguration::Snapshot>
OutboundConfiguration::Capture() const noexcept {
    return snapshot_;
}

void OutboundConfiguration::BindHosts(net::io_context& reactor) {
    if (hosts_) throw std::logic_error("outbound hosts already bound");
    hosts_ = std::make_unique<Hosts>(Hosts{reactor, {}});
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
            co_await resident.host->AsyncJoin();
        } catch (...) { if (!failure) failure = std::current_exception(); }
    }
    hosts_.reset();
    if (failure) std::rethrow_exception(failure);
}

void OutboundConfiguration::Replace(const PreparedOutboundConfig& configuration) {
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
