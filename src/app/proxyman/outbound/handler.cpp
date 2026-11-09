#include "app/proxyman/outbound/handler.hpp"

#include "app/dns/dns.hpp"
#include "app/proxyman/outbound/factory.hpp"
#include <stdexcept>
#include <utility>

namespace proxyman::outbound {

// ============================================================================
// Handler
// ============================================================================

Handler::Handler(OutboundConfiguration::Entry config, net::io_context& io_context,
                 app::dns::DNS& dns, std::chrono::seconds dial_timeout,
                 AwaitableTaskGroup& tasks)
    : config_(std::move(config)) {
    dialer_.emplace(io_context, dns, config_->sender, dial_timeout);
    proxy_ = NewProxy(*config_, io_context, tasks);
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
        Clear();
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
    return std::make_shared<const PreparedOutboundConfig>(configuration);
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

void OutboundConfiguration::Replace(const PreparedOutboundConfig& configuration) {
    auto snapshot = std::make_shared<Snapshot>(*Capture());
    snapshot->reserve(snapshot->size() + 1);
    auto candidate = Prepare(configuration);
    for (auto& entry : *snapshot) {
        if (entry->tag != configuration.tag) continue;
        entry = std::move(candidate);
        Publish(std::move(snapshot));
        return;
    }
    snapshot->push_back(std::move(candidate));
    Publish(std::move(snapshot));
}

void OutboundConfiguration::Remove(std::string_view tag) {
    auto snapshot = std::make_shared<Snapshot>(*Capture());
    std::erase_if(*snapshot, [tag](const Entry& entry) {
        return entry->tag == tag;
    });
    Publish(std::move(snapshot));
}

}  // namespace proxyman::outbound
