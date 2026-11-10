#include "app/proxyman/outbound/handler.hpp"

#include "app/dns/dns.hpp"
#include <map>
#include <stdexcept>
#include <utility>

namespace proxyman::outbound {

// ============================================================================
// Handler
// ============================================================================

Handler::Handler(memory::worker_memory& pool,
                 OutboundConfiguration::Entry config, net::io_context& io_context,
                 app::dns::DNS& dns, std::chrono::seconds dial_timeout,
                 AwaitableTaskGroup& tasks)
    : config_(std::move(config))
    , dialer_(io_context, dns, config_->sender, dial_timeout)
    , proxy_(NewProxy(*config_, io_context, tasks, pool)) {
}


Handler::~Handler() = default;

net::awaitable<OutboundProcessResult> Handler::Dispatch(
    session::Context& ctx,
    transport::Link inbound,
    const TimeoutsConfig& timeouts,
    StatsShard& stats,
    const RelayConfig& relay_config,
    buf::MultiBufferBatch&& first_payload,
    std::chrono::seconds relay_idle_timeout,
    std::chrono::seconds relay_write_timeout) {
    // Not a coroutine: the callee frame is the request's outbound frame.
    return proxy_->Process(ctx, inbound, dialer_, timeouts, stats, relay_config,
                           std::move(first_payload), relay_idle_timeout,
                           relay_write_timeout);
}

// ============================================================================
// HandlerLookup
// ============================================================================

HandlerLookup::HandlerLookup(memory::worker_memory& pool,
                             const OutboundConfiguration& configuration,
                             net::io_context& io_context, app::dns::DNS& dns,
                             std::chrono::seconds dial_timeout, AwaitableTaskGroup& tasks)
    : pool_(pool), configuration_(configuration), io_context_(io_context), dns_(dns),
      dial_timeout_(dial_timeout), tasks_(tasks), entries_(pool.resource()) {}

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
    const auto& snapshot = configuration_.Entries();
    memory::Vector<Entry> next(pool_.resource());
    next.reserve(snapshot.size());
    for (const auto& config : snapshot) {
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
    return memory::AllocateShared<Handler>(
        pool_.resource(), pool_, config, io_context_, dns_, dial_timeout_, tasks_);
}

// ============================================================================
// OutboundConfiguration
// ============================================================================

OutboundConfiguration::OutboundConfiguration(
    const std::vector<PreparedOutboundConfig>& configurations) {
    entries_.reserve(configurations.size());
    for (const auto& config : configurations)
        entries_.push_back(Prepare(config));
    generation_ = 1;
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

uint64_t OutboundConfiguration::Generation() const noexcept {
    return generation_;
}

void OutboundConfiguration::Replace(const PreparedOutboundConfig& configuration) {
    auto candidate = Prepare(configuration);
    for (auto& entry : entries_) {
        if (entry->tag != configuration.tag) continue;
        entry = std::move(candidate);
        ++generation_;
        return;
    }
    entries_.push_back(std::move(candidate));
    ++generation_;
}

void OutboundConfiguration::Remove(std::string_view tag) {
    std::erase_if(entries_, [tag](const Entry& entry) {
        return entry->tag == tag;
    });
    ++generation_;
}

// ============================================================================
// Outbound Factory Registration
// ============================================================================

namespace {

using CreatorMap = std::map<
    std::string,
    std::optional<PreparedOutboundProxy> (*)(
        const infra::OutboundSourceConfig& config),
    std::less<>>;

CreatorMap& Proxies() noexcept {
    static CreatorMap proxies;
    return proxies;
}

}  // namespace

void RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundProxy> (*creator)(
        const infra::OutboundSourceConfig& config)) {
    if (protocol.empty() || !creator) {
        throw std::invalid_argument(
            "invalid outbound protocol registration for '" +
            std::string(protocol) + "'");
    }
    if (!Proxies().try_emplace(std::string(protocol), creator).second) {
        throw std::logic_error(
            "duplicate outbound protocol registration for '" +
            std::string(protocol) + "'");
    }
}

std::optional<PreparedOutboundConfig> PrepareOutboundConfig(
    const infra::OutboundSourceConfig& config) {
    auto& proxies = Proxies();
    auto it = proxies.find(config.protocol);
    if (it == proxies.end()) {
        return std::nullopt;
    }
    auto prepared = it->second(config);
    if (!prepared || !prepared->create) {
        return std::nullopt;
    }
    // Xray: the handler-level sendThrough wins over any protocol default.
    if (config.send_through) {
        prepared->sender.send_through = *config.send_through;
    }
    prepared->sender.passthrough = config.passthrough;
    return PreparedOutboundConfig{
        .tag = config.tag,
        .protocol = config.protocol,
        .sender = std::move(prepared->sender),
        .create = std::move(prepared->create),
    };
}

std::unique_ptr<::Outbound> NewProxy(
    const PreparedOutboundConfig& config,
    ::net::io_context& io_context,
    ::AwaitableTaskGroup& tasks,
    memory::worker_memory& pool) {
    if (!config.create) {
        throw std::logic_error(
            "prepared outbound '" + config.tag + "' has no creator");
    }
    auto proxy = config.create(config.tag, io_context, tasks, pool);
    if (!proxy) {
        throw std::logic_error(
            "prepared outbound '" + config.tag + "' creator returned null");
    }
    return proxy;
}

bool HasProxy(std::string_view protocol) {
    return Proxies().contains(protocol);
}

}  // namespace proxyman::outbound
