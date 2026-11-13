#include "app/outbound_handler.hpp"
#include "app/relay.hpp"

#include "app/dns.hpp"
#include "common/allocator.hpp"
#include <map>
#include <stdexcept>
#include <utility>
#include <string>
#include <vector>

namespace app {

// ============================================================================
// OutboundHandler
// ============================================================================

OutboundHandler::OutboundHandler(PreparedOutboundConfig config, net::io_context& io_context,
                                 app::DNS& dns, std::chrono::seconds dial_timeout,
                                 common::AwaitableTaskGroup& tasks)
    : config_(std::move(config))
    , dialer_(io_context, dns, config_.sender, dial_timeout)
    , proxy_(NewProxy(config_, io_context, tasks)) {
}

OutboundHandler::~OutboundHandler() = default;

net::awaitable<proxy::OutboundProcessResult> OutboundHandler::Dispatch(
    common::Context& ctx,
    transport::Link inbound,
    const infra::TimeoutsConfig& timeouts,
    app::StatsShard& stats,
    const app::RelayConfig& relay_config,
    common::MultiBufferBatch&& first_payload) {
    // Not a coroutine: the callee frame is the request's outbound frame.
    return proxy_->Process(ctx, inbound, dialer_, timeouts, stats, relay_config,
                           std::move(first_payload));
}

// ============================================================================
// HandlerRegistry
// ============================================================================

OutboundHandlerRegistry::OutboundHandlerRegistry(
    const std::vector<PreparedOutboundConfig>& configurations,
    net::io_context& io_context, app::DNS& dns,
    std::chrono::seconds dial_timeout, common::AwaitableTaskGroup& tasks)
    : io_context_(io_context), dns_(dns), dial_timeout_(dial_timeout), tasks_(tasks) {
    handlers_.reserve(configurations.size());
    for (const auto& configuration : configurations) {
        auto handler = Instantiate(configuration);
        if (!handlers_.try_emplace(configuration.tag,
                                   std::move(handler)).second) {
            throw std::logic_error(
                "duplicate prepared outbound tag '" + configuration.tag + "'");
        }
    }
}

OutboundHandlerRegistry::~OutboundHandlerRegistry() = default;

std::shared_ptr<OutboundHandler> OutboundHandlerRegistry::GetHandler(std::string_view tag) const noexcept {
    const auto it = handlers_.find(tag);
    return it == handlers_.end() ? nullptr : it->second;
}

void OutboundHandlerRegistry::Replace(const PreparedOutboundConfig& configuration) {
    auto handler = Instantiate(configuration);
    // In-flight requests keep any retired handler through their own handles.
    handlers_.insert_or_assign(configuration.tag, std::move(handler));
}

void OutboundHandlerRegistry::Remove(std::string_view tag) {
    const auto it = handlers_.find(tag);
    if (it == handlers_.end()) return;
    handlers_.erase(it);
    common::MaybeShrinkHashContainer(handlers_, 8);
}

std::shared_ptr<OutboundHandler> OutboundHandlerRegistry::Instantiate(
    const PreparedOutboundConfig& configuration) const {
    if (configuration.tag.empty() || !configuration.create) {
        throw std::logic_error(
            "prepared outbound '" + configuration.tag + "' has no tag or creator");
    }
    return std::make_shared<OutboundHandler>(
        configuration, io_context_, dns_, dial_timeout_, tasks_);
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

std::unique_ptr<::proxy::Outbound> NewProxy(
    const PreparedOutboundConfig& config,
    ::net::io_context& io_context,
    ::common::AwaitableTaskGroup& tasks) {
    if (!config.create) {
        throw std::logic_error(
            "prepared outbound '" + config.tag + "' has no creator");
    }
    auto proxy = config.create(config.tag, io_context, tasks);
    if (!proxy) {
        throw std::logic_error(
            "prepared outbound '" + config.tag + "' creator returned null");
    }
    return proxy;
}

}  // namespace app
