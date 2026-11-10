#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "infra/config_types.hpp"
#include "proxy/outbound.hpp"
#include "transport/internet/outbound_target_builder.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>
class AwaitableTaskGroup;
namespace app::dns {
class DNS;
}  // namespace app::dns

namespace proxyman::outbound {

class OutboundProtocolSettings {
public:
    virtual ~OutboundProtocolSettings() noexcept = default;
};

template <typename T>
struct TypedOutboundProtocolSettings final : OutboundProtocolSettings {
    explicit TypedOutboundProtocolSettings(T v) : value(std::move(v)) {}
    T value;
};

// Constructs the protocol instance for one Worker: its native reactor and
// resident task group (joined before the Worker's teardown). Dialing goes
// through the owning Handler's OutboundDialer, never through creator state.
struct PreparedOutboundCreator {
    using CreateFn = std::unique_ptr<::Outbound> (*)(
        std::string_view tag,
        const std::shared_ptr<const OutboundProtocolSettings>& settings,
        ::net::io_context& io_context,
        ::AwaitableTaskGroup& tasks,
        memory::worker_memory& pool);

    std::shared_ptr<const OutboundProtocolSettings> settings;
    CreateFn create_fn = nullptr;

    PreparedOutboundCreator() noexcept = default;

    PreparedOutboundCreator(
        std::shared_ptr<const OutboundProtocolSettings> s,
        CreateFn fn) noexcept
        : settings(std::move(s))
        , create_fn(fn) {}

    [[nodiscard]] explicit operator bool() const noexcept {
        return create_fn != nullptr;
    }

    [[nodiscard]] std::unique_ptr<::Outbound> operator()(
        std::string_view tag,
        ::net::io_context& io_context,
        ::AwaitableTaskGroup& tasks,
        memory::worker_memory& pool) const {
        return create_fn(tag, settings, io_context, tasks, pool);
    }
};

template <typename State, auto Fn>
[[nodiscard]] PreparedOutboundCreator MakePreparedOutboundCreator(State state) {
    using Decayed = std::decay_t<State>;
    using Holder = TypedOutboundProtocolSettings<Decayed>;
    return PreparedOutboundCreator{
        std::make_shared<const Holder>(std::move(state)),
        +[](std::string_view tag,
            const std::shared_ptr<const OutboundProtocolSettings>& base,
            ::net::io_context& io_context,
            ::AwaitableTaskGroup& tasks,
            memory::worker_memory& pool) -> std::unique_ptr<::Outbound> {
            const auto* holder = static_cast<const Holder*>(base.get());
            return Fn(tag, std::shared_ptr<const Decayed>(base, &holder->value),
                      io_context, tasks, pool);
        }};
}

// Xray core.OutboundHandlerConfig after preparation: tag, sender settings and
// the protocol constructor. Immutable once published.
struct PreparedOutboundConfig {
    std::string tag;
    std::string protocol;
    OutboundSenderSettings sender;
    PreparedOutboundCreator create;
};
// What a protocol contributes to its Handler: the protocol constructor and the
// sender settings with its stream defaults applied. The top-level sendThrough
// of the source config overrides the protocol's default bind.
struct PreparedOutboundProxy {
    PreparedOutboundCreator create;
    OutboundSenderSettings sender;
};

// Cold-path registration API. Proxyman receives an already normalized
// source config and produces an immutable prepared handler constructor.
void RegisterProxy(
    std::string_view protocol,
    std::optional<PreparedOutboundProxy> (*)(
        const infra::OutboundSourceConfig& config));

[[nodiscard]] std::optional<PreparedOutboundConfig> PrepareOutboundConfig(
    const infra::OutboundSourceConfig& config);

// Prepared configs are runtime invariants. Construction failures throw;
// callers must not continue with a partially installed outbound handler.
// `tasks` must outlive the protocol instance and join everything it starts.
[[nodiscard]] std::unique_ptr<::Outbound> NewProxy(
    const PreparedOutboundConfig& config,
    ::net::io_context& io_context,
    ::AwaitableTaskGroup& tasks,
    memory::worker_memory& pool);

[[nodiscard]] bool HasProxy(std::string_view protocol);

// ============================================================================
// OutboundConfiguration - the one outbound publication of a Worker
//
// Xray app/proxyman/outbound.Manager: prepared handler configs by tag. Worker-
// level dispatch and every physical session read the same snapshot through
// HandlerLookup; dynamic add/replace/remove updates only this publication.
// Mutations and lookups run on the owning Worker; a lookup resynchronizes
// its cached handlers only when the generation changed.
// ============================================================================
class OutboundConfiguration final {
public:
    using Entry = std::shared_ptr<const PreparedOutboundConfig>;
    using Snapshot = std::vector<Entry>;

    explicit OutboundConfiguration(
        const std::vector<PreparedOutboundConfig>& configurations);
    ~OutboundConfiguration();
    OutboundConfiguration(const OutboundConfiguration&) = delete;
    OutboundConfiguration& operator=(const OutboundConfiguration&) = delete;

    [[nodiscard]] uint64_t Generation() const noexcept;
    [[nodiscard]] const Snapshot& Entries() const noexcept { return entries_; }
    // Transactional: a failed prepare leaves the published entries intact.
    void Replace(const PreparedOutboundConfig& configuration);
    void Remove(std::string_view tag);

private:
    Entry Prepare(const PreparedOutboundConfig& configuration);

    Snapshot entries_;
    uint64_t generation_ = 0;
};

// ============================================================================
// Handler - Xray app/proxyman/outbound.Handler
//
// One concrete handler per outbound tag per executing domain. It owns the
// prepared sender settings (through its configuration entry), the tag's
// OutboundDialer and the protocol instance.
// ============================================================================
class Handler final : public memory::WorkerAllocated {
public:
    // Stateless tag: the protocol instance and dialer live in the requesting
    // domain (reactor, DNS client and resident task group outlive the handler).
    Handler(memory::worker_memory& pool,
            OutboundConfiguration::Entry config, net::io_context& io_context,
            app::dns::DNS& dns, std::chrono::seconds dial_timeout,
            AwaitableTaskGroup& tasks);
    ~Handler();
    Handler(const Handler&) = delete;
    Handler& operator=(const Handler&) = delete;

    [[nodiscard]] std::string_view Tag() const noexcept { return config_->tag; }

    // The caller keeps this handler alive until the returned awaitable completes.
    [[nodiscard]] net::awaitable<OutboundProcessResult> Dispatch(
        session::Context& ctx,
        transport::Link inbound,
        const TimeoutsConfig& timeouts,
        StatsShard& stats,
        const RelayConfig& relay_config,
        buf::MultiBufferBatch&& first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout);

private:
    // Destroyed in reverse order: the protocol instance before the dialer,
    // the dialer before the sender settings it borrows from config_.
    OutboundConfiguration::Entry config_;
    OutboundDialer dialer_;
    std::unique_ptr<::Outbound> proxy_;
};

// ============================================================================
// HandlerLookup - per-domain view of the OutboundConfiguration publication
//
// The dispatcher's only outbound lookup. Instantiates a tag's Handler lazily
// in the owning domain and keeps it until the tag is replaced or removed;
// returned handles keep the handler alive for the whole request.
// ============================================================================
class HandlerLookup final : public memory::WorkerAllocated {
public:
    HandlerLookup(memory::worker_memory& pool,
                  const OutboundConfiguration& configuration,
                  net::io_context& io_context, app::dns::DNS& dns,
                  std::chrono::seconds dial_timeout, AwaitableTaskGroup& tasks);
    HandlerLookup(const HandlerLookup&) = delete;
    HandlerLookup& operator=(const HandlerLookup&) = delete;

    [[nodiscard]] std::shared_ptr<Handler> GetHandler(std::string_view tag);

    // Cold path after a publication: drop handlers of replaced or removed
    // tags now instead of at the next lookup. Under allocation failure all
    // cached handlers are dropped and the next lookup resynchronizes.
    void Refresh() noexcept;
    void Clear() noexcept {
        entries_.clear();
        generation_ = 0;
    }

private:
    struct Entry {
        OutboundConfiguration::Entry config;
        std::shared_ptr<Handler> handler;
    };

    void Sync(uint64_t generation);
    [[nodiscard]] std::shared_ptr<Handler> Instantiate(
        const OutboundConfiguration::Entry& config);

    memory::worker_memory& pool_;
    const OutboundConfiguration& configuration_;
    net::io_context& io_context_;
    app::dns::DNS& dns_;
    const std::chrono::seconds dial_timeout_;
    AwaitableTaskGroup& tasks_;
    uint64_t generation_ = 0;  // Publications start at 1.
    memory::Vector<Entry> entries_;
};

}  // namespace proxyman::outbound
