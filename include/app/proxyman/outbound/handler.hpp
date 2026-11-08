#pragma once

#include "app/proxyman/outbound/prepared_config.hpp"
#include "common/allocator.hpp"
#include "proxy/outbound.hpp"
#include "transport/internet/outbound_target_builder.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <vector>

class AwaitableTaskGroup;
class GroupCoordinator;
struct WorkerRuntimeStatsSnapshot;
namespace app::dns {
class DNS;
class DNSWorker;
}  // namespace app::dns

namespace proxyman::outbound {

// Stable cache namespace; active physical sessions have independent domains.
class OutboundPoolHost;

// ============================================================================
// OutboundConfiguration - the one outbound publication of a Worker
//
// Xray app/proxyman/outbound.Manager: prepared handler configs by tag. Worker-
// level dispatch and every physical session read the same snapshot through
// HandlerLookup; dynamic add/replace/remove updates only this publication.
// Cold mutations serialize on the publication mutex; readers take the
// immutable snapshot only when the generation changed.
// ============================================================================
class OutboundConfiguration final {
public:
    struct Configuration final : PreparedOutboundConfig {
        explicit Configuration(const PreparedOutboundConfig& config)
            : PreparedOutboundConfig(config) {}
        // Host of a persistent_state tag once hosts are bound.
        std::shared_ptr<OutboundPoolHost> host;
    };
    using Entry = std::shared_ptr<const Configuration>;
    using Snapshot = std::vector<Entry>;

    explicit OutboundConfiguration(
        const std::vector<PreparedOutboundConfig>& configurations);
    ~OutboundConfiguration();
    OutboundConfiguration(const OutboundConfiguration&) = delete;
    OutboundConfiguration& operator=(const OutboundConfiguration&) = delete;

    // Cold Worker setup/publication only; no Worker state is captured by hosts.
    void BindHosts(net::io_context& reactor, uint32_t worker_id,
                   std::shared_ptr<GroupCoordinator> coordinator,
                   app::dns::DNSWorker& dns_worker, std::chrono::seconds dial_timeout);
    // Called only after the Worker's requests have drained.
    net::awaitable<void> AsyncJoinHosts();
    net::awaitable<void> CollectRuntimeStats(WorkerRuntimeStatsSnapshot& result,
                                             bool include_resources);

    // Incremented after each snapshot store (release). A reader that observes
    // a generation (acquire) then captures a snapshot at least that new.
    [[nodiscard]] uint64_t Generation() const noexcept;
    [[nodiscard]] std::shared_ptr<const Snapshot> Capture() const noexcept;
    // Transactional: a failed prepare leaves the published snapshot intact.
    void Replace(const PreparedOutboundConfig& configuration);
    void Remove(std::string_view tag);

private:
    struct Hosts;
    Entry Prepare(const PreparedOutboundConfig& configuration);
    void Publish(std::shared_ptr<const Snapshot> snapshot) noexcept;

    std::unique_ptr<Hosts> hosts_;
    std::mutex publication_mutex_;
    std::atomic<std::shared_ptr<const Snapshot>> snapshot_;
    std::atomic<uint64_t> generation_{0};
};

// ============================================================================
// Handler - Xray app/proxyman/outbound.Handler
//
// One concrete handler per outbound tag per executing domain. It owns the
// prepared sender settings (through its configuration entry), the tag's
// OutboundDialer and the protocol instance, or - for persistent_state tags -
// a lease on the tag's stable cache host. Requests execute in their own domain;
// only cold cache operations run on the host.
// ============================================================================
class Handler final : public memory::ThreadAllocated {
public:
    // Stateless tag: the protocol instance and dialer live in the requesting
    // domain (reactor, DNS client and resident task group outlive the handler).
    Handler(OutboundConfiguration::Entry config, net::io_context& io_context,
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
        buf::MultiBufferBatch first_payload,
        std::chrono::seconds relay_idle_timeout,
        std::chrono::seconds relay_write_timeout);

private:
    // Destroyed in reverse order: the protocol instance before the dialer,
    // the dialer before the sender settings it borrows from config_.
    OutboundConfiguration::Entry config_;
    std::shared_ptr<OutboundPoolHost> host_;
    std::optional<OutboundDialer> dialer_;
    std::unique_ptr<::Outbound> proxy_;
};

// ============================================================================
// HandlerLookup - per-domain view of the OutboundConfiguration publication
//
// The dispatcher's only outbound lookup. Instantiates a tag's Handler lazily
// in the owning domain and keeps it until the tag is replaced or removed;
// returned handles keep the handler alive for the whole request.
// ============================================================================
class HandlerLookup final : public memory::ThreadAllocated {
public:
    HandlerLookup(const OutboundConfiguration& configuration,
                  net::io_context& io_context, app::dns::DNS& dns,
                  std::chrono::seconds dial_timeout, AwaitableTaskGroup& tasks);
    HandlerLookup(const HandlerLookup&) = delete;
    HandlerLookup& operator=(const HandlerLookup&) = delete;

    [[nodiscard]] std::shared_ptr<Handler> GetHandler(std::string_view tag);

    // Cold path after a publication: drop handlers of replaced or removed
    // tags now instead of at the next lookup. Under allocation failure all
    // cached handlers are dropped and the next lookup resynchronizes.
    void Refresh() noexcept;

private:
    struct Entry {
        OutboundConfiguration::Entry config;
        std::shared_ptr<Handler> handler;
    };

    void Sync(uint64_t generation);
    [[nodiscard]] std::shared_ptr<Handler> Instantiate(
        const OutboundConfiguration::Entry& config);

    const OutboundConfiguration& configuration_;
    net::io_context& io_context_;
    app::dns::DNS& dns_;
    const std::chrono::seconds dial_timeout_;
    AwaitableTaskGroup& tasks_;
    uint64_t generation_ = 0;  // Publications start at 1.
    memory::ThreadLocalVector<Entry> entries_;
};

}  // namespace proxyman::outbound
