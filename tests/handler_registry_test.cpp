#include <gtest/gtest.h>

#include "app/proxyman/inbound/handler_registry.hpp"
#include "app/proxyman/outbound/handler.hpp"
#include "app/dns/dns.hpp"
#include "app/dns/dns_worker.hpp"
#include "common/session.hpp"
#include "app/stats.hpp"
#include "infra/runtime_config_types.hpp"
#include "proxy/outbound.hpp"
#include "../src/common/awaitable_task_group.hpp"

#include <asio/co_spawn.hpp>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace {

using ::proxyman::outbound::HandlerLookup;
using ::proxyman::outbound::OutboundConfiguration;
using ::proxyman::outbound::PreparedOutboundConfig;

struct Probe {
    int created = 0;
    int destroyed = 0;
    int processed = 0;
    ::OutboundDialer* last_dialer = nullptr;
};

class CountingOutbound final : public ::Outbound {
public:
    explicit CountingOutbound(Probe& probe) : probe_(probe) { ++probe_.created; }
    ~CountingOutbound() noexcept override { ++probe_.destroyed; }

    ::net::awaitable<::OutboundProcessResult> Process(
        ::session::Context&, ::transport::Link, ::OutboundDialer& dialer,
        const ::TimeoutsConfig&, ::StatsShard&, const ::RelayConfig&,
        ::buf::MultiBufferBatch, std::chrono::seconds, std::chrono::seconds) override {
        ++probe_.processed;
        probe_.last_dialer = &dialer;
        co_return ::RelayResult{};
    }

private:
    Probe& probe_;
};

PreparedOutboundConfig MakeConfig(std::string tag, Probe& probe) {
    return PreparedOutboundConfig{
        .tag = std::move(tag),
        .protocol = "test-counting",
        .sender = {},
        .create = ::proxyman::outbound::MakePreparedOutboundCreator<
            Probe*,
            +[](std::string_view, std::shared_ptr<Probe* const> probe,
                ::net::io_context&, ::AwaitableTaskGroup&)
                -> std::unique_ptr<::Outbound> {
                return std::make_unique<CountingOutbound>(**probe);
            }>(&probe),
    };
}

using InboundRegistry = ::proxyman::inbound::HandlerRegistry;

int Run() {
    ::net::io_context io;
    // Lookup tests never resolve names; one inert endpoint satisfies DNSWorker.
    ::app::dns::Config dns_config{
        .servers = {{::net::ip::address_v4::loopback(), 9}}};
    ::app::dns::DNSWorker dns_worker(io, dns_config, 8);
    ::app::dns::DNS dns(dns_worker);
    ::ResidentTaskGroup tasks(io.get_executor());

    Probe first_probe;
    Probe second_probe;
    OutboundConfiguration configuration({MakeConfig("direct", first_probe)});
    HandlerLookup lookup(configuration, io, dns, std::chrono::seconds(1), tasks.Tasks());

    // Lazy per-domain instantiation, memoized until the tag is republished.
    if (first_probe.created != 0) return 1;
    auto first = lookup.GetHandler("direct");
    if (!first || first->Tag() != "direct" || first_probe.created != 1) return 2;
    if (lookup.GetHandler("direct") != first || first_probe.created != 1) return 3;
    if (lookup.GetHandler("") || lookup.GetHandler("missing")) return 4;

    // Dispatch reaches the protocol exactly once, with the handler's dialer.
    ::session::Context ctx;
    ::TimeoutsConfig timeouts;
    ::StatsShard stats;
    ::RelayConfig relay;
    bool dispatched = false;
    ::net::co_spawn(io,
        first->Dispatch(ctx, ::transport::Link{}, timeouts, stats, relay, {},
                        std::chrono::seconds(1), std::chrono::seconds(1)),
        [&](std::exception_ptr error, ::OutboundProcessResult result) {
            dispatched = !error && result.has_value();
        });
    for (int round = 0; round < 100 && !dispatched; ++round) {
        io.run_for(std::chrono::milliseconds(10));
        io.restart();
    }
    if (!dispatched || first_probe.processed != 1 || !first_probe.last_dialer) return 5;

    // A failed publication leaves the published snapshot untouched.
    const auto generation = configuration.Generation();
    PreparedOutboundConfig missing_creator;
    missing_creator.tag = "direct";
    bool rejected = false;
    try {
        configuration.Replace(missing_creator);
    } catch (const std::logic_error&) {
        rejected = true;
    }
    if (!rejected || configuration.Generation() != generation) return 6;
    if (lookup.GetHandler("direct") != first) return 7;

    // Replacement: new handler for new requests; in-flight handles survive.
    configuration.Replace(MakeConfig("direct", second_probe));
    auto second = lookup.GetHandler("direct");
    if (!second || second == first || second_probe.created != 1) return 8;
    if (first_probe.destroyed != 0) return 9;
    first.reset();
    if (first_probe.destroyed != 1) return 10;

    // Removal: Refresh releases the cached handler before the next lookup.
    configuration.Remove("direct");
    lookup.Refresh();
    if (second_probe.destroyed != 0) return 11;
    second.reset();
    if (second_probe.destroyed != 1) return 12;
    if (lookup.GetHandler("direct")) return 13;
    return 0;
}

}  // namespace

TEST(HandlerRegistry, Contract) {
    try {
        const int result = ::Run();
        std::printf("outbound handler lookup: %s (%d)\n", result == 0 ? "PASS" : "FAIL", result);
        { ASSERT_EQ((result), 0); return; }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "fixture failure: %s\n", error.what());
        FAIL() << error.what();
    }
}
