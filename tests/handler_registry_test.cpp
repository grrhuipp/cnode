#include <gtest/gtest.h>

#include "app/proxyman/inbound/handler.hpp"
#include "app/relay.hpp"
#include "app/proxyman/outbound/handler.hpp"
#include "app/dns/dns.hpp"
#include "common/session.hpp"
#include "app/stats.hpp"
#include "infra/config_types.hpp"
#include "proxy/outbound.hpp"
#include "common/awaitable_task_group.hpp"

#include <asio/co_spawn.hpp>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace {

using ::proxyman::outbound::HandlerRegistry;
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
    HandlerRegistry registry({MakeConfig("direct", first_probe)}, io, dns,
                             std::chrono::seconds(1), tasks.Tasks());

    // Publication instantiates on the owning Worker; lookups never construct.
    if (first_probe.created != 1) return 1;
    auto first = registry.GetHandler("direct");
    if (!first || first->Tag() != "direct") return 2;
    if (registry.GetHandler("direct") != first || first_probe.created != 1) return 3;
    if (registry.GetHandler("") || registry.GetHandler("missing")) return 4;

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

    // A failed publication leaves the published handler untouched.
    PreparedOutboundConfig missing_creator;
    missing_creator.tag = "direct";
    bool rejected = false;
    try {
        registry.Replace(missing_creator);
    } catch (const std::logic_error&) {
        rejected = true;
    }
    if (!rejected) return 6;
    if (registry.GetHandler("direct") != first) return 7;

    // Replacement: new handler for new requests; in-flight handles survive.
    registry.Replace(MakeConfig("direct", second_probe));
    auto second = registry.GetHandler("direct");
    if (!second || second == first || second_probe.created != 1) return 8;
    if (first_probe.destroyed != 0) return 9;
    first.reset();
    if (first_probe.destroyed != 1) return 10;

    // Removal releases the registry's handle; the request handle survives.
    registry.Remove("direct");
    if (second_probe.destroyed != 0) return 11;
    second.reset();
    if (second_probe.destroyed != 1) return 12;
    if (registry.GetHandler("direct")) return 13;

    // Duplicate tags never publish a partial registry.
    Probe duplicate_probe;
    bool duplicate_rejected = false;
    try {
        HandlerRegistry duplicate({MakeConfig("same", duplicate_probe),
                                   MakeConfig("same", duplicate_probe)},
                                  io, dns, std::chrono::seconds(1), tasks.Tasks());
    } catch (const std::logic_error&) {
        duplicate_rejected = true;
    }
    if (!duplicate_rejected || duplicate_probe.created != 2 ||
        duplicate_probe.destroyed != 2) {
        return 14;
    }
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
