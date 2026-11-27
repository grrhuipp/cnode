#include <gtest/gtest.h>

#include "app/default_dispatcher.hpp"
#include "app/dns.hpp"
#include "app/inbound_handler.hpp"
#include "app/outbound_handler.hpp"
#include "app/relay.hpp"
#include "app/request_load.hpp"
#include "app/stats.hpp"
#include "app/udp_ingress.hpp"
#include "common/awaitable_task_group.hpp"
#include "common/rule.hpp"
#include "infra/config_types.hpp"
#include "proxy/outbound.hpp"
#include "routing/router.hpp"
#include "transport/async_stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/ip/udp.hpp>
#include <asio/steady_timer.hpp>

#include <array>
#include <chrono>
#include <memory>

namespace {
using namespace std::chrono_literals;

struct TargetProbe {
    int prepared = 0;
    int reads = 0;
};

// Target endpoint of an admitted flow: takes uplink datagrams and keeps the
// downlink open until the test ends the association.
class HeldTarget final : public transport::AsyncStream {
public:
    HeldTarget(TargetProbe& probe, net::io_context& io) : probe_(probe), deadline_(io, *this) {}
    ~HeldTarget() override { deadline_.Clear(); }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer) override { co_return 0; }
    net::awaitable<void> WriteBuffers(std::span<const net::const_buffer>) override { co_return; }
    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override {
        ++probe_.reads;
        net::steady_timer hold(co_await net::this_coro::executor);
        hold.expires_after(300ms);
        (void)co_await hold.async_wait(net::as_tuple(net::use_awaitable));
        co_return common::MultiBuffer{};
    }
    void ShutdownWrite() override {}
    void Cancel() noexcept override { NotifyCancellation(); }
    void Close() override {
        deadline_.Clear();
        NotifyClosed();
    }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return true; }

protected:
    transport::StreamPhaseDeadline* LogicalPhaseDeadline() noexcept override { return &deadline_; }

private:
    TargetProbe& probe_;
    transport::StreamPhaseDeadline deadline_;
};

class HeldOutbound final : public proxy::Outbound {
public:
    struct Session final : proxy::OutboundSession {
        TargetProbe& probe;
        HeldTarget endpoint;
        Session(proxy::OutboundPrepareContext& context, TargetProbe& probe)
            : probe(probe), endpoint(probe, context.dialer.IoContext()) {}
        net::awaitable<proxy::OutboundPrepareResult<HeldTarget>> Prepare() {
            ++probe.prepared;
            co_return std::ref(endpoint);
        }
    };
    auto SessionArguments() noexcept { return std::tuple{std::ref(probe_)}; }
    explicit HeldOutbound(TargetProbe& probe)
        : Outbound(std::in_place_type<HeldOutbound>), probe_(probe) {}

private:
    TargetProbe& probe_;
};

class NoRoutes final : public routing::Router {
public:
    routing::RouteDecision Route(const common::Context&) const override { return {}; }
    routing::DomainStrategy DomainStrategy() const noexcept override {
        return routing::DomainStrategy::AsIs;
    }
};

common::MultiBuffer Datagram(uint8_t marker) {
    const std::array<uint8_t, 1> bytes{marker};
    common::MultiBuffer payload;
    if (!payload.AppendSpan(bytes)) throw std::bad_alloc();
    return payload;
}

struct AssociationOutcome {
    bool ended_before_close = false;
    common::ErrorCode error = common::ErrorCode::OK;
    int prepared = 0;
};

// One native UDP association: `blocked` datagrams name targets a detect rule
// rejects, all read before their flows run; a datagram for an admitted target
// follows once every blocked flow has failed.
AssociationOutcome RunAssociation(std::initializer_list<common::TargetAddress> blocked) {
    net::io_context io;
    app::RequestLoadState load(100, 30);
    TargetProbe probe;
    NoRoutes router;
    common::DetectRulePolicy request_policy;
    request_policy.UpdateRule("udp-flow-test",
        std::make_shared<const common::DetectRulePolicy::RuleList>(
            common::DetectRulePolicy::RuleList{{.Pattern = std::regex("192\\.0\\.2\\.")}}));
    app::SessionTrackingState session_tracking;
    udp::socket dns_peer(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    app::DnsConfig dns_config{.servers = {dns_peer.local_endpoint()}};
    app::DNSWorker dns(io, dns_config, 8);
    common::ResidentTaskGroup outbound_tasks(io.get_executor());
    app::OutboundHandlerRegistry registry(
        {app::PreparedOutboundConfig{
            .tag = "direct",
            .protocol = "test-held",
            .sender = {},
            .create = app::MakePreparedOutboundCreator<TargetProbe*,
                +[](std::string_view, std::shared_ptr<TargetProbe* const> target,
                    net::io_context&, common::AwaitableTaskGroup&) -> std::unique_ptr<proxy::Outbound> {
                    return std::make_unique<HeldOutbound>(**target);
                }>(&probe),
        }},
        io, dns, std::chrono::seconds(1), outbound_tasks);
    app::DefaultDispatcher dispatcher(
        router, registry, request_policy, session_tracking, dns, load);

    app::UdpResourceBudget budget;
    proxy::InboundDatagramOwner owner;
    const std::array<uint8_t, 1> owner_bytes{7};
    EXPECT_TRUE(owner.Assign(owner_bytes));
    app::UdpIngress::ClientSession association(io, {}, udp::endpoint{}, owner, budget,
                                               budget.AcquireAssociation());
    uint8_t marker = 0;
    for (const auto& target : blocked) EXPECT_TRUE(association.Push(target, Datagram(++marker)));

    routing::DispatchPolicy policy{routing::SniffConfig{}, routing::ForceOutbound{"direct"}};
    common::Context ctx;
    ctx.conn_id = 1;
    ctx.inbound.tag = "udp-flow-test";
    ctx.inbound.user_id = 42;
    ctx.content.network = common::Network::UDP;
    ctx.outbound.target = *blocked.begin();
    ctx.outbound.original_target = ctx.outbound.target;
    app::StatsShard stats;
    infra::TimeoutsConfig timeouts;

    AssociationOutcome outcome;
    bool done = false;
    net::cancellation_signal parent;
    net::co_spawn(io,
        proxy::DispatchAuthenticatedInbound(dispatcher, io, policy,
            routing::DispatchRequest(transport::Link{&association, &association, nullptr}),
            ctx, stats, timeouts),
        net::bind_cancellation_slot(parent.slot(),
            [&](std::exception_ptr error, app::RelayResult result) {
                EXPECT_FALSE(error);
                outcome.error = result.error;
                done = true;
            }));
    net::steady_timer admitted(io, 50ms);
    admitted.async_wait([&](IoErrorCode error) {
        if (!error && !done)
            (void)association.Push(common::TargetAddress("198.51.100.7", 53), Datagram(0xa0));
    });
    io.run_for(150ms);
    outcome.ended_before_close = done;
    outcome.prepared = probe.prepared;

    association.Close();
    io.restart();
    io.run_for(2s);
    if (!done) {
        parent.emit(net::cancellation_type::terminal);
        io.restart();
        io.run_for(1s);
    }
    EXPECT_TRUE(done);
    dns.RequestStop();
    bool dns_joined = false, outbounds_joined = false;
    net::co_spawn(io, dns.AsyncJoin(), [&](std::exception_ptr) { dns_joined = true; });
    net::co_spawn(io, outbound_tasks.AsyncJoin(), [&](std::exception_ptr) { outbounds_joined = true; });
    io.restart();
    io.run();
    EXPECT_TRUE(dns_joined);
    EXPECT_TRUE(outbounds_joined);
    EXPECT_EQ(load.ActiveConnections(), 0u);
    return outcome;
}

// Xray's udp.Dispatcher keeps a per-packet addressed session when one
// destination fails; the next datagram dispatches again.
TEST(UdpFlowIsolation, FailedTargetsDoNotEndMultiTargetAssociation) {
    const auto outcome = RunAssociation({common::TargetAddress("192.0.2.1", 53),
                                         common::TargetAddress("192.0.2.2", 53)});
    EXPECT_FALSE(outcome.ended_before_close)
        << "blocked targets ended the association with "
        << common::ErrorCodeToString(outcome.error);
    EXPECT_EQ(outcome.prepared, 1) << "a later admitted target never reached its outbound";
}

// A single-target association is Xray's single-link UDP request: the failure
// of its only target ends it.
TEST(UdpFlowIsolation, FailedOnlyTargetEndsSingleTargetAssociation) {
    const auto outcome = RunAssociation({common::TargetAddress("192.0.2.1", 53)});
    EXPECT_TRUE(outcome.ended_before_close);
    EXPECT_EQ(outcome.error, common::ErrorCode::BLOCKED);
    EXPECT_EQ(outcome.prepared, 0);
}

}  // namespace
