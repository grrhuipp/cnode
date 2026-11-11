#include <gtest/gtest.h>

#include "app/dispatcher/default_dispatcher.hpp"
#include "app/dns/dns.hpp"
#include "app/relay.hpp"
#include "app/proxyman/inbound/handler.hpp"
#include "common/allocator.hpp"
#include "common/rule.hpp"
#include "app/proxyman/outbound/handler.hpp"
#include "app/stats.hpp"
#include "features/routing/router.hpp"
#include "infra/config_types.hpp"
#include "proxy/outbound.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "common/awaitable_task_group.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/ip/udp.hpp>
#include <asio/this_coro.hpp>
#include <chrono>
#include <tuple>

namespace {
using namespace std::chrono_literals;

buf::MultiBuffer Payload(size_t size) {
    std::vector<uint8_t> bytes(size, 0x42);
    buf::MultiBuffer payload;
    if (!buf::AppendSpanToMultiBuffer(bytes, payload)) throw std::bad_alloc();
    return payload;
}

struct State {
    bool block = false;
    bool return_cancelled = false;
    bool allocation_failure = false;
    ErrorCode read_error = ErrorCode::OK;
    size_t payload_size = 0;
    size_t written = 0;
    int active = 0;
    int entered = 0;
    int committed = 0;
    int cancelled = 0;
    bool destroyed = false;
    bool notify_closed_on_destroy = false;
    bool closed = false;
    bool cleanup_has_owner = false;
    app::RequestLoadState* load = nullptr;
    TcpStream* phase_stream = nullptr;
};

net::awaitable<void> Wait(State& state) {
    ++state.active;
    net::steady_timer timer(co_await net::this_coro::executor);
    timer.expires_after(400ms);
    const auto [error] = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
    if (error) {
        ++state.cancelled;
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        timer.expires_after(20ms);
        co_await timer.async_wait(net::use_awaitable);
        state.cleanup_has_owner = state.load && state.load->ActiveConnections() != 0;
    }
    --state.active;
    if (error) throw IoSystemError(error);
}

class Stream final : public AsyncStream {
public:
    explicit Stream(State& state) : state_(state) {}
    ~Stream() override {
        state_.destroyed = true;
        if (state_.notify_closed_on_destroy) NotifyClosed();
    }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer) override { co_return 0; }
    net::awaitable<size_t> AsyncWrite(net::const_buffer data) override {
        state_.written += data.size();
        co_return data.size();
    }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override {
        ++state_.entered;
        if (state_.allocation_failure) throw std::bad_alloc();
        if (state_.read_error != ErrorCode::OK) throw transport::LinkError(state_.read_error);
        if (state_.block) co_await Wait(state_);
        co_return Payload(std::exchange(state_.payload_size, 0));
    }
    void ShutdownWrite() override {}
    void Cancel() noexcept override { NotifyCancellation(); }
    void Close() override { state_.closed = true; NotifyClosed(); }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return !state_.closed; }
protected:
    TcpStream* BaseTcpStream() override { return state_.phase_stream; }
    const TcpStream* BaseTcpStream() const override { return state_.phase_stream; }
private:
    State& state_;
};

// Protocol instance behind one outbound tag; the probe outlives every handler.
struct OutboundProbe {
    State state;
    State target_state;
    bool relay = false;
};

class TestOutbound final : public Outbound {
public:
    explicit TestOutbound(OutboundProbe& probe) : probe_(probe) {}
    net::awaitable<OutboundProcessResult> Process(
        session::Context& ctx, transport::Link inbound, OutboundDialer& dialer,
        const TimeoutsConfig&, StatsShard& stats, const RelayConfig& config,
        buf::MultiBufferBatch first) override {
        auto& state = probe_.state;
        ++state.entered;
        if (state.block) co_await Wait(state);
        ++state.committed;
        if (state.return_cancelled) {
            RelayResult result;
            result.error = ErrorCode::CANCELLED;
            co_return result;
        }
        if (!probe_.relay) co_return RelayResult{};
        Stream target(probe_.target_state);
        co_return co_await DoRelayLink(dialer.IoContext(), *inbound.reader, *inbound.writer,
            inbound.control, target, ctx, stats, config, std::move(first));
    }
private:
    OutboundProbe& probe_;
};

proxyman::outbound::PreparedOutboundConfig ProbeConfig(std::string tag, OutboundProbe& probe) {
    return proxyman::outbound::PreparedOutboundConfig{
        .tag = std::move(tag),
        .protocol = "test-probe",
        .sender = {},
        .create = proxyman::outbound::MakePreparedOutboundCreator<
            OutboundProbe*,
            +[](std::string_view, std::shared_ptr<OutboundProbe* const> probe,
                net::io_context&, AwaitableTaskGroup&) -> std::unique_ptr<Outbound> {
                return std::make_unique<TestOutbound>(**probe);
            }>(&probe),
    };
}

// "direct" and "second" published through the real outbound registry.
struct OutboundProbes {
    OutboundProbe direct;
    OutboundProbe second;
    [[nodiscard]] int Entered() const noexcept {
        return direct.state.entered + second.state.entered;
    }
};

struct Outbounds {
    Outbounds(OutboundProbes& probes, net::io_context& io, app::dns::DNS& dns)
        : tasks(io.get_executor()),
          registry({ProbeConfig("direct", probes.direct),
                    ProbeConfig("second", probes.second)},
                   io, dns, std::chrono::seconds(1), tasks.Tasks()) {}
    ResidentTaskGroup tasks;
    proxyman::outbound::HandlerRegistry registry;
};

class Router final : public routing::Router {
public:
    mutable int calls = 0;
    routing::RouteDecision decision;
    routing::RouteDecision Route(const session::Context&) const override { ++calls; return decision; }
    routing::DomainStrategy DomainStrategy() const noexcept override {
        return routing::DomainStrategy::IPOnDemand;
    }
};

void JoinRuntime(net::io_context& io, app::dns::DNSWorker& dns, Outbounds& outbounds) {
    dns.RequestStop();
    bool dns_joined = false;
    bool outbounds_joined = false;
    net::co_spawn(io, dns.AsyncJoin(), [&](std::exception_ptr error) {
        EXPECT_FALSE(error);
        dns_joined = true;
    });
    net::co_spawn(io, outbounds.tasks.AsyncJoin(), [&](std::exception_ptr error) {
        EXPECT_FALSE(error);
        outbounds_joined = true;
    });
    io.restart();
    io.run();
    EXPECT_TRUE(dns_joined);
    EXPECT_TRUE(outbounds_joined);
}

enum class Case { PreStopped, Sniff, Handshake, RoutingDns, Parent, Pending,
                  Success, RelaySuccess, RelayFailure, RelayCancelled, SniffMemory, SniffLinkError,
                  RoutedFallback, RuleMatch, PolicyBlockedForce, PolicyBlockedRoute, PolicyAllowed };

void ExerciseDispatch(Case which, bool controlled, ErrorCode reason = ErrorCode::CANCELLED) {
    net::io_context io;
    app::RequestLoadState load(100, 30);
    State source_state;
    tcp::socket phase_socket(io);
    IoErrorCode phase_open_error;
    phase_socket.open(tcp::v4(), phase_open_error);
    if (phase_open_error) throw IoSystemError(phase_open_error);
    TcpStream phase_stream(std::move(phase_socket));
    source_state.load = &load;
    source_state.block = which == Case::Sniff;
    source_state.allocation_failure = which == Case::SniffMemory;
    source_state.read_error = which == Case::SniffLinkError ? ErrorCode::RESOURCE_EXHAUSTED : ErrorCode::OK;
    source_state.payload_size = 7;
    source_state.notify_closed_on_destroy = controlled &&
        (which == Case::RelayFailure || which == Case::RelayCancelled);
    auto stream = std::make_unique<Stream>(source_state);
    auto* reader = stream.get();
    OutboundProbes outbounds;
    Router router;
    if (which == Case::RuleMatch) {
        router.decision = {.outbound_tag = "second", .matched = true};
    }
    auto& outbound = which == Case::RuleMatch ? outbounds.second : outbounds.direct;
    outbound.state.load = &load;
    outbound.target_state.phase_stream = &phase_stream;
    outbound.state.block = which == Case::Handshake || which == Case::Parent || which == Case::Pending;
    outbound.relay = which == Case::RelaySuccess || which == Case::RelayFailure;
    outbound.state.return_cancelled = which == Case::RelayCancelled;
    outbound.target_state.payload_size = 13;
    if (which == Case::RelayFailure) outbound.target_state.read_error = ErrorCode::SOCKET_READ_FAILED;
    routing::DispatchPolicy policy{SniffConfig{}, routing::ForceOutbound{"direct"}};
    if (which == Case::RoutedFallback || which == Case::RuleMatch ||
        which == Case::PolicyBlockedRoute) {
        policy.outbound = routing::RouteWithFallback{"direct"};
    }
    policy.sniffing.enabled = which == Case::Sniff || which == Case::SniffMemory || which == Case::SniffLinkError;
    session::Context ctx;
    ctx.conn_id = 1;
    ctx.inbound.tag = "dispatcher-test";
    ctx.inbound.accounting_key = "panel/fixture/1/";
    ctx.inbound.user_id = 42;
    ctx.inbound.user_email = "dispatcher|42";
    ctx.outbound.target = TargetAddress("192.0.2.1", 443);
    ctx.outbound.original_target = ctx.outbound.target;
    ctx.content.network = Network::TCP;
    StatsShard stats;
    TimeoutsConfig timeouts;
    udp::socket dns_peer(io, udp::endpoint(net::ip::make_address("127.0.0.42"), 0));
    app::dns::Config dns_config{
        .servers = {dns_peer.local_endpoint()},
        .timeout_sec = 2,
    };
    if (which == Case::RoutingDns) {
        policy.outbound = routing::RouteWithFallback{"direct"};
        ctx.outbound.target = TargetAddress("dispatcher-cancellation.example", 443);
        ctx.outbound.original_target = ctx.outbound.target;
    }
    app::dns::DNSWorker dns_worker(io, dns_config, 8);
    app::dns::DNS dns(dns_worker);
    app::SessionTrackingState session_tracking;
    rule::DetectRulePolicy request_policy;
    if (which == Case::PolicyBlockedForce || which == Case::PolicyBlockedRoute ||
        which == Case::PolicyAllowed) {
        request_policy.UpdateRule(
            ctx.inbound.tag,
            std::make_shared<const rule::DetectRulePolicy::RuleList>(
                rule::DetectRulePolicy::RuleList{{
                    .Pattern = std::regex(which == Case::PolicyAllowed
                        ? "198\\.51\\.100\\.1" : "192\\.0\\.2\\.1"),
                }}));
    }
    Outbounds outbound_handlers(outbounds, io, dns);
    app::dispatcher::DefaultDispatcher dispatcher(
        router, outbound_handlers.registry, request_policy, session_tracking, dns, load);
    if (which == Case::PreStopped) reader->Cancellation().Stop(reason);
    bool done = false;
    bool triggered = false;
    std::exception_ptr failure;
    RelayResult result;
    net::cancellation_signal parent;
    net::steady_timer trigger(io);
    if (which == Case::Sniff || which == Case::Handshake || which == Case::RoutingDns ||
        which == Case::Parent || which == Case::Pending) {
        trigger.expires_after(30ms);
        trigger.async_wait([&](IoErrorCode error) {
            if (error || done) return;
            triggered = which == Case::RoutingDns ? dns_peer.available() > 0 :
                (source_state.active + outbound.state.active == 1);
            if (which == Case::Parent) parent.emit(net::cancellation_type::terminal);
            else if (which == Case::Pending) reader->Cancellation().CancelPending(reason);
            else reader->Cancellation().Stop(reason);
        });
    }
    auto request = dispatcher.Dispatch(io, policy, controlled ? std::move(stream) : nullptr,
        controlled ? transport::Link{} : transport::Link{reader, reader, nullptr},
        InitialPayload{}, ctx, stats, timeouts);
    net::co_spawn(io, std::move(request), net::bind_cancellation_slot(parent.slot(),
        [&](std::exception_ptr error, RelayResult value) { failure = error; result = value; done = true; }));
    io.run_for(180ms);
    const bool completed_in_budget = done;
    if (!done) {
        parent.emit(net::cancellation_type::terminal);
        io.restart();
        io.run_for(1s);
    }
    JoinRuntime(io, dns_worker, outbound_handlers);
    EXPECT_TRUE(completed_in_budget);
    EXPECT_TRUE(done);
    EXPECT_FALSE(failure);
    EXPECT_EQ(load.ActiveConnections(), 0u);
    EXPECT_EQ(source_state.active, 0);
    EXPECT_EQ(outbound.state.active, 0);
    if (controlled) EXPECT_TRUE(source_state.destroyed);
    auto expected = reason;
    if (which == Case::Success || which == Case::RelaySuccess ||
        which == Case::RoutedFallback || which == Case::RuleMatch ||
        which == Case::PolicyAllowed) expected = ErrorCode::OK;
    if (which == Case::RelayFailure) expected = ErrorCode::SOCKET_READ_FAILED;
    if (which == Case::RelayCancelled) expected = ErrorCode::CANCELLED;
    if (which == Case::SniffMemory || which == Case::SniffLinkError) expected = ErrorCode::RESOURCE_EXHAUSTED;
    if (which == Case::PolicyBlockedForce || which == Case::PolicyBlockedRoute)
        expected = ErrorCode::BLOCKED;
    EXPECT_EQ(result.error, expected);
    if (which == Case::PreStopped || which == Case::Sniff || which == Case::RoutingDns ||
        which == Case::SniffMemory || which == Case::SniffLinkError) {
        EXPECT_EQ(outbounds.Entered(), 0);
    }
    if (source_state.block || outbound.state.block) {
        const auto& waiting = source_state.block ? source_state : outbound.state;
        EXPECT_TRUE(triggered);
        EXPECT_EQ(waiting.cancelled, 1);
        EXPECT_TRUE(waiting.cleanup_has_owner);
        EXPECT_EQ(outbound.state.committed, 0);
    }
    if (which == Case::RoutingDns) {
        EXPECT_TRUE(triggered);
        EXPECT_TRUE(ctx.outbound.tag.empty());
    }
    const bool routed = which == Case::RoutedFallback || which == Case::RuleMatch ||
        which == Case::PolicyBlockedRoute;
    if (routed) EXPECT_GT(router.calls, 0);
    else EXPECT_EQ(router.calls, 0);
    if (which == Case::RoutedFallback || which == Case::PolicyBlockedRoute) {
        EXPECT_EQ(ctx.outbound.tag, "direct");
    }
    if (which == Case::RuleMatch) {
        EXPECT_EQ(ctx.outbound.tag, "second");
        EXPECT_EQ(outbounds.direct.state.entered, 0);
        EXPECT_EQ(outbound.state.committed, 1);
    }
    if (which == Case::PolicyBlockedForce || which == Case::PolicyBlockedRoute) {
        EXPECT_EQ(outbounds.Entered(), 0);
        EXPECT_EQ(outbound.state.committed, 0);
    }
    if (which == Case::PolicyAllowed) {
        EXPECT_EQ(ctx.outbound.tag, "direct");
        EXPECT_EQ(outbound.state.committed, 1);
    }
    if (which == Case::RelaySuccess) {
        EXPECT_EQ(result.bytes_up, 7u);
        EXPECT_EQ(result.bytes_down, 13u);
        EXPECT_EQ(source_state.written, 13u);
        EXPECT_EQ(outbound.target_state.written, 7u);
        if (controlled) EXPECT_TRUE(source_state.closed);
    }
    const auto traffic = session_tracking.SnapshotTraffic(ctx.inbound.accounting_key);
    session_tracking.CommitTraffic(ctx.inbound.accounting_key, traffic);
    if (which == Case::RelaySuccess) {
        const auto user = traffic.users.find(42);
        EXPECT_NE(user, traffic.users.end());
        if (user != traffic.users.end()) {
            EXPECT_EQ(user->second.upload, 7u);
            EXPECT_EQ(user->second.download, 13u);
        }
    }
    // Completed requests must no longer contribute live traffic to reporting.
    ++ctx.traffic.bytes_up;
    ++ctx.traffic.bytes_down;
    EXPECT_TRUE(session_tracking.SnapshotTraffic(ctx.inbound.accounting_key).empty());
    if (!controlled && done) {
        // Borrowed logical inputs may outlive Dispatcher and notify again.
        // No callback may retain its completed task group or stack context.
        reader->Cancellation().CancelPending();
        reader->Cancellation().Stop();
    }
}

void ExerciseSiblingIsolation(bool controlled) {
    net::io_context io;
    app::RequestLoadState load(100, 30);
    State a, b;
    auto first = std::make_unique<Stream>(a);
    auto second = std::make_unique<Stream>(b);
    auto* source = first.get();
    OutboundProbes outbounds;
    for (auto* probe : {&outbounds.direct, &outbounds.second}) {
        probe->state.block = true;
        probe->state.load = &load;
    }
    Router router;
    rule::DetectRulePolicy request_policy;
    app::SessionTrackingState session_tracking;
    udp::socket dns_peer(io, udp::endpoint(net::ip::address_v4::loopback(), 0));
    app::dns::Config dns_config{.servers = {dns_peer.local_endpoint()}};
    app::dns::DNSWorker dns_worker(io, dns_config, 8);
    app::dns::DNS dns(dns_worker);
    Outbounds outbound_handlers(outbounds, io, dns);
    app::dispatcher::DefaultDispatcher dispatcher(
        router, outbound_handlers.registry, request_policy, session_tracking, dns, load);
    routing::DispatchPolicy policy_a{SniffConfig{.enabled = false, .domains_excluded = {}}, routing::ForceOutbound{"direct"}};
    routing::DispatchPolicy policy_b{SniffConfig{.enabled = false, .domains_excluded = {}}, routing::ForceOutbound{"second"}};
    session::Context ctx_a, ctx_b;
    ctx_a.outbound.target = ctx_b.outbound.target = TargetAddress("192.0.2.1", 443);
    StatsShard stats;
    TimeoutsConfig timeouts;
    bool first_done = false, second_done = false;
    int first_active_on_completion = -1;
    size_t load_on_first_completion = 0;
    net::cancellation_signal cancel_first, cancel_second;
    RelayResult result_a, result_b;
    const auto link_a = controlled ? transport::Link{} : transport::Link{first.get(), first.get(), nullptr};
    const auto link_b = controlled ? transport::Link{} : transport::Link{second.get(), second.get(), nullptr};
    net::co_spawn(io, dispatcher.Dispatch(io, policy_a, controlled ? std::move(first) : nullptr,
        link_a, InitialPayload{}, ctx_a, stats, timeouts),
        net::bind_cancellation_slot(cancel_first.slot(), [&](std::exception_ptr error, RelayResult result) {
            EXPECT_FALSE(error);
            first_done = true;
            result_a = result;
            first_active_on_completion = outbounds.direct.state.active;
            load_on_first_completion = load.ActiveConnections();
        }));
    net::co_spawn(io, dispatcher.Dispatch(io, policy_b, controlled ? std::move(second) : nullptr,
        link_b, InitialPayload{}, ctx_b, stats, timeouts),
        net::bind_cancellation_slot(cancel_second.slot(), [&](std::exception_ptr error, RelayResult result) {
            EXPECT_FALSE(error);
            second_done = true;
            result_b = result;
        }));
    int direct_waiting = 0, second_waiting = 0;
    net::steady_timer stop(io, 30ms);
    stop.async_wait([&](IoErrorCode error) {
        if (error) return;
        direct_waiting = outbounds.direct.state.active;
        second_waiting = outbounds.second.state.active;
        source->Cancellation().Stop(ErrorCode::RESOURCE_EXHAUSTED);
    });
    io.run_for(1s);
    const bool completed_in_budget = first_done && second_done;
    if (!first_done) cancel_first.emit(net::cancellation_type::terminal);
    if (!second_done) cancel_second.emit(net::cancellation_type::terminal);
    JoinRuntime(io, dns_worker, outbound_handlers);
    EXPECT_TRUE(completed_in_budget);
    EXPECT_TRUE(first_done);
    EXPECT_TRUE(second_done);
    EXPECT_EQ(direct_waiting, 1);
    EXPECT_EQ(second_waiting, 1);
    EXPECT_EQ(first_active_on_completion, 0);
    EXPECT_EQ(load_on_first_completion, 1u);
    EXPECT_EQ(result_a.error, ErrorCode::RESOURCE_EXHAUSTED);
    EXPECT_EQ(result_b.error, ErrorCode::OK);
    EXPECT_EQ(outbounds.direct.state.cancelled, 1);
    EXPECT_EQ(outbounds.direct.state.committed, 0);
    EXPECT_EQ(outbounds.second.state.cancelled, 0);
    EXPECT_EQ(outbounds.second.state.committed, 1);
    EXPECT_EQ(outbounds.second.state.active, 0);
    EXPECT_EQ(load.ActiveConnections(), 0u);
}

void ExpectTraffic(const app::UserTrafficCounters& traffic, int64_t user_id,
                   uint64_t upload, uint64_t download) {
    const auto user = traffic.users.find(user_id);
    ASSERT_NE(user, traffic.users.end());
    EXPECT_EQ(user->second.upload, upload);
    EXPECT_EQ(user->second.download, download);
}

TEST(DispatcherAccounting, CompletionPreservesUncommittedTrafficWithoutAllocating) {
    struct Restore {
        bool previous = memory::reject_next_process_allocation;
        size_t rejections = memory::rejected_process_allocations;
        ~Restore() {
            memory::reject_next_process_allocation = previous;
            memory::rejected_process_allocations = rejections;
        }
    } restore;
    app::SessionTrackingState tracking;
    app::SessionTrackingState::ActiveSession old_port, new_port, static_inbound;
    session::Traffic old_traffic, new_traffic, static_traffic;
    constexpr std::string_view key = "panel/same-node/9/";
    tracking.RegisterActiveSession(old_port, key, 42, old_traffic);
    tracking.RegisterActiveSession(new_port, key, 42, new_traffic);
    tracking.RegisterActiveSession(static_inbound, {}, 42, static_traffic);
    old_traffic.bytes_up = 7;
    old_traffic.bytes_down = 11;
    new_traffic.bytes_up = 13;
    new_traffic.bytes_down = 17;
    static_traffic.bytes_up = 1000;
    auto first = tracking.SnapshotTraffic(key);
    ExpectTraffic(first, 42, 20, 28);
    // Failed persistence leaves the same delta visible; sampling is not reset.
    const auto uncommitted = tracking.SnapshotTraffic(key);
    ExpectTraffic(uncommitted, 42, 20, 28);
    old_traffic.bytes_up += 19;
    new_traffic.bytes_down += 23;
    const auto rejections = memory::rejected_process_allocations;
    memory::reject_next_process_allocation = true;
    tracking.UnregisterActiveSession(old_port);
    tracking.UnregisterActiveSession(new_port);
    tracking.UnregisterActiveSession(static_inbound);
    const bool allocation_still_pending = memory::reject_next_process_allocation;
    const auto rejections_after_teardown = memory::rejected_process_allocations;
    memory::reject_next_process_allocation = false;
    EXPECT_TRUE(allocation_still_pending);
    EXPECT_EQ(rejections_after_teardown, rejections);
    // Completion during off-thread persistence must survive committing the
    // older snapshot. This also exercises account address stability on close.
    tracking.CommitTraffic(key, first);
    const auto remaining = tracking.SnapshotTraffic(key);
    tracking.CommitTraffic(key, remaining);
    ExpectTraffic(remaining, 42, 19, 23);
    EXPECT_TRUE(tracking.SnapshotTraffic(key).empty());
    EXPECT_TRUE(tracking.SnapshotTraffic({}).empty());
}

TEST(DispatcherAccounting, ReusedSessionStartsWithFreshTraffic) {
    app::SessionTrackingState tracking;
    app::SessionTrackingState::ActiveSession active;
    session::Traffic traffic;
    constexpr std::string_view key = "panel/same-node/9/";
    tracking.RegisterActiveSession(active, key, 42, traffic);
    traffic.bytes_up = 7;
    traffic.bytes_down = 11;
    tracking.UnregisterActiveSession(active);
    const auto first = tracking.SnapshotTraffic(key);
    tracking.CommitTraffic(key, first);
    tracking.RegisterActiveSession(active, key, 42, traffic);
    traffic.bytes_up = 3;
    traffic.bytes_down = 5;
    tracking.UnregisterActiveSession(active);
    const auto reused = tracking.SnapshotTraffic(key);
    tracking.CommitTraffic(key, reused);
    ExpectTraffic(reused, 42, 3, 5);
    EXPECT_TRUE(tracking.SnapshotTraffic(key).empty());
}

TEST(DispatcherAccounting, RollbackRestoresTrafficFromRetiredSession) {
    constexpr std::string_view key = "panel/same-node/9/";
    // A closed session folds its remaining delta into the Worker ledger while
    // an earlier snapshot is in flight; rollback restores the full total.
    app::SessionTrackingState aggregate;
    app::SessionTrackingState::ActiveSession retired_session;
    session::Traffic retired_traffic;
    aggregate.RegisterActiveSession(retired_session, key, 77, retired_traffic);
    retired_traffic.bytes_up = 29;
    retired_traffic.bytes_down = 31;
    const auto in_flight = aggregate.SnapshotTraffic(key);
    retired_traffic.bytes_up += 37;
    retired_traffic.bytes_down += 41;
    aggregate.UnregisterActiveSession(retired_session);
    aggregate.RollbackTraffic(key, in_flight);
    const auto consolidated = aggregate.SnapshotTraffic(key);
    ExpectTraffic(consolidated, 77, 66, 72);
    aggregate.CommitTraffic(key, consolidated);
    EXPECT_TRUE(aggregate.SnapshotTraffic(key).empty());
}

class DispatcherStopReason
    : public ::testing::TestWithParam<std::tuple<bool, ErrorCode>> {};

TEST_P(DispatcherStopReason, PreStoppedRequestNeverEntersOutbound) {
    const auto [controlled, reason] = GetParam();
    ExerciseDispatch(Case::PreStopped, controlled, reason);
}

TEST_P(DispatcherStopReason, SniffCancellationJoinsCleanupBeforeReleasingLoad) {
    const auto [controlled, reason] = GetParam();
    ExerciseDispatch(Case::Sniff, controlled, reason);
}

TEST_P(DispatcherStopReason, HandshakeCancellationJoinsCleanupBeforeReleasingLoad) {
    const auto [controlled, reason] = GetParam();
    ExerciseDispatch(Case::Handshake, controlled, reason);
}

INSTANTIATE_TEST_SUITE_P(OwnershipAndReason, DispatcherStopReason,
    ::testing::Combine(::testing::Bool(),
        ::testing::Values(ErrorCode::CANCELLED, ErrorCode::RESOURCE_EXHAUSTED)),
    [](const ::testing::TestParamInfo<std::tuple<bool, ErrorCode>>& info) {
        return std::string(std::get<0>(info.param) ? "Owned" : "Borrowed") +
            (std::get<1>(info.param) == ErrorCode::CANCELLED ? "Cancelled" : "ResourceExhausted");
    });

class DispatcherOwnership : public ::testing::TestWithParam<bool> {};

TEST_P(DispatcherOwnership, RoutingDnsCancellationDoesNotPublishOutbound) {
    ExerciseDispatch(Case::RoutingDns, GetParam());
}

TEST_P(DispatcherOwnership, ParentCancellationJoinsHandshake) {
    ExerciseDispatch(Case::Parent, GetParam());
}

TEST_P(DispatcherOwnership, PendingCancellationJoinsHandshake) {
    ExerciseDispatch(Case::Pending, GetParam());
}

TEST_P(DispatcherOwnership, SuccessfulOutboundReleasesRequestResources) {
    ExerciseDispatch(Case::Success, GetParam());
}

TEST_P(DispatcherOwnership, RelayAccountsBothDirectionsAndClosesOwnedStream) {
    ExerciseDispatch(Case::RelaySuccess, GetParam());
}

TEST_P(DispatcherOwnership, RelayFailurePreservesOriginalErrorDuringDestruction) {
    ExerciseDispatch(Case::RelayFailure, GetParam());
}

TEST(DispatcherCancellation, OwnedStreamDestructionPreservesReturnedCancellation) {
    ExerciseDispatch(Case::RelayCancelled, true);
}

TEST_P(DispatcherOwnership, SniffAllocationFailureDoesNotEnterOutbound) {
    ExerciseDispatch(Case::SniffMemory, GetParam());
}

TEST_P(DispatcherOwnership, SniffLinkFailureDoesNotEnterOutbound) {
    ExerciseDispatch(Case::SniffLinkError, GetParam());
}

TEST_P(DispatcherOwnership, RouterMissUsesConfiguredFallback) {
    ExerciseDispatch(Case::RoutedFallback, GetParam());
}

TEST_P(DispatcherOwnership, RouterMatchSelectsOnlyMatchedOutbound) {
    ExerciseDispatch(Case::RuleMatch, GetParam());
}

TEST_P(DispatcherOwnership, PolicyBlocksForcedOutboundBeforeHandshake) {
    ExerciseDispatch(Case::PolicyBlockedForce, GetParam());
}

TEST_P(DispatcherOwnership, PolicyBlocksRoutedOutboundBeforeHandshake) {
    ExerciseDispatch(Case::PolicyBlockedRoute, GetParam());
}

TEST_P(DispatcherOwnership, PolicyAllowsUnmatchedTarget) {
    ExerciseDispatch(Case::PolicyAllowed, GetParam());
}

TEST_P(DispatcherOwnership, CancellingOneRequestDoesNotCancelSibling) {
    ExerciseSiblingIsolation(GetParam());
}

INSTANTIATE_TEST_SUITE_P(StreamOwnership, DispatcherOwnership, ::testing::Bool(),
    [](const ::testing::TestParamInfo<bool>& info) {
        return info.param ? "Owned" : "Borrowed";
    });

}  // namespace
