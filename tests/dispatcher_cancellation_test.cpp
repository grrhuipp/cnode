#include <gtest/gtest.h>

#include "app/dispatcher/default_dispatcher.hpp"
#include "app/dns/dns_worker.hpp"
#include "app/relay.hpp"
#include "app/request_load_state.hpp"
#include "app/session_tracking.hpp"
#include "common/rule.hpp"
#include "app/proxyman/outbound/handler.hpp"
#include "app/stats.hpp"
#include "features/routing/router.hpp"
#include "infra/runtime_config_types.hpp"
#include "proxy/outbound.hpp"
#include "transport/internet/tcp_stream.hpp"
#include "../src/common/awaitable_task_group.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/ip/udp.hpp>
#include <asio/this_coro.hpp>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>

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
    int instantiated = 0;
};

class TestOutbound final : public Outbound {
public:
    explicit TestOutbound(OutboundProbe& probe) : probe_(probe) { ++probe_.instantiated; }
    net::awaitable<OutboundProcessResult> Process(
        session::Context& ctx, transport::Link inbound, OutboundDialer& dialer,
        const TimeoutsConfig&, StatsShard& stats, const RelayConfig& config,
        buf::MultiBufferBatch first, std::chrono::seconds, std::chrono::seconds) override {
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

// "direct" and "second" published through the real configuration/lookup pair.
struct OutboundProbes {
    OutboundProbe direct;
    OutboundProbe second;
    [[nodiscard]] int Instantiated() const noexcept {
        return direct.instantiated + second.instantiated;
    }
};

struct Outbounds {
    Outbounds(OutboundProbes& probes, net::io_context& io, app::dns::DNS& dns)
        : configuration({ProbeConfig("direct", probes.direct),
                         ProbeConfig("second", probes.second)}),
          tasks(io.get_executor()),
          lookup(configuration, io, dns, std::chrono::seconds(1), tasks.Tasks()) {}
    proxyman::outbound::OutboundConfiguration configuration;
    ResidentTaskGroup tasks;
    proxyman::outbound::HandlerLookup lookup;
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

enum class Case { PreStopped, Sniff, Handshake, RoutingDns, Parent, Pending,
                  Success, RelaySuccess, RelayFailure, RelayCancelled, SniffMemory, SniffLinkError,
                  RoutedFallback, RuleMatch, PolicyBlockedForce, PolicyBlockedRoute, PolicyAllowed };

bool Run(Case which, bool controlled, ErrorCode reason = ErrorCode::CANCELLED) {
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
    if (which == Case::RelayFailure) outbound.target_state.read_error = ErrorCode::RELAY_READ_FAILED;
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
        request_policy.UpdateRule(ctx.inbound.tag, {{
            .Pattern = std::regex(which == Case::PolicyAllowed
                ? "198\\.51\\.100\\.1" : "192\\.0\\.2\\.1"),
        }});
    }
    Outbounds outbound_handlers(outbounds, io, dns);
    app::dispatcher::DefaultDispatcher dispatcher(
        router, outbound_handlers.lookup, request_policy, session_tracking, dns, load);
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
    bool passed = completed_in_budget && done && !failure && load.ActiveConnections() == 0 &&
        source_state.active == 0 && outbound.state.active == 0 &&
        (!controlled || source_state.destroyed);
    auto expected = reason;
    if (which == Case::Success || which == Case::RelaySuccess ||
        which == Case::RoutedFallback || which == Case::RuleMatch ||
        which == Case::PolicyAllowed) expected = ErrorCode::OK;
    if (which == Case::RelayFailure) expected = ErrorCode::RELAY_READ_FAILED;
    if (which == Case::RelayCancelled) expected = ErrorCode::CANCELLED;
    if (which == Case::SniffMemory || which == Case::SniffLinkError) expected = ErrorCode::RESOURCE_EXHAUSTED;
    if (which == Case::PolicyBlockedForce || which == Case::PolicyBlockedRoute)
        expected = ErrorCode::BLOCKED;
    passed &= result.error == expected;
    if (which == Case::PreStopped || which == Case::Sniff || which == Case::RoutingDns ||
        which == Case::SniffMemory || which == Case::SniffLinkError) passed &= outbounds.Instantiated() == 0 && outbound.state.entered == 0;
    if (source_state.block || outbound.state.block) {
        const auto& waiting = source_state.block ? source_state : outbound.state;
        passed &= triggered && waiting.cancelled == 1 && waiting.cleanup_has_owner && outbound.state.committed == 0;
    }
    if (which == Case::RoutingDns) passed &= triggered && ctx.outbound.tag.empty();
    const bool routed = which == Case::RoutedFallback || which == Case::RuleMatch ||
        which == Case::PolicyBlockedRoute;
    passed &= routed ? router.calls > 0 : router.calls == 0;
    if (which == Case::RoutedFallback || which == Case::PolicyBlockedRoute) {
        passed &= ctx.outbound.tag == "direct";
    }
    if (which == Case::RuleMatch) {
        passed &= ctx.outbound.tag == "second" &&
            outbounds.direct.state.entered == 0 && outbound.state.committed == 1;
    }
    if (which == Case::PolicyBlockedForce || which == Case::PolicyBlockedRoute) {
        passed &= outbounds.Instantiated() == 0 && outbound.state.entered == 0 &&
            outbound.state.committed == 0;
    }
    if (which == Case::PolicyAllowed) {
        passed &= ctx.outbound.tag == "direct" &&
            outbound.state.committed == 1;
    }
    if (which == Case::RelaySuccess) passed &= result.bytes_up == 7 && result.bytes_down == 13 &&
        source_state.written == 13 && outbound.target_state.written == 7 && (!controlled || source_state.closed);
    const auto traffic = session_tracking.SnapshotTraffic(ctx.inbound.accounting_key);
    session_tracking.CommitTraffic(ctx.inbound.accounting_key, traffic);
    if (which == Case::RelaySuccess) {
        const auto user = traffic.users.find(42);
        passed &= user != traffic.users.end() &&
            user->second.upload == 7 && user->second.download == 13;
    }
    // Completed requests must no longer contribute live traffic to reporting.
    ++ctx.traffic.bytes_up;
    ++ctx.traffic.bytes_down;
    passed &= session_tracking.SnapshotTraffic(ctx.inbound.accounting_key).empty();
    if (!controlled && done) {
        // Borrowed logical inputs may outlive Dispatcher and notify again.
        // No callback may retain its completed task group or stack context.
        reader->Cancellation().CancelPending();
        reader->Cancellation().Stop();
    }
    std::printf("case=%d controlled=%d reason=%s result=%s timely=%d triggered=%d lookups=%d committed=%d joined=%d: %s\n",
        int(which), controlled, ErrorCodeToString(reason).data(), ErrorCodeToString(result.error).data(),
        completed_in_budget, triggered, outbounds.Instantiated(), outbound.state.committed,
        source_state.active + outbound.state.active == 0, passed ? "PASS" : "FAIL");
    return passed;
}

bool SiblingIsolation(bool controlled) {
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
        router, outbound_handlers.lookup, request_policy, session_tracking, dns, load);
    routing::DispatchPolicy policy_a{SniffConfig{.enabled = false, .domains_excluded = {}}, routing::ForceOutbound{"direct"}};
    routing::DispatchPolicy policy_b{SniffConfig{.enabled = false, .domains_excluded = {}}, routing::ForceOutbound{"second"}};
    session::Context ctx_a, ctx_b;
    ctx_a.outbound.target = ctx_b.outbound.target = TargetAddress("192.0.2.1", 443);
    StatsShard stats;
    TimeoutsConfig timeouts;
    bool first_done = false, second_done = false, first_joined = false, failed = false;
    RelayResult result_a, result_b;
    const auto link_a = controlled ? transport::Link{} : transport::Link{first.get(), first.get(), nullptr};
    const auto link_b = controlled ? transport::Link{} : transport::Link{second.get(), second.get(), nullptr};
    net::co_spawn(io, dispatcher.Dispatch(io, policy_a, controlled ? std::move(first) : nullptr,
        link_a, InitialPayload{}, ctx_a, stats, timeouts), [&](std::exception_ptr error, RelayResult result) {
            failed |= bool(error);
            first_done = true;
            result_a = result;
            first_joined = outbounds.direct.state.active == 0 && load.ActiveConnections() == 1;
        });
    net::co_spawn(io, dispatcher.Dispatch(io, policy_b, controlled ? std::move(second) : nullptr,
        link_b, InitialPayload{}, ctx_b, stats, timeouts), [&](std::exception_ptr error, RelayResult result) {
            failed |= bool(error);
            second_done = true;
            result_b = result;
        });
    bool both_waiting = false;
    net::steady_timer stop(io, 30ms);
    stop.async_wait([&](IoErrorCode error) {
        if (error) return;
        both_waiting = outbounds.direct.state.active == 1 && outbounds.second.state.active == 1;
        source->Cancellation().Stop(ErrorCode::RESOURCE_EXHAUSTED);
    });
    io.run_for(1s);
    const bool passed = !failed && first_done && second_done && both_waiting && first_joined &&
        result_a.error == ErrorCode::RESOURCE_EXHAUSTED && result_b.error == ErrorCode::OK &&
        outbounds.direct.state.cancelled == 1 && outbounds.direct.state.committed == 0 &&
        outbounds.second.state.cancelled == 0 && outbounds.second.state.committed == 1 &&
        outbounds.second.state.active == 0 && load.ActiveConnections() == 0;
    std::printf("sibling isolation controlled=%d first=%s second=%s joined=%d: %s\n", controlled,
        ErrorCodeToString(result_a.error).data(), ErrorCodeToString(result_b.error).data(), first_joined,
        passed ? "PASS" : "FAIL");
    return passed;
}

bool StableAccounting() {
    struct Resource final : std::pmr::memory_resource {
        std::pmr::memory_resource* upstream = std::pmr::get_default_resource();
        bool reject = false;
        size_t attempts = 0;
        void* do_allocate(size_t bytes, size_t alignment) override {
            if (reject) { ++attempts; throw std::bad_alloc(); }
            return upstream->allocate(bytes, alignment);
        }
        void do_deallocate(void* p, size_t bytes, size_t alignment) override {
            upstream->deallocate(p, bytes, alignment);
        }
        bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
            return this == &other;
        }
    } resource;
    struct Restore {
        std::pmr::memory_resource* previous;
        ~Restore() { std::pmr::set_default_resource(previous); }
    } restore{std::pmr::set_default_resource(&resource)};
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
    bool passed = first.users.at(42).upload == 20 && first.users.at(42).download == 28;
    // Failed persistence leaves the same delta visible; sampling is not reset.
    const auto uncommitted = tracking.SnapshotTraffic(key);
    passed &= uncommitted.users.at(42).upload == 20 &&
        uncommitted.users.at(42).download == 28;
    old_traffic.bytes_up += 19;
    new_traffic.bytes_down += 23;
    resource.reject = true;
    tracking.UnregisterActiveSession(old_port);
    tracking.UnregisterActiveSession(new_port);
    tracking.UnregisterActiveSession(static_inbound);
    resource.reject = false;
    // Completion during off-thread persistence must survive committing the
    // older snapshot. This also exercises account address stability on close.
    tracking.CommitTraffic(key, first);
    const auto remaining = tracking.SnapshotTraffic(key);
    tracking.CommitTraffic(key, remaining);
    passed &= remaining.users.at(42).upload == 19 && remaining.users.at(42).download == 23 &&
        resource.attempts == 0 && tracking.SnapshotTraffic(key).empty() &&
        tracking.SnapshotTraffic({}).empty();
    tracking.RegisterActiveSession(new_port, key, 42, new_traffic);
    new_traffic.bytes_up = 3;
    new_traffic.bytes_down = 5;
    tracking.UnregisterActiveSession(new_port);
    const auto reused = tracking.SnapshotTraffic(key);
    tracking.CommitTraffic(key, reused);
    passed &= reused.users.at(42).upload == 3 && reused.users.at(42).download == 5;
    // A closed physical connection transfers only counters outside the current
    // durable snapshot. The snapshot token keeps the small ledger alive, not
    // the connection domain; rollback makes its counters transferable again.
    app::SessionTrackingState retired;
    app::SessionTrackingState aggregate;
    app::SessionTrackingState::ActiveSession retired_session;
    session::Traffic retired_traffic;
    retired.RegisterActiveSession(retired_session, key, 77, retired_traffic);
    retired_traffic.bytes_up = 29;
    retired_traffic.bytes_down = 31;
    const auto in_flight = retired.SnapshotTraffic(key);
    retired_traffic.bytes_up += 37;
    retired_traffic.bytes_down += 41;
    retired.UnregisterActiveSession(retired_session);
    auto after_snapshot = retired.ExtractAvailableTraffic(key);
    passed &= after_snapshot.users.at(77).upload == 37 &&
        after_snapshot.users.at(77).download == 41;
    aggregate.MergeCompletedTraffic(key, after_snapshot);
    passed &= after_snapshot.empty();
    retired.RollbackTraffic(key, in_flight);
    auto restored = retired.ExtractAvailableTraffic(key);
    passed &= restored.users.at(77).upload == 29 &&
        restored.users.at(77).download == 31;
    aggregate.MergeCompletedTraffic(key, restored);
    const auto consolidated = aggregate.SnapshotTraffic(key);
    passed &= consolidated.users.at(77).upload == 66 &&
        consolidated.users.at(77).download == 72 &&
        retired.SnapshotTraffic(key).empty();
    aggregate.CommitTraffic(key, consolidated);
    std::printf("stable accounting with retired sessions and teardown OOM: %s\n",
                passed ? "PASS" : "FAIL");
    return passed;
}
}

TEST(DispatcherCancellation, Contract) {
    try {
        bool passed = StableAccounting();
        for (bool controlled : {false, true}) {
            for (const auto which : {Case::PreStopped, Case::Sniff, Case::Handshake, Case::RoutingDns,
                Case::Parent, Case::Pending, Case::Success, Case::RelaySuccess, Case::RelayFailure,
                Case::SniffMemory, Case::SniffLinkError, Case::RoutedFallback, Case::RuleMatch,
                Case::PolicyBlockedForce, Case::PolicyBlockedRoute, Case::PolicyAllowed})
                passed &= ::Run(which, controlled);
            if (controlled) passed &= ::Run(Case::RelayCancelled, true);
            for (const auto which : {Case::PreStopped, Case::Sniff, Case::Handshake})
                passed &= ::Run(which, controlled, ErrorCode::RESOURCE_EXHAUSTED);
            passed &= SiblingIsolation(controlled);
        }
        { ASSERT_TRUE(passed); return; }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "fixture failure: %s\n", error.what());
        FAIL() << error.what();
    }
}
