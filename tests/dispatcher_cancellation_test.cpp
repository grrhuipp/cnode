#include "acppnode/app/access_log_session.hpp"
#include "acppnode/app/dispatcher/default_dispatcher.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/relay.hpp"
#include "acppnode/app/request_load_state.hpp"
#include "acppnode/features/outbound/outbound.hpp"
#include "acppnode/features/routing/router.hpp"
#include "acppnode/infra/runtime_config_types.hpp"
#include "acppnode/proxy/outbound.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/co_spawn.hpp>
#include <asio/ip/udp.hpp>
#include <asio/this_coro.hpp>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>

// The real Dispatcher, DNS and relay run below. Only the external log sink is
// replaced, so terminal accounting can be inspected without an upload service.
namespace acpp::app {
size_t completions = 0;
RelayResult last_result;
AccessLogSession::AccessLogSession(session::Context& ctx) noexcept : ctx_(&ctx) {}
AccessLogSession::~AccessLogSession() noexcept = default;
void AccessLogSession::Complete(const RelayResult& result) noexcept {
    ++completions;
    last_result = result;
}
}

namespace {
using namespace acpp;
using namespace std::chrono_literals;

buf::MultiBuffer Payload(size_t size) {
    std::vector<uint8_t> bytes(size, 0x42);
    buf::MultiBuffer payload;
    if (!buf::AppendSpanToMultiBuffer(bytes, payload)) throw std::bad_alloc();
    return payload;
}

struct State {
    bool block = false;
    bool allocation_failure = false;
    ErrorCode read_error = ErrorCode::OK;
    size_t payload_size = 0;
    size_t written = 0;
    int active = 0;
    int entered = 0;
    int committed = 0;
    int cancelled = 0;
    bool destroyed = false;
    bool closed = false;
    bool cleanup_has_owner = false;
    app::RequestLoadState* load = nullptr;
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
    ~Stream() override { state_.destroyed = true; }
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
private:
    State& state_;
};

class Handler final : public Outbound {
public:
    State state;
    State target_state;
    bool relay = false;
    std::string_view Tag() const noexcept override { return "direct"; }
    net::awaitable<OutboundProcessResult> Process(
        net::io_context& io, const tcp::endpoint*, session::Context& ctx,
        const TimeoutsConfig&, transport::Link inbound, StatsShard& stats,
        const RelayConfig& config, buf::MultiBuffer first,
        std::chrono::seconds, std::chrono::seconds) override {
        ++state.entered;
        if (state.block) co_await Wait(state);
        ++state.committed;
        if (!relay) co_return RelayResult{};
        Stream target(target_state);
        if (inbound.control) co_return co_await DoRelayLink(io, *inbound.reader,
            *inbound.writer, *inbound.control, target, ctx, stats, config, std::move(first));
        co_return co_await DoRelayLink(io, *inbound.reader, *inbound.writer,
            target, ctx, stats, config, std::move(first));
    }
};

class Manager final : public features::outbound::Manager {
public:
    std::shared_ptr<Handler> handler = std::make_shared<Handler>();
    std::shared_ptr<Handler> second;
    int lookups = 0;
    HandlerPtr GetHandler(std::string_view tag) noexcept override {
        ++lookups;
        return tag == "second" ? second : handler;
    }
};

class Router final : public routing::Router {
public:
    mutable int calls = 0;
    routing::RouteDecision Route(const session::Context&) const override { ++calls; return {}; }
    routing::DomainStrategy DomainStrategy() const noexcept override {
        return routing::DomainStrategy::IPOnDemand;
    }
};

enum class Case { PreStopped, Sniff, Handshake, RoutingDns, Parent, Pending,
                  Success, RelaySuccess, RelayFailure, SniffMemory, SniffLinkError };

bool Run(Case which, bool controlled, ErrorCode reason = ErrorCode::CANCELLED) {
    net::io_context io;
    app::RequestLoadState load(100, 30);
    State source_state;
    source_state.load = &load;
    source_state.block = which == Case::Sniff;
    source_state.allocation_failure = which == Case::SniffMemory;
    source_state.read_error = which == Case::SniffLinkError ? ErrorCode::RESOURCE_EXHAUSTED : ErrorCode::OK;
    source_state.payload_size = 7;
    auto stream = std::make_unique<Stream>(source_state);
    auto* reader = stream.get();
    Manager manager;
    Router router;
    auto& outbound = *manager.handler;
    outbound.state.load = &load;
    outbound.state.block = which == Case::Handshake || which == Case::Parent || which == Case::Pending;
    outbound.relay = which == Case::RelaySuccess || which == Case::RelayFailure;
    outbound.target_state.payload_size = 13;
    if (which == Case::RelayFailure) outbound.target_state.read_error = ErrorCode::RELAY_READ_FAILED;
    app::dispatcher::DefaultDispatcher dispatcher;
    dispatcher.BindOutboundManager(manager);
    dispatcher.BindRequestLoadState(load);
    dispatcher.BindRouter(router);
    routing::DispatchPolicy policy{SniffConfig{}, routing::ForceOutbound{"direct"}};
    policy.sniffing.enabled = which == Case::Sniff || which == Case::SniffMemory || which == Case::SniffLinkError;
    session::Context ctx;
    ctx.outbound.target = TargetAddress("192.0.2.1", 443);
    ctx.outbound.original_target = ctx.outbound.target;
    ctx.content.network = Network::TCP;
    StatsShard stats;
    TimeoutsConfig timeouts;
    std::optional<udp::socket> dns_peer;
    std::optional<app::dns::DNS> dns;
    if (which == Case::RoutingDns) {
        const auto address = net::ip::make_address("127.0.0.42");
        dns_peer.emplace(io, udp::v4());
        IoErrorCode bind_error;
        dns_peer->bind(udp::endpoint(address, 0), bind_error);
        if (bind_error) throw IoSystemError(bind_error);
        app::dns::Config config;
        config.servers = {dns_peer->local_endpoint()};
        config.timeout_sec = 2;
        dns.emplace(io, config);
        dispatcher.BindDnsService(*dns);
        policy.outbound = routing::RouteWithFallback{"direct"};
        ctx.outbound.target = TargetAddress("dispatcher-cancellation.example", 443);
        ctx.outbound.original_target = ctx.outbound.target;
    }
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
            triggered = which == Case::RoutingDns ? dns_peer->available() > 0 :
                (source_state.active + outbound.state.active == 1);
            if (which == Case::Parent) parent.emit(net::cancellation_type::terminal);
            else if (which == Case::Pending) reader->Cancellation().CancelPending(reason);
            else reader->Cancellation().Stop(reason);
        });
    }
    const size_t before_logs = app::completions;
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
        source_state.active == 0 && outbound.state.active == 0 && app::completions == before_logs + 1 &&
        app::last_result.error == result.error && (!controlled || source_state.destroyed);
    auto expected = reason;
    if (which == Case::Success || which == Case::RelaySuccess) expected = ErrorCode::OK;
    if (which == Case::RelayFailure) expected = ErrorCode::RELAY_READ_FAILED;
    if (which == Case::SniffMemory || which == Case::SniffLinkError) expected = ErrorCode::RESOURCE_EXHAUSTED;
    passed &= result.error == expected;
    if (which == Case::PreStopped || which == Case::Sniff || which == Case::RoutingDns ||
        which == Case::SniffMemory || which == Case::SniffLinkError) passed &= manager.lookups == 0 && outbound.state.entered == 0;
    if (source_state.block || outbound.state.block) {
        const auto& waiting = source_state.block ? source_state : outbound.state;
        passed &= triggered && waiting.cancelled == 1 && waiting.cleanup_has_owner && outbound.state.committed == 0;
    }
    if (which == Case::RoutingDns) passed &= triggered && ctx.outbound.tag.empty();
    if (which == Case::RelaySuccess) passed &= result.bytes_up == 7 && result.bytes_down == 13 &&
        source_state.written == 13 && outbound.target_state.written == 7 && (!controlled || source_state.closed);
    if (!controlled && done) {
        // Borrowed logical inputs may outlive Dispatcher and notify again.
        // No callback may retain its completed task group or stack context.
        reader->Cancellation().CancelPending();
        reader->Cancellation().Stop();
        passed &= app::completions == before_logs + 1;
    }
    std::printf("case=%d controlled=%d reason=%s result=%s timely=%d triggered=%d lookups=%d committed=%d joined=%d: %s\n",
        int(which), controlled, ErrorCodeToString(reason).data(), ErrorCodeToString(result.error).data(),
        completed_in_budget, triggered, manager.lookups, outbound.state.committed,
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
    Manager manager;
    manager.second = std::make_shared<Handler>();
    for (const auto& handler : {manager.handler, manager.second}) {
        handler->state.block = true;
        handler->state.load = &load;
    }
    app::dispatcher::DefaultDispatcher dispatcher;
    dispatcher.BindOutboundManager(manager);
    dispatcher.BindRequestLoadState(load);
    routing::DispatchPolicy policy_a{SniffConfig{.enabled = false}, routing::ForceOutbound{"direct"}};
    routing::DispatchPolicy policy_b{SniffConfig{.enabled = false}, routing::ForceOutbound{"second"}};
    session::Context ctx_a, ctx_b;
    ctx_a.outbound.target = ctx_b.outbound.target = TargetAddress("192.0.2.1", 443);
    StatsShard stats;
    TimeoutsConfig timeouts;
    bool first_done = false, second_done = false, first_joined = false, failed = false;
    RelayResult result_a, result_b;
    const auto logs_before = app::completions;
    const auto link_a = controlled ? transport::Link{} : transport::Link{first.get(), first.get(), nullptr};
    const auto link_b = controlled ? transport::Link{} : transport::Link{second.get(), second.get(), nullptr};
    net::co_spawn(io, dispatcher.Dispatch(io, policy_a, controlled ? std::move(first) : nullptr,
        link_a, InitialPayload{}, ctx_a, stats, timeouts), [&](std::exception_ptr error, RelayResult result) {
            failed |= bool(error);
            first_done = true;
            result_a = result;
            first_joined = manager.handler->state.active == 0 && load.ActiveConnections() == 1;
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
        both_waiting = manager.handler->state.active == 1 && manager.second->state.active == 1;
        source->Cancellation().Stop(ErrorCode::RESOURCE_EXHAUSTED);
    });
    io.run_for(1s);
    const bool passed = !failed && first_done && second_done && both_waiting && first_joined &&
        result_a.error == ErrorCode::RESOURCE_EXHAUSTED && result_b.error == ErrorCode::OK &&
        manager.handler->state.cancelled == 1 && manager.handler->state.committed == 0 &&
        manager.second->state.cancelled == 0 && manager.second->state.committed == 1 &&
        manager.second->state.active == 0 && load.ActiveConnections() == 0 && app::completions == logs_before + 2;
    std::printf("sibling isolation controlled=%d first=%s second=%s joined=%d: %s\n", controlled,
        ErrorCodeToString(result_a.error).data(), ErrorCodeToString(result_b.error).data(), first_joined,
        passed ? "PASS" : "FAIL");
    return passed;
}
}

int main() {
    try {
        bool passed = true;
        for (bool controlled : {false, true}) {
            for (const auto which : {Case::PreStopped, Case::Sniff, Case::Handshake, Case::RoutingDns,
                Case::Parent, Case::Pending, Case::Success, Case::RelaySuccess, Case::RelayFailure,
                Case::SniffMemory, Case::SniffLinkError}) passed &= Run(which, controlled);
            for (const auto which : {Case::PreStopped, Case::Sniff, Case::Handshake})
                passed &= Run(which, controlled, ErrorCode::RESOURCE_EXHAUSTED);
            passed &= SiblingIsolation(controlled);
        }
        return passed ? 0 : 1;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "fixture failure: %s\n", error.what());
        return 1;
    }
}
