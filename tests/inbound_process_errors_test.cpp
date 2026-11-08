#include <gtest/gtest.h>

#include "app/proxyman/inbound/handler.hpp"
#include "app/request_load_state.hpp"
#include "app/rate_limiter.hpp"
#include "app/session_group_executor.hpp"
#include "common/allocator.hpp"
#include "common/session.hpp"
#include "transport/internet/tls_stream.hpp"
#include "transport/internet/transport_stack.hpp"
#include "transport/link_error.hpp"
#include "anytls_codec.hpp"
#include "../src/common/awaitable_task_group.hpp"

#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <optional>
#include <vector>

namespace {

struct State { int fault = 0; int active = 0; bool destroyed = false; int id = 0; };

void Check(bool condition) {
    if (!condition) throw std::runtime_error("inbound fixture invariant failed");
}

struct DomainHooks final : ExecutionDomain::Hooks {
    memory::AllocationDomain allocation;
    std::optional<memory::ScopedAllocationDomain> lease;
    std::exception_ptr failure;

    void Enter() noexcept override { lease.emplace(allocation); }
    void Leave() noexcept override { lease.reset(); }
    void OnFailure(std::exception_ptr error) noexcept override { failure = error; }
};

// Keep the coordinator on the reactor, but construct, execute and destroy every
// request object on the real domain executor with its allocation lease active.
template<class Scenario>
bool RunFixture(const RateLimitConfig& config, Scenario scenario) {
    net::io_context io;
    auto coordinator = std::make_shared<GroupCoordinator>(io);
    coordinator->RegisterWorker(0, io, io.get_executor());
    auto hooks = std::make_shared<DomainHooks>();
    auto domain = ExecutionDomain::Create(io, 0, io.get_executor(), hooks, coordinator);
    hooks->allocation.SetLeaseGroup(
        domain->LeaseIdentity(), ExecutionDomain::SharesLeaseIdentity);
    auto limiter = ConnectionLimiter::Acquire(config, coordinator);
    bool result = false;
    bool finalized = false;
    std::exception_ptr failure;
    auto run = [&]() -> net::awaitable<void> {
        try {
            result = co_await net::co_spawn(domain->Executor(),
                [&]() -> net::awaitable<bool> {
                    Check(ExecutionDomain::Current() == domain);
                    co_return co_await scenario(io, *limiter);
                }, net::use_awaitable);
        } catch (...) {
            failure = std::current_exception();
        }
        // Leave any inline domain completion before destroying its services.
        co_await net::post(io, net::use_awaitable);
        coordinator->CloseAdmission();
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        domain.reset();
        co_await coordinator->Finalize();
        limiter.reset();
        finalized = true;
    };
    net::co_spawn(io, run(), [&](std::exception_ptr error) {
        if (error) failure = error;
    });
    io.run();
    if (!failure) failure = hooks->failure;
    if (failure) {
        try { std::rethrow_exception(failure); }
        catch (const std::exception& error) {
            std::printf("fixture parent failure: %s\n", error.what());
        }
        catch (...) { std::printf("fixture parent failure: unknown\n"); }
    }
    return result && finalized && !failure;
}

void Raise(int fault) {
    switch (fault) {
        case 1: throw std::bad_alloc();
        case 2: throw transport::LinkError(ErrorCode::BLOCKED);
        case 3: throw IoSystemError(io_error::operation_aborted);
        case 4: throw IoSystemError(io_error::timed_out);
        case 5: throw IoSystemError(io_error::connection_reset);
        case 6: throw std::runtime_error("original-inbound-error");
        case 7: throw 42;
    }
}

class Stream final : public AsyncStream {
public:
    explicit Stream(State& state) : state_(state) {
        Check(bool(ExecutionDomain::Current()));
        Check(memory::CurrentAllocationDomain() != nullptr);
    }
    State& GetState() noexcept { return state_; }
    ~Stream() override { if (state_.active != 0) std::terminate(); state_.destroyed = true; }
    net::awaitable<size_t> AsyncRead(net::mutable_buffer buffer) override {
        ++state_.active;
        co_await net::post(net::use_awaitable);
        --state_.active;
        Raise(state_.fault);
        std::memset(buffer.data(), 0, buffer.size());
        co_return buffer.size();
    }
    net::awaitable<size_t> AsyncWrite(net::const_buffer buffer) override { co_return buffer.size(); }
    net::awaitable<buf::MultiBuffer> ReadMultiBuffer() override { co_return buf::MultiBuffer{}; }
    void ShutdownWrite() override {}
    void Cancel() noexcept override { NotifyCancellation(); }
    void Close() override { NotifyClosed(); }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return true; }
private:
    State& state_;
};

class Proxy final : public Inbound {
public:
    Proxy(int fault, bool codec) : fault_(fault), codec_(codec) {}
    net::awaitable<RelayResult> Process(std::unique_ptr<AsyncStream> stream,
        routing::Dispatcher&, const proxyman::inbound::ReceiverSettings&, net::io_context&,
        session::Context&, const TimeoutsConfig&, uint32_t) override {
        RelayResult result;
        if (codec_) {
            auto text = co_await anytls::ReadFrameText(*stream, 19);
            if (!text) result.error = text.error();
        } else {
            co_await net::post(net::use_awaitable);
            Raise(fault_);
        }
        co_return result;
    }
private:
    int fault_;
    bool codec_;
};

class Dispatcher final : public routing::Dispatcher {
    net::awaitable<RelayResult> Dispatch(net::io_context&, const routing::DispatchPolicy&,
        std::unique_ptr<AsyncStream>, transport::Link, InitialPayload, session::Context&,
        StatsShard&, const TimeoutsConfig&) override { throw std::logic_error("unexpected dispatch"); co_return RelayResult{}; }
};

using Signal = net::experimental::channel<void(IoErrorCode, int)>;

struct QuotaCase {
    QuotaCase(net::io_context& io, ConnectionLimiter& connection_limiter,
              uint32_t global_limit, bool ip_rejection, bool reverse)
        : limiter(connection_limiter), limit(global_limit),
          reject_ip(ip_rejection), reverse_completion(reverse),
          events(io, 8), gates{Signal(io, 1), Signal(io, 1), Signal(io, 1)} {
        for (int id = 0; id != 3; ++id) children[id].id = id;
    }

    ConnectionLimiter& limiter;
    uint32_t limit;
    bool reject_ip;
    bool reverse_completion;
    Signal events;
    std::array<Signal, 3> gates;
    std::array<State, 3> children;
    int entered = 0;
    bool completed = false;
};

QuotaCase* quota_case = nullptr;

class QuotaProxy final : public Inbound {
public:
    explicit QuotaProxy(QuotaCase& test) : test_(test) {}

    net::awaitable<RelayResult> Process(
        std::unique_ptr<AsyncStream> stream, routing::Dispatcher&,
        const proxyman::inbound::ReceiverSettings&, net::io_context&,
        session::Context&, const TimeoutsConfig&, uint32_t) override {
        const int id = static_cast<Stream&>(*stream).GetState().id;
        ++test_.entered;
        Check(test_.events.try_send(IoErrorCode{}, id + 1));
        (void)co_await test_.gates[id].async_receive(net::use_awaitable);
        co_return RelayResult{};
    }

private:
    QuotaCase& test_;
};

net::awaitable<void> RunChild(
    QuotaCase& test, InboundTransportStreamHandler& sink, int id) {
    co_await sink.OnInboundTransportStream(std::make_unique<Stream>(test.children[id]), {});
    Check(test.events.try_send(IoErrorCode{}, -id - 1));
}

net::awaitable<void> CheckGlobalSlots(ConnectionLimiter& limiter,
                                    uint32_t limit, uint32_t occupied) {
    // Hold all successful reservations until the bounded-capacity check ends.
    std::vector<ConnectionLimiter::Reservation> reservations;
    reservations.reserve(limit);
    for (uint32_t acquired = 0; acquired < limit; ++acquired) {
        auto admission = co_await limiter.ReservePhysical();
        if (admission.reason != ConnectionLimiter::RejectReason::NONE) {
            Check(admission.reason == ConnectionLimiter::RejectReason::MAX_CONNECTIONS);
            break;
        }
        reservations.push_back(std::move(admission.reservation));
    }
    Check(reservations.size() == limit - occupied);
    const auto rejected = co_await limiter.ReservePhysical();
    Check(rejected.reason == ConnectionLimiter::RejectReason::MAX_CONNECTIONS);
}

net::awaitable<void> CheckGlobalSlots(QuotaCase& test, uint32_t occupied) {
    co_await CheckGlobalSlots(test.limiter, test.limit, occupied);
}

net::awaitable<void> CheckIPRestored(ConnectionLimiter& limiter,
                                    std::string_view ip, bool bounded) {
    auto admitted = co_await limiter.ReserveIP("test", ip, true);
    Check(admitted.reason == ConnectionLimiter::RejectReason::NONE);
    if (bounded) {
        const auto rejected = co_await limiter.ReserveIP("test", ip, true);
        Check(rejected.reason == ConnectionLimiter::RejectReason::MAX_CONNECTIONS_PER_IP);
    }
}

net::awaitable<void> ExerciseQuota(
    QuotaCase& test, InboundTransportStreamHandler& sink, AwaitableTaskGroup& group) {
    group.Spawn(RunChild(test, sink, 0));
    Check(co_await test.events.async_receive(net::use_awaitable) == 1);
    co_await CheckGlobalSlots(test, 1);
    group.Spawn(RunChild(test, sink, 1));
    if (test.limit == 1 || test.reject_ip) {
        Check(co_await test.events.async_receive(net::use_awaitable) == -2);
        Check(test.children[1].destroyed && test.entered == 1);
        co_await CheckGlobalSlots(test, 1);
        Check(test.gates[0].try_send(IoErrorCode{}, 0));
        Check(co_await test.events.async_receive(net::use_awaitable) == -1);
    } else {
        Check(co_await test.events.async_receive(net::use_awaitable) == 2);
        co_await CheckGlobalSlots(test, 2);
        const int first = test.reverse_completion ? 1 : 0;
        Check(test.gates[first].try_send(IoErrorCode{}, 0));
        Check(co_await test.events.async_receive(net::use_awaitable) == -first - 1);
        co_await CheckGlobalSlots(test, 1);
        Check(test.gates[1 - first].try_send(IoErrorCode{}, 0));
        Check(co_await test.events.async_receive(net::use_awaitable) == -(1 - first) - 1);
    }
    co_await CheckGlobalSlots(test, 1);
    // A new first child reuses the floor after all prior children complete.
    group.Spawn(RunChild(test, sink, 2));
    Check(co_await test.events.async_receive(net::use_awaitable) == 3);
    co_await CheckGlobalSlots(test, 1);
    Check(test.gates[2].try_send(IoErrorCode{}, 0));
    Check(co_await test.events.async_receive(net::use_awaitable) == -3);
    co_await CheckGlobalSlots(test, 1);
    test.completed = true;
}

bool TestQuota(uint32_t limit, bool reject_ip, bool reverse) {
    return RunFixture(RateLimitConfig{
        .max_connections = limit, .max_conn_per_ip = reject_ip ? 1u : 0u},
        [=](net::io_context& io, ConnectionLimiter& limiter) -> net::awaitable<bool> {
            QuotaCase test(io, limiter, limit, reject_ip, reverse);
            State physical;
            proxyman::inbound::ReceiverSettings receiver{
                .inbound_tag = "test", .inbound_tags = {}, .protocol = "fixture",
                .stream_settings = {},
                .dispatch_policy = {{}, routing::ForceOutbound{"direct"}},
                .proxy_protocol = ProxyProtocolMode::Off};
            receiver.stream_settings.network = "grpc";
            receiver.stream_settings = NormalizeStreamSettings(receiver.stream_settings);
            auto handler = std::make_shared<proxyman::inbound::Handler>(
                std::move(receiver), std::make_unique<QuotaProxy>(test), limiter);
            Dispatcher dispatcher;
            StatsShard stats;
            app::RequestLoadState load(100, 0);
            TimeoutsConfig timeouts;
            session::Context context;
            context.inbound.tag = "test";
            context.inbound.source_ip = "192.0.2.1";
            struct ActiveQuota {
                explicit ActiveQuota(QuotaCase& test) { quota_case = &test; }
                ~ActiveQuota() { quota_case = nullptr; }
            } active(test);
            co_await handler->ProcessAcceptedTCP(io, dispatcher, stats, load, timeouts,
                std::make_unique<Stream>(physical), context);
            co_await CheckGlobalSlots(limiter, limit, 0);
            co_await CheckIPRestored(limiter, context.inbound.source_ip, reject_ip);
            co_return test.completed && physical.destroyed &&
                test.children[0].destroyed && test.children[1].destroyed &&
                test.children[2].destroyed;
        });
}
}

// Replace the external transport builder and reporting sink; execute the
// production accepted-TCP and logical-transport ownership/error boundaries.

net::awaitable<TransportBuildResult> BuildInboundTransport(net::io_context&,
    std::unique_ptr<AsyncStream> raw, const StreamSettings&, SslContext*, uint64_t,
    std::shared_ptr<InboundTransportStreamHandler> streams, InboundTransportMetadata*,
    const InboundFallbackContext*) {
    if (streams) {
        streams->OnInboundTransportReady(*raw);
        if (quota_case) {
            co_await RunAwaitableTaskGroup(co_await net::this_coro::executor, [&](AwaitableTaskGroup& group) {
                group.Spawn(ExerciseQuota(*quota_case, *streams, group));
            });
        } else {
            co_await streams->OnInboundTransportStream(std::move(raw), {});
        }
        co_return std::unique_ptr<AsyncStream>{};
    }
    co_return raw;
}
net::awaitable<ProxyProtocolReadResult> ReadInboundProxyProtocol(AsyncStream&, std::chrono::seconds) {
    throw std::logic_error("unexpected proxy protocol"); co_return ProxyProtocolReadResult{};
}
TEST(InboundProcessErrors, Contract) {
    size_t passed = 0, total = 0;
    for (bool logical : {false, true}) for (bool codec : {false, true}) for (int fault = 0; fault < 8; ++fault) {
        State state{.fault = fault};
        bool returned = false;
        const bool ok = RunFixture(
            RateLimitConfig{.max_connections = 1, .max_conn_per_ip = 1},
            [&](net::io_context& io, ConnectionLimiter& limiter) -> net::awaitable<bool> {
        proxyman::inbound::ReceiverSettings receiver{
            .inbound_tag = "test", .inbound_tags = {}, .protocol = "fixture",
            .stream_settings = {},
            .dispatch_policy = {{}, routing::ForceOutbound{"direct"}},
            .proxy_protocol = ProxyProtocolMode::Off};
        receiver.stream_settings.network = logical ? "grpc" : "tcp";
        receiver.stream_settings = NormalizeStreamSettings(receiver.stream_settings);
        auto handler = std::make_shared<proxyman::inbound::Handler>(
            std::move(receiver), std::make_unique<Proxy>(fault, codec), limiter);
        Dispatcher dispatcher;
        StatsShard stats;
        app::RequestLoadState load(100, 0);
        TimeoutsConfig timeouts;
        session::Context context;
        context.conn_id = 1;
        context.inbound.tag = "test";
        co_await handler->ProcessAcceptedTCP(io, dispatcher, stats, load, timeouts,
            std::make_unique<Stream>(state), context);
        returned = true;
        co_await CheckGlobalSlots(limiter, 1, 0);
        co_await CheckIPRestored(limiter, context.inbound.source_ip, true);
        co_return returned && state.destroyed;
        });
        ++total;
        passed += ok;
        std::printf("inbound logical=%d codec=%d fault=%d released=%d returned=%d: %s\n",
            logical, codec, fault, state.destroyed, returned, ok ? "PASS" : "FAIL");
    }
    for (uint32_t limit : {1u, 2u}) {
        for (bool reject_ip : {false, true}) {
            for (bool reverse : {false, true}) {
                const bool ok = TestQuota(limit, reject_ip, reverse);
                ++total;
                passed += ok;
                std::printf("quota=%u ip_rejection=%d reverse=%d: %s\n",
                    limit, reject_ip, reverse, ok ? "PASS" : "FAIL");
            }
        }
    }
    std::printf("inbound cases=%zu passed=%zu failed=%zu\n", total, passed, total - passed);
    { ASSERT_TRUE(passed == total); return; }
}
