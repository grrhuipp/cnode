#include <gtest/gtest.h>

#include "app/inbound_handler.hpp"
#include "app/relay.hpp"
#include "app/rate_limiter.hpp"
#include "app/group_coordinator.hpp"
#include "common/allocator.hpp"
#include "common/session.hpp"
#include "transport/tls_stream.hpp"
#include "transport/transport_stack.hpp"
#include "proxy/anytls/anytls_codec.hpp"
#include "proxy/inbound_admission.hpp"
#include "common/awaitable_task_group.hpp"

#include <asio/co_spawn.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/cancellation_state.hpp>
#include <asio/post.hpp>
#include <asio/experimental/channel.hpp>
#include <asio/this_coro.hpp>
#include <asio/steady_timer.hpp>
#include <array>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <optional>
#include <vector>
#include <string>
#include <tuple>

namespace {

struct State { int fault = 0; int active = 0; bool destroyed = false; int id = 0; };


template<class Scenario>
void RunFixture(const app::RateLimitConfig& config, Scenario scenario) {
    net::io_context io;
    auto coordinator = std::make_shared<app::GroupCoordinator>(io);
    coordinator->RegisterWorker();
    auto limiter = app::ConnectionLimiter::Acquire(config, coordinator);
    common::UserOnlineTracker tracker(*coordinator);
    app::StatsShard stats;
    const app::AdmissionEnvironment environment{
        *coordinator, *limiter, tracker, stats};
    bool finalized = false;
    std::exception_ptr failure;
    bool expired = false;
    net::cancellation_signal cancellation;
    net::steady_timer watchdog(io, std::chrono::seconds(5));
    watchdog.async_wait([&](IoErrorCode error) {
        if (!error) {
            expired = true;
            cancellation.emit(net::cancellation_type::all);
        }
    });
    auto run = [&]() -> net::awaitable<void> {
        try {
            co_await scenario(io, environment);
        } catch (...) {
            failure = std::current_exception();
        }
        co_await net::this_coro::reset_cancellation_state(net::disable_cancellation());
        co_await net::post(io, net::use_awaitable);
        coordinator->CloseAdmission();
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        co_await coordinator->Finalize();
        limiter.reset();
        finalized = true;
    };
    net::co_spawn(io, run(), net::bind_cancellation_slot(cancellation.slot(),
        [&](std::exception_ptr error) {
            if (error) failure = error;
            watchdog.cancel();
        }));
    io.run();
    EXPECT_FALSE(expired) << "inbound fixture exceeded its completion deadline";
    EXPECT_FALSE(failure);
    EXPECT_TRUE(finalized);
}

void Raise(int fault) {
    switch (fault) {
        case 1: throw std::bad_alloc();
        case 2: throw transport::LinkError(common::ErrorCode::BLOCKED);
        case 3: throw IoSystemError(io_error::operation_aborted);
        case 4: throw IoSystemError(io_error::timed_out);
        case 5: throw IoSystemError(io_error::connection_reset);
        case 6: throw std::runtime_error("original-inbound-error");
        case 7: throw 42;
    }
}

class Stream final : public transport::AsyncStream {
public:
    explicit Stream(State& state) : state_(state) {}
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
    net::awaitable<common::MultiBuffer> ReadMultiBuffer() override { co_return common::MultiBuffer{}; }
    void ShutdownWrite() override {}
    void Cancel() noexcept override { NotifyCancellation(); }
    void Close() override { NotifyClosed(); }
    int NativeHandle() const override { return -1; }
    bool IsOpen() const override { return true; }
private:
    State& state_;
};

class Proxy final : public proxy::Inbound {
public:
    Proxy(int fault, bool codec) : fault_(fault), codec_(codec) {}
    net::awaitable<app::RelayResult> Process(std::unique_ptr<transport::AsyncStream> stream,
        routing::Dispatcher&, const app::ReceiverSettings&, net::io_context&,
        common::Context&, const infra::TimeoutsConfig&, uint32_t) override {
        app::RelayResult result;
        if (codec_) {
            auto text = co_await proxy::ReadFrameText(*stream, 19);
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
    net::awaitable<app::RelayResult> Dispatch(net::io_context&, const routing::DispatchPolicy&,
        std::unique_ptr<transport::AsyncStream>, transport::Link, common::InitialPayload, common::Context&,
        app::StatsShard&, const infra::TimeoutsConfig&) override { throw std::logic_error("unexpected dispatch"); co_return app::RelayResult{}; }
};

using Signal = net::experimental::channel<void(IoErrorCode, int)>;

struct QuotaCase {
    QuotaCase(net::io_context& io, app::ConnectionLimiter& connection_limiter,
              uint32_t global_limit, bool ip_rejection, bool reverse)
        : limiter(connection_limiter), limit(global_limit),
          reject_ip(ip_rejection), reverse_completion(reverse),
          events(io, 8), gates{Signal(io, 1), Signal(io, 1), Signal(io, 1)} {
        for (int id = 0; id != 3; ++id) children[id].id = id;
    }

    app::ConnectionLimiter& limiter;
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

class QuotaProxy final : public proxy::Inbound {
public:
    explicit QuotaProxy(QuotaCase& test) : test_(test) {}

    net::awaitable<app::RelayResult> Process(
        std::unique_ptr<transport::AsyncStream> stream, routing::Dispatcher&,
        const app::ReceiverSettings&, net::io_context&,
        common::Context&, const infra::TimeoutsConfig&, uint32_t) override {
        const int id = static_cast<Stream&>(*stream).GetState().id;
        ++test_.entered;
        if (!test_.events.try_send(IoErrorCode{}, id + 1))
            throw std::logic_error("quota fixture event queue is full");
        (void)co_await test_.gates[id].async_receive(net::use_awaitable);
        co_return app::RelayResult{};
    }

private:
    QuotaCase& test_;
};

net::awaitable<void> RunChild(
    QuotaCase& test, transport::InboundTransportStreamHandler& sink, int id) {
    co_await sink.OnInboundTransportStream(std::make_unique<Stream>(test.children[id]), {});
    if (!test.events.try_send(IoErrorCode{}, -id - 1))
        throw std::logic_error("quota fixture event queue is full");
}

net::awaitable<void> CheckGlobalSlots(app::ConnectionLimiter& limiter,
                                    uint32_t limit, uint32_t occupied) {
    // Hold all successful reservations until the bounded-capacity check ends.
    std::vector<app::ConnectionLimiter::Reservation> reservations;
    reservations.reserve(limit);
    for (uint32_t acquired = 0; acquired < limit; ++acquired) {
        auto pending = limiter.TryReserve({
            .scope = app::ConnectionLimiter::ReservationScope::Physical});
        EXPECT_TRUE(pending);
        if (!pending) co_return;
        auto admission = co_await std::move(*pending);
        if (admission.reason != app::ConnectionLimiter::RejectReason::NONE) {
            EXPECT_EQ(admission.reason, app::ConnectionLimiter::RejectReason::MAX_CONNECTIONS);
            break;
        }
        reservations.push_back(std::move(admission.reservation));
    }
    EXPECT_EQ(reservations.size(), limit - occupied);
    auto pending = limiter.TryReserve({
        .scope = app::ConnectionLimiter::ReservationScope::Physical});
    EXPECT_TRUE(pending);
    if (!pending) co_return;
    const auto rejected = co_await std::move(*pending);
    EXPECT_EQ(rejected.reason, app::ConnectionLimiter::RejectReason::MAX_CONNECTIONS);
}

net::awaitable<void> CheckGlobalSlots(QuotaCase& test, uint32_t occupied) {
    co_await CheckGlobalSlots(test.limiter, test.limit, occupied);
}

net::awaitable<void> CheckIPRestored(app::ConnectionLimiter& limiter,
                                    std::string_view ip, bool bounded) {
    auto pending = limiter.TryReserve({
        .scope = app::ConnectionLimiter::ReservationScope::ClientIp,
        .tag = "test", .ip = ip, .check_ban = true});
    EXPECT_EQ(pending.has_value(), bounded);
    if (!pending) co_return;
    auto admitted = co_await std::move(*pending);
    EXPECT_EQ(admitted.reason, app::ConnectionLimiter::RejectReason::NONE);
    if (bounded) {
        auto next = limiter.TryReserve({
            .scope = app::ConnectionLimiter::ReservationScope::ClientIp,
            .tag = "test", .ip = ip, .check_ban = true});
        EXPECT_TRUE(next);
        if (!next) co_return;
        const auto rejected = co_await std::move(*next);
        EXPECT_EQ(rejected.reason, app::ConnectionLimiter::RejectReason::MAX_CONNECTIONS_PER_IP);
    }
}

net::awaitable<void> ExerciseQuota(
    QuotaCase& test, transport::InboundTransportStreamHandler& sink, common::AwaitableTaskGroup& group) {
    group.Spawn(RunChild(test, sink, 0));
    EXPECT_EQ(co_await test.events.async_receive(net::use_awaitable), 1);
    co_await CheckGlobalSlots(test, 1);
    group.Spawn(RunChild(test, sink, 1));
    if (test.limit == 1 || test.reject_ip) {
        EXPECT_EQ(co_await test.events.async_receive(net::use_awaitable), -2);
        EXPECT_TRUE(test.children[1].destroyed);
        EXPECT_EQ(test.entered, 1);
        co_await CheckGlobalSlots(test, 1);
        if (!test.gates[0].try_send(IoErrorCode{}, 0))
            throw std::logic_error("quota fixture gate is full");
        EXPECT_EQ(co_await test.events.async_receive(net::use_awaitable), -1);
    } else {
        EXPECT_EQ(co_await test.events.async_receive(net::use_awaitable), 2);
        co_await CheckGlobalSlots(test, 2);
        const int first = test.reverse_completion ? 1 : 0;
        if (!test.gates[first].try_send(IoErrorCode{}, 0))
            throw std::logic_error("quota fixture gate is full");
        EXPECT_EQ(co_await test.events.async_receive(net::use_awaitable), -first - 1);
        co_await CheckGlobalSlots(test, 1);
        if (!test.gates[1 - first].try_send(IoErrorCode{}, 0))
            throw std::logic_error("quota fixture gate is full");
        EXPECT_EQ(co_await test.events.async_receive(net::use_awaitable), -(1 - first) - 1);
    }
    co_await CheckGlobalSlots(test, 1);
    // A new first child reuses the floor after all prior children complete.
    group.Spawn(RunChild(test, sink, 2));
    EXPECT_EQ(co_await test.events.async_receive(net::use_awaitable), 3);
    co_await CheckGlobalSlots(test, 1);
    if (!test.gates[2].try_send(IoErrorCode{}, 0))
        throw std::logic_error("quota fixture gate is full");
    EXPECT_EQ(co_await test.events.async_receive(net::use_awaitable), -3);
    co_await CheckGlobalSlots(test, 1);
    test.completed = true;
}

void TestQuota(uint32_t limit, bool reject_ip, bool reverse) {
    RunFixture(app::RateLimitConfig{
        .max_connections = limit, .max_conn_per_ip = reject_ip ? 1u : 0u},
        [=](net::io_context& io,
            const app::AdmissionEnvironment& environment) -> net::awaitable<void> {
            auto& limiter = environment.limiter;
            QuotaCase test(io, limiter, limit, reject_ip, reverse);
            State physical;
            app::ReceiverSettings receiver{
                .inbound_tag = "test", .inbound_tags = {}, .protocol = "fixture",
                .stream_settings = {},
                .dispatch_policy = {{}, routing::ForceOutbound{"direct"}},
                .proxy_protocol = transport::ProxyProtocolMode::Off};
            receiver.stream_settings.network_mode = ::transport::NetworkMode::Grpc;
            receiver.stream_settings = transport::NormalizeStreamSettings(receiver.stream_settings);
            auto handler = std::make_shared<app::InboundHandler>(
                std::move(receiver), std::make_unique<QuotaProxy>(test), environment);
            Dispatcher dispatcher;
            auto& stats = environment.stats;
            app::RequestLoadState load(100, 0);
            infra::TimeoutsConfig timeouts;
            common::Context context;
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
            EXPECT_TRUE(test.completed);
            EXPECT_TRUE(physical.destroyed);
            for (const auto& child : test.children) EXPECT_TRUE(child.destroyed);
        });
}

TEST(InboundAdmission, UntrackedAndPerIpReservationsSkipOnlyIrrelevantScopes) {
    using Scope = app::ConnectionLimiter::ReservationScope;
    RunFixture({.max_connections = 1},
        [](net::io_context&, const app::AdmissionEnvironment& environment)
        -> net::awaitable<void> {
        EXPECT_FALSE(environment.limiter.TryReserve({.scope = Scope::ClientIp, .ip = "192.0.2.1"}));
        EXPECT_FALSE(environment.limiter.TryReserve({.scope = Scope::Logical, .ip = "192.0.2.1"}));
        auto pending = environment.limiter.TryReserve({.scope = Scope::Physical});
        EXPECT_TRUE(pending);
        if (!pending) co_return;
        auto physical = co_await std::move(*pending);
        auto child = environment.limiter.TryReserve({
            .scope = Scope::Logical, .family = physical.reservation.FamilyLease()});
        EXPECT_TRUE(child);
        if (!child) co_return;
        auto logical = co_await std::move(*child);
        EXPECT_EQ(logical.reason, app::ConnectionLimiter::RejectReason::NONE);
    });
    RunFixture({}, [](net::io_context&, const app::AdmissionEnvironment& environment)
        -> net::awaitable<void> {
        for (auto scope : {Scope::Physical, Scope::ClientIp, Scope::Logical}) {
            EXPECT_FALSE(environment.limiter.TryReserve({.scope = scope, .tag = "test", .ip = "192.0.2.1"}));
        }
        co_return;
    });
    RunFixture({.max_conn_per_ip = 1},
        [](net::io_context&, const app::AdmissionEnvironment& environment)
        -> net::awaitable<void> {
        EXPECT_FALSE(environment.limiter.TryReserve({.scope = Scope::Physical}));
        for (auto scope : {Scope::ClientIp, Scope::Logical}) {
            auto pending = environment.limiter.TryReserve({.scope = scope, .tag = "test", .ip = "192.0.2.1"});
            EXPECT_TRUE(pending);
            if (!pending) co_return;
            auto admitted = co_await std::move(*pending);
            EXPECT_EQ(admitted.reason, app::ConnectionLimiter::RejectReason::NONE);
            admitted.reservation = {};
            co_await net::post(net::use_awaitable);
        }
    });
}

TEST(InboundAdmission, BanOnlyReservationsRequireAnAttributedNonemptyAddress) {
    RunFixture({.ip_ban = {.enabled = true, .failure_limit = 1, .window_seconds = 60, .ban_seconds = 60}},
        [](net::io_context&, const app::AdmissionEnvironment& environment)
        -> net::awaitable<void> {
        for (auto scope : {app::ConnectionLimiter::ReservationScope::Physical,
                           app::ConnectionLimiter::ReservationScope::ClientIp,
                           app::ConnectionLimiter::ReservationScope::Logical}) {
            EXPECT_FALSE(environment.limiter.TryReserve({.scope = scope, .ip = "192.0.2.1"}));
            EXPECT_FALSE(environment.limiter.TryReserve({.scope = scope, .check_ban = true}));
            auto pending = environment.limiter.TryReserve({
                .scope = scope, .tag = "test", .ip = "192.0.2.1", .check_ban = true});
            EXPECT_TRUE(pending);
            if (!pending) co_return;
            auto admission = co_await std::move(*pending);
            EXPECT_EQ(admission.reason, app::ConnectionLimiter::RejectReason::NONE);
        }
    });
}

TEST(InboundAdmission, PostBindRejectionNeitherBansNorOccupiesADevice) {
    RunFixture({.ip_ban = {.enabled = true, .failure_limit = 1, .window_seconds = 60, .ban_seconds = 60}},
        [](net::io_context&, const app::AdmissionEnvironment& environment)
        -> net::awaitable<void> {
        common::Context context;
        context.inbound.tag = "post-bind";
        context.inbound.source_ip = "192.0.2.1";
        context.inbound.client_ip_source = common::Inbound::ClientIpSource::ProxyProtocol;
        const common::UserProfile profile{.user_id = 7, .email = "bound", .device_limit = 1};
        constexpr std::array<uint8_t, 1> raw{0x41};
        for (unsigned attempt = 0; attempt != 12; ++attempt) {
            context.inbound.user_id = 99;
            context.inbound.user_email = "inherited";
            auto authentication = co_await proxy::BeginInboundAuthentication(environment, context);
            EXPECT_TRUE(authentication);
            if (!authentication) co_return;
            EXPECT_EQ(context.inbound.user_id, 0);
            EXPECT_TRUE(context.inbound.user_email.empty());
            EXPECT_EQ(co_await authentication->VerifyCredential({proxy::KeyedInboundProtocol::Vless, raw}), common::ErrorCode::OK);
            auto bound = std::move(*authentication).Bind(profile,
                proxy::InboundRequestTarget{common::Network::TCP, common::TargetAddress(net::ip::address_v4::loopback(), 443)});
            EXPECT_EQ(context.inbound.user_id, profile.user_id);
            EXPECT_EQ(std::string_view(context.inbound.user_email), std::string_view(profile.email));
            EXPECT_EQ(context.outbound.target.port, 443);
            EXPECT_EQ(std::move(bound).Reject("flow rejected", common::ErrorCode::PROTOCOL_UNSUPPORTED), common::ErrorCode::PROTOCOL_UNSUPPORTED);
        }
        EXPECT_FALSE(co_await environment.limiter.IsBanned(context.inbound.tag, context.inbound.source_ip));
        EXPECT_EQ(environment.online_users.OnlineDeviceCount(context.inbound.tag, 7), 0);
        auto authentication = co_await proxy::BeginInboundAuthentication(environment, context);
        EXPECT_TRUE(authentication);
        if (!authentication) co_return;
        auto admitted = co_await proxy::AuthenticateAndAdmit(
            std::move(*authentication), &profile, "no matching user", std::nullopt);
        EXPECT_TRUE(admitted);
        EXPECT_EQ(environment.online_users.OnlineDeviceCount(context.inbound.tag, 7), 1);
    });
}
}

// Replace the external transport builder and reporting sink; execute the
// production accepted-TCP and logical-transport ownership/error boundaries.

net::awaitable<transport::TransportBuildResult> transport::BuildInboundTransport(app::GroupCoordinator&, net::io_context&,
    std::unique_ptr<transport::AsyncStream> raw, const transport::StreamSettings&, transport::SslContext*, uint64_t,
    std::shared_ptr<transport::InboundTransportStreamHandler> streams, transport::InboundTransportMetadata*,
    const transport::InboundFallbackContext*) {
    if (streams) {
        streams->OnInboundTransportReady(*raw);
        if (quota_case) {
            co_await common::RunAwaitableTaskGroup(co_await net::this_coro::executor, [&](common::AwaitableTaskGroup& group) {
                group.Spawn(ExerciseQuota(*quota_case, *streams, group));
            });
        } else {
            co_await streams->OnInboundTransportStream(std::move(raw), {});
        }
        co_return std::unique_ptr<transport::AsyncStream>{};
    }
    co_return raw;
}
net::awaitable<transport::ProxyProtocolReadResult> transport::ReadInboundProxyProtocol(transport::AsyncStream&, std::chrono::seconds) {
    throw std::logic_error("unexpected proxy protocol"); co_return transport::ProxyProtocolReadResult{};
}
class InboundFailureBoundary
    : public ::testing::TestWithParam<std::tuple<bool, bool, int>> {};

TEST_P(InboundFailureBoundary, ReleasesStreamAndAdmissionAfterProtocolCompletion) {
    const auto [logical, codec, fault] = GetParam();
    State state{.fault = fault};
    bool returned = false;
    RunFixture(
        app::RateLimitConfig{.max_connections = 1, .max_conn_per_ip = 1},
        [&](net::io_context& io,
            const app::AdmissionEnvironment& environment) -> net::awaitable<void> {
            auto& limiter = environment.limiter;
            app::ReceiverSettings receiver{
                .inbound_tag = "test", .inbound_tags = {}, .protocol = "fixture",
                .stream_settings = {},
                .dispatch_policy = {{}, routing::ForceOutbound{"direct"}},
                .proxy_protocol = transport::ProxyProtocolMode::Off};
            receiver.stream_settings.network_mode = logical ? ::transport::NetworkMode::Grpc : ::transport::NetworkMode::Tcp;
            receiver.stream_settings = transport::NormalizeStreamSettings(receiver.stream_settings);
            auto handler = std::make_shared<app::InboundHandler>(
                std::move(receiver), std::make_unique<Proxy>(fault, codec), environment);
            Dispatcher dispatcher;
            auto& stats = environment.stats;
            app::RequestLoadState load(100, 0);
            infra::TimeoutsConfig timeouts;
            common::Context context;
            context.conn_id = 1;
            context.inbound.tag = "test";
            co_await handler->ProcessAcceptedTCP(io, dispatcher, stats, load, timeouts,
                std::make_unique<Stream>(state), context);
            returned = true;
            EXPECT_TRUE(state.destroyed);
            EXPECT_EQ(state.active, 0);
            co_await CheckGlobalSlots(limiter, 1, 0);
            co_await CheckIPRestored(limiter, context.inbound.source_ip, true);
        });
    EXPECT_TRUE(returned);
}

INSTANTIATE_TEST_SUITE_P(OwnershipAndFaults, InboundFailureBoundary, ::testing::Combine(::testing::Bool(), ::testing::Bool(), ::testing::Range(0, 8)), ([](const ::testing::TestParamInfo<InboundFailureBoundary::ParamType>& info) { const auto [logical, codec, fault] = info.param;
constexpr std::array names{"Success", "Memory", "Blocked", "Cancelled",
                           "Timeout", "ConnectionReset", "Exception", "UnknownException"};
return std::string(logical ? "Logical" : "Physical") +
    (codec ? "Codec" : "Protocol") + names[fault]; }));

class LogicalInboundQuota
    : public ::testing::TestWithParam<std::tuple<uint32_t, bool, bool>> {};

TEST_P(LogicalInboundQuota, RestoresSharedPhysicalAndIpSlotsAfterChildrenJoin) {
    const auto [limit, reject_ip, reverse] = GetParam();
    TestQuota(limit, reject_ip, reverse);
}

INSTANTIATE_TEST_SUITE_P(AdmissionAndCompletionOrder, LogicalInboundQuota, ::testing::Values(LogicalInboundQuota::ParamType{1u, false, false},
    LogicalInboundQuota::ParamType{1u, true, false},
    LogicalInboundQuota::ParamType{2u, true, false},
    LogicalInboundQuota::ParamType{2u, false, false},
    LogicalInboundQuota::ParamType{2u, false, true}), ([](const ::testing::TestParamInfo<LogicalInboundQuota::ParamType>& info) { const auto [limit, reject_ip, reverse] = info.param;
return "Limit" + std::to_string(limit) + (reject_ip ? "PerIp" : "Global") +
    (reverse ? "ReverseCompletion" : "ForwardCompletion"); }));

TEST(InboundAdmission, ClosedCoordinatorCancelsEveryAuthenticationPhaseWithoutADevice) {
    RunFixture({.ip_ban = {.enabled = true, .failure_limit = 1, .window_seconds = 60, .ban_seconds = 60}},
        [](net::io_context&, const app::AdmissionEnvironment& environment)
        -> net::awaitable<void> {
        common::Context context;
        context.inbound.tag = "closed";
        context.inbound.source_ip = "192.0.2.1";
        auto authentication = co_await proxy::BeginInboundAuthentication(environment, context);
        EXPECT_TRUE(authentication);
        if (!authentication) co_return;
        auto credential_phase = co_await proxy::BeginInboundAuthentication(environment, context);
        EXPECT_TRUE(credential_phase);
        if (!credential_phase) co_return;
        const common::UserProfile profile{.user_id = 9, .email = "closed", .device_limit = 1};
        auto bound = std::move(*authentication).Bind(profile, std::nullopt);
        environment.coordinator.CloseAdmission();
        auto admitted = co_await std::move(bound).Admit();
        EXPECT_FALSE(admitted);
        if (!admitted) EXPECT_EQ(admitted.error(), common::ErrorCode::CANCELLED);
        constexpr std::array<uint8_t, 1> credential{0x42};
        EXPECT_EQ(co_await credential_phase->VerifyCredential({proxy::KeyedInboundProtocol::Vless, credential}), common::ErrorCode::CANCELLED);
        context.inbound.client_ip_source = common::Inbound::ClientIpSource::ProxyProtocol;
        auto beginning = co_await proxy::BeginInboundAuthentication(environment, context);
        EXPECT_FALSE(beginning);
        if (!beginning) EXPECT_EQ(beginning.error(), common::ErrorCode::CANCELLED);
        EXPECT_EQ(environment.online_users.OnlineDeviceCount(context.inbound.tag, 9), 0);
        EXPECT_EQ(environment.stats.errors, 0);
    });
}
