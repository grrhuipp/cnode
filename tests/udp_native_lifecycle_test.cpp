#include <stdexcept>
#include <gtest/gtest.h>

#include "app/udp_ingress.hpp"
#include "udp_ingress_fixture.hpp"
#include "worker_coordinator_fixture.hpp"
#include "proxy/shadowsocks/ss_inbound.hpp"
#include "proxy/shadowsocks/ss_udp.hpp"
#include "app/relay.hpp"

#include "app/inbound_handler.hpp"
#include "app/stats.hpp"
#include "common/user_online_tracker.hpp"
#include "common/session.hpp"
#include "routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <exception>
#include <memory>
#include <new>
#include <span>
#include <string_view>
#include <vector>

namespace {
using namespace std::chrono_literals;
using Ingress = ::app::UdpIngress;
using Reclaimer = ::app::UdpAssociationReclaimer;




class NativeResponse final : public ::proxy::InboundDatagramResponse {
public:
    ::common::MultiBuffer Encode(::proxy::UDPPacketView packet) override {
        ::common::MultiBuffer payload;
        if (!payload.AppendSpan(packet.data)) return {};
        return payload;
    }
};

class NativeInbound final : public ::proxy::Inbound {
public:

    ::net::awaitable<::app::RelayResult> Process(
        std::unique_ptr<::transport::AsyncStream>, ::routing::Dispatcher&,
        const ::app::ReceiverSettings&, ::net::io_context&,
        ::common::Context&, const ::infra::TimeoutsConfig&, uint32_t) override {
        co_return ::app::RelayResult{};
    }

    tl::expected<::proxy::InboundDatagramResult, ::common::ErrorCode> Process(
        const ::proxy::InboundDatagramRequest& request) override {
        ::proxy::InboundDatagramResult result;
        result.user = &profile_;
        constexpr std::array<uint8_t, 1> owner{0x47};
        if (!result.session_owner.Assign(owner))
            return tl::unexpected(::common::ErrorCode::RESOURCE_EXHAUSTED);
        result.session_id = request.payload.front() == 0x63 ? 2 : 1;
        result.target = ::common::TargetAddress(
            ::net::ip::address_v4::loopback(), 53);
        auto buffer = ::common::BufferGuard{::common::Buffer::New()};
        if (!buffer) return tl::unexpected(::common::ErrorCode::RESOURCE_EXHAUSTED);
        buffer->Tail()[0] = request.payload.front();
        buffer->Produce(1);
        result.payload.push_back(std::move(buffer));
        return result;
    }
    tl::expected<std::shared_ptr<::proxy::InboundDatagramResponse>, ::common::ErrorCode>
    CreateDatagramResponse(const ::proxy::InboundDatagramResult&) override {
        return std::make_shared<NativeResponse>();
    }

private:
    ::common::UserProfile profile_;
};

class GateDispatcher final : public ::routing::Dispatcher {
    struct RequestCancellation final : ::transport::CancellationSubscription {
        explicit RequestCancellation(GateDispatcher& owner) noexcept : owner(owner) {}
        GateDispatcher& owner;
    private:
        void OnCancellation(::transport::Cancellation) noexcept override {
            ++owner.cancellations;
            if (owner.reenter_stop && !owner.stop_reentered) {
                owner.stop_reentered = true;
                owner.ingress->RequestStop();
            }
        }
    };

public:
    explicit GateDispatcher(::net::io_context& io) : gate(io) {
        gate.expires_after(10s);
    }

    ::net::awaitable<::app::RelayResult> Dispatch(
        ::net::io_context&, const ::routing::DispatchPolicy& policy,
        std::unique_ptr<::transport::AsyncStream>, ::transport::Link link,
        ::common::InitialPayload, ::common::Context& context, ::app::StatsShard&,
        const ::infra::TimeoutsConfig&) override {
        const auto* forced = std::get_if<::routing::ForceOutbound>(&policy.outbound);
        EXPECT_NE(forced, nullptr);
        if (forced) EXPECT_EQ(forced->outbound_tag, "loopback");
        EXPECT_EQ(context.inbound.tag, "receiver-tag");
        EXPECT_EQ(context.inbound.tags.size(), 1u);
        if (!context.inbound.tags.empty()) EXPECT_EQ(context.inbound.tags.front(), "route-tag");
        EXPECT_LT(dispatches, sessions.size());
        EXPECT_NE(link.reader, nullptr);
        if (dispatches >= sessions.size() || !link.reader) co_return ::app::RelayResult{};
        sessions[dispatches++] = static_cast<Ingress::ClientSession*>(link.reader);
        auto payload = co_await link.reader->ReadMultiBuffer();
        EXPECT_EQ(payload.byte_size(), 1u);
        for (const auto* buffer : payload) {
            EXPECT_NE(buffer, nullptr);
            if (!buffer) continue;
            EXPECT_EQ(buffer->Len(), 1u);
            if (buffer->Len() != 1) continue;
            EXPECT_TRUE(buffer->Bytes()[0] == 0x62 || buffer->Bytes()[0] == 0x63);
        }
        ++packets_read;
        RequestCancellation cancellation(*this);
        cancellation.Resubscribe(link.reader->Cancellation());
        auto [ec] = co_await gate.async_wait(
            ::net::as_tuple(::net::use_awaitable));
        (void)ec;
        co_return ::app::RelayResult{};
    }


    ::net::steady_timer gate;
    Ingress* ingress = nullptr;
    // Kept alive by their native jobs until the gate releases them.
    std::array<Ingress::ClientSession*, 4> sessions{};
    size_t dispatches = 0;
    size_t packets_read = 0;
    size_t cancellations = 0;
    bool reenter_stop = false;
    bool stop_reentered = false;
};


::net::awaitable<void> ObserveJoin(Ingress& ingress, bool& returned) {
    co_await ingress.AsyncJoin();
    returned = true;
}


::net::awaitable<void> ObserveCancelledJoin(
    Ingress& ingress, bool& returned, bool& parent_cancelled,
    bool& throw_setting, ::net::cancellation_signal& parent_signal) {
    co_await ::net::this_coro::throw_if_cancelled(false);
    // Cancel after the child starts, but before joining. Cancelling co_spawn
    // before entry would prevent this coroutine from ever calling AsyncJoin.
    parent_signal.emit(::net::cancellation_type::terminal);
    co_await ingress.AsyncJoin();
    const auto cancellation_state =
        co_await ::net::this_coro::cancellation_state;
    parent_cancelled = cancellation_state.cancelled() !=
        ::net::cancellation_type::none;
    throw_setting = co_await ::net::this_coro::throw_if_cancelled();
    returned = true;
}

::app::ReceiverSettings MakeReceiver() {
    auto receiver = ::app::ReceiverSettings{
        .inbound_tag = "receiver-tag",
        .inbound_tags = {"route-tag"},
        .protocol = "native-test",
        .stream_settings = {},
        .dispatch_policy = {
            .sniffing = {},
            .outbound = ::routing::ForceOutbound{"loopback"}}};
    receiver.stream_settings.security_mode = ::transport::SecurityMode::Tls;
    return receiver;
}



struct DrainNativeJobs {
    ::net::io_context& io;
    Ingress& ingress;
    GateDispatcher& dispatcher;
    ~DrainNativeJobs() {
        ingress.RequestStop();
        dispatcher.gate.cancel();
        io.restart();
        bool joined = false;
        ::net::co_spawn(io, ObserveJoin(ingress, joined), ::net::detached);
        io.run();
        EXPECT_TRUE(joined);
    }
};

class UdpNativeLifecycleTest : public ::testing::Test {
protected:
    ::net::io_context io;
    WorkerCoordinatorFixture coordinator{io};
    std::shared_ptr<::app::ConnectionLimiter> limiter =
        ::app::ConnectionLimiter::Acquire({}, coordinator.Get());
    ::common::UserOnlineTracker tracker{*coordinator.Get()};
    ::app::StatsShard stats;
    const ::app::AdmissionEnvironment admission{
        *coordinator.Get(), *limiter, tracker, stats};
    ::app::RequestLoadState request_load{1024, 0};
    UdpNativeLifecycleTest() { coordinator.Get()->RegisterWorker(); }
    ::transport::TimeoutScheduler& scheduler = ::transport::TimeoutScheduler::ForIoContext(io);
    Reclaimer reclaimer{scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); }};
};

TEST_F(UdpNativeLifecycleTest, RetiredSocketJobsCannotAffectReplacementIdentity) {
    io.restart();
    UdpSocketFixtures sockets(io);
    ::app::UdpResourceBudget budget({
        .associations = 2, .datagrams = 8, .payload_capacity = 64 * 1024});
    Ingress ingress("native-reuse", std::make_unique<NativeInbound>(), reclaimer, budget, io);
    Ingress other("native-other", std::make_unique<NativeInbound>(), reclaimer, budget, io);
    auto old_socket = Ingress::MakeSocket(io);
    ::IoErrorCode ec;
    old_socket->open(::udp::v4(), ec);
    ASSERT_FALSE(ec) << "failed to open old socket identity test socket";
    old_socket->bind({::net::ip::address_v4::loopback(), 0}, ec);
    ASSERT_FALSE(ec) << "failed to attach old socket identity";
    ASSERT_TRUE(sockets.Attach(ingress, "identity-socket", old_socket)) << "failed to attach old socket identity";
    GateDispatcher dispatcher(io);
    DrainNativeJobs drain{io, ingress, dispatcher};
    ::infra::TimeoutsConfig timeouts;
    auto receiver = MakeReceiver();
    const ::app::DatagramSessionEnvironment environment{
        .timeouts = timeouts, .dispatcher = &dispatcher,
        .admission = &admission, .request_load = &request_load};
    constexpr std::array<uint8_t, 1> packet{0x62};
    auto process = [&](const Ingress::SocketPtr& current) {
        ingress.ProcessDatagram(::app::UdpDatagramContext{
            .socket = sockets.Find(ingress, current.get()).get(),
            .client_endpoint = {::net::ip::address_v4::loopback(), 47123},
            .payload = packet,
            .receiver = &receiver,
            .io_context = io,
            .worker_id = 6,
            .environment = environment,
        });
    };
    process(old_socket);
    io.poll();
    io.restart();
    EXPECT_EQ(dispatcher.dispatches, 1) << "old socket identity did not start its native dispatch";
    EXPECT_EQ(dispatcher.packets_read, 1) << "old socket identity did not start its native dispatch";
    ::proxy::InboundDatagramOwner owner;
    constexpr std::array<uint8_t, 1> owner_bytes{0x47};
    EXPECT_TRUE(owner.Assign(owner_bytes)) << "failed to create socket identity owner";
    const ::app::ClientSessionKey client_key{owner, 1};
    auto* const old_session = dispatcher.sessions[0];
    ASSERT_TRUE(old_session) << "old socket session was not created";
    EXPECT_EQ(ingress.GetResourceStats().associations, 1) << "old socket session was not created";
    ingress.CloseSocket(*sockets.Get(ingress, "identity-socket"));

    auto replacement_socket = Ingress::MakeSocket(io);
    replacement_socket->open(::udp::v4(), ec);
    ASSERT_FALSE(ec) << "failed to open replacement socket identity";
    replacement_socket->bind({::net::ip::address_v4::loopback(), 0}, ec);
    ASSERT_FALSE(ec) << "failed to attach replacement socket identity";
    ASSERT_TRUE(sockets.Attach(ingress, "identity-socket", replacement_socket)) << "failed to attach replacement socket identity";
    process(old_socket);
    EXPECT_EQ(ingress.GetResourceStats().associations, 0) << "stale socket datagram crossed into its replacement identity";
    EXPECT_EQ(ingress.GetResourceStats().native_dispatches, 1) << "stale socket datagram crossed into its replacement identity";
    EXPECT_TRUE(sockets.Owns(ingress, "identity-socket", replacement_socket.get())) << "stale socket datagram crossed into its replacement identity";
    process(replacement_socket);
    io.poll();
    io.restart();
    auto* const replacement_session = dispatcher.sessions[1];
    ASSERT_TRUE(replacement_session) << "replacement socket did not create an independent native job";
    EXPECT_NE(replacement_session, old_session) << "replacement socket did not create an independent native job";
    EXPECT_EQ(ingress.GetResourceStats().associations, 1) << "replacement socket did not create an independent native job";
    EXPECT_EQ(dispatcher.dispatches, 2) << "replacement socket did not create an independent native job";
    EXPECT_EQ(dispatcher.packets_read, 2) << "replacement socket did not create an independent native job";
    EXPECT_EQ(ingress.GetResourceStats().native_dispatches, 2) << "replacement socket did not create an independent native job";
    const auto create_other = [&] {
        return other.CreateClientSession(sockets.Get(other, "other-socket"), client_key, io,
            {},
            {::net::ip::address_v4::loopback(), 47124}, owner,
            std::chrono::steady_clock::now(), 0s);
    };
    EXPECT_EQ(budget.GetUsage().associations, 2) << "retired dispatcher ownership bypassed the shared association limit";
    EXPECT_FALSE(create_other()) << "retired dispatcher ownership bypassed the shared association limit";

    replacement_session->Close();
    bool joined = false;
    ::net::co_spawn(io, ObserveJoin(ingress, joined), ::net::detached);
    dispatcher.gate.cancel();
    io.run();
    EXPECT_TRUE(joined) << "old job completion damaged the replacement socket identity";
    EXPECT_EQ(ingress.GetResourceStats().native_dispatches, 0) << "old job completion damaged the replacement socket identity";
    EXPECT_TRUE(sockets.Owns(ingress, "identity-socket", replacement_socket.get())) << "old job completion damaged the replacement socket identity";
    EXPECT_TRUE(replacement_socket->is_open()) << "old job completion damaged the replacement socket identity";
    auto recovered = create_other();
    // Both native jobs completed and released their rows: only `recovered`
    // holds a lease now.
    EXPECT_TRUE(recovered) << "dispatcher completion did not return its association lease";
    EXPECT_EQ(budget.GetUsage().associations, 1) << "dispatcher completion did not return its association lease";
    other.RequestStop();
    ingress.RequestStop();
}

TEST_F(UdpNativeLifecycleTest, UplinkRefreshDelaysNaturalExpiryUntilIdle) {
    io.restart();
    UdpSocketFixtures sockets(io);
    ::app::UdpResourceBudget budget;
    Ingress ingress("native-refresh", std::make_unique<NativeInbound>(), reclaimer, budget, io);
    auto socket = Ingress::MakeSocket(io);
    ::IoErrorCode ec;
    socket->open(::udp::v4(), ec);
    ASSERT_FALSE(ec) << "failed to open UDP refresh test socket";
    socket->bind({::net::ip::address_v4::loopback(), 0}, ec);
    ASSERT_FALSE(ec) << "failed to attach UDP refresh test socket";
    ASSERT_TRUE(sockets.Attach(ingress, "refresh-socket", socket)) << "failed to attach UDP refresh test socket";

    GateDispatcher dispatcher(io);
    DrainNativeJobs drain{io, ingress, dispatcher};
    ::infra::TimeoutsConfig timeouts;
    timeouts.idle = 1;
    auto receiver = MakeReceiver();
    const ::app::DatagramSessionEnvironment environment{
        .timeouts = timeouts, .dispatcher = &dispatcher,
        .admission = &admission, .request_load = &request_load};
    constexpr std::array<uint8_t, 1> packet{0x62};
    auto process_packet = [&]() {
        ingress.ProcessDatagram(::app::UdpDatagramContext{
            .socket = sockets.Find(ingress, socket.get()).get(),
            .client_endpoint = {::net::ip::address_v4::loopback(), 45123},
            .payload = packet,
            .receiver = &receiver,
            .io_context = io,
            .worker_id = 4,
            .environment = environment,
        });
    };
    process_packet();
    io.poll();
    io.restart();
    EXPECT_EQ(dispatcher.dispatches, 1) << "UDP refresh test did not start its native session";
    EXPECT_EQ(dispatcher.packets_read, 1) << "UDP refresh test did not start its native session";
    auto* const session = dispatcher.sessions[0];
    ASSERT_TRUE(session) << "UDP refresh session row is missing";
    EXPECT_EQ(ingress.GetResourceStats().associations, 1) << "UDP refresh session row is missing";

    ::net::steady_timer refresh(io);
    refresh.expires_after(650ms);
    refresh.async_wait([&](::IoErrorCode timer_ec) {
        if (!timer_ec) process_packet();
    });
    io.run_for(1250ms);
    io.restart();
    EXPECT_EQ(ingress.GetResourceStats().associations, 1) << "native uplink failed to refresh its association idle timestamp";
    EXPECT_FALSE(session->Closed()) << "native uplink failed to refresh its association idle timestamp";

    io.run_for(1100ms);
    io.restart();
    EXPECT_EQ(ingress.GetResourceStats().associations, 0) << "refreshed native association did not expire naturally after idleness";
    EXPECT_TRUE(session->Closed()) << "refreshed native association did not expire naturally after idleness";
    ingress.RequestStop();
    bool joined = false;
    ::net::co_spawn(io, ObserveJoin(ingress, joined), ::net::detached);
    dispatcher.gate.cancel();
    io.run();
    EXPECT_TRUE(joined) << "idle-expired native dispatch did not join at actual completion";
    EXPECT_EQ(ingress.GetResourceStats().native_dispatches, 0) << "idle-expired native dispatch did not join at actual completion";
}

TEST_F(UdpNativeLifecycleTest, ClosedSessionReleasesAllocationButRetainsReplayAuthority) {
    using namespace ::app;
    UdpSocketFixtures sockets(io);
    UdpHandoffDirectory directory;
    const auto& policy = ::proxy::Ss2022UdpAssociation::Policy();
    auto configuration = std::make_shared<const ::app::ProtocolSettings>();
    std::weak_ptr<const ::app::ProtocolSettings> configuration_lifetime = configuration;
    ::proxy::InboundDatagramOwner owner;
    constexpr std::array<uint8_t, 32> credential{0x71};
    EXPECT_TRUE(owner.Assign(credential)) << "failed to prepare tombstone credential";
    UdpHandoffIdentity key{
        .socket = nullptr, .client = ClientSessionKey{owner, 9, {}, configuration.get()}};
    UdpResourceBudget budget;
    const ::udp::endpoint endpoint{::net::ip::address_v4::loopback(), 48234};
    Ingress ingress("directory-tombstone", std::make_unique<NativeInbound>(),
                    reclaimer, budget, io);
    auto socket = sockets.Get(ingress, "closed-listener");
    key.socket = socket.get();
    auto record = directory.Claim(key, configuration, policy);
    ASSERT_NE(record, nullptr);
    auto session = ingress.CreateClientSession(socket, key.client, io, {},
    {::net::ip::address_v4::loopback(), 48234},
    owner, std::chrono::steady_clock::now(), 0s, record);
    ASSERT_TRUE(session) << "failed to prepare live directory association";
    ASSERT_TRUE(record) << "failed to prepare live directory association";
    EXPECT_TRUE(record->association->Check(31, 0, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "failed to prepare live directory association";
    record->association->claimed = false;
    ingress.CleanupClientSessions(*socket);
    EXPECT_TRUE(session->Closed()) << "closed association did not retain its outstanding session owner";
    EXPECT_FALSE(record->session.expired()) << "closed association did not retain its outstanding session owner";
    session.reset();
    EXPECT_TRUE(record->session.expired()) << "directory kept a closed association alive";
    EXPECT_EQ(budget.GetUsage().associations, 0) << "directory kept a closed association alive";
    const std::weak_ptr<Ingress::ClientSession> empty_session;
    EXPECT_FALSE(record->session.owner_before(empty_session)) << "replay tombstone retained the closed session allocation";
    EXPECT_FALSE(empty_session.owner_before(record->session)) << "replay tombstone retained the closed session allocation";
    auto previous = ingress.CreateClientSession(socket, key.client, io, {}, endpoint, owner,
    std::chrono::steady_clock::now(), 0s, record);
    auto replacement = ingress.CreateClientSession(socket, key.client, io, {}, endpoint, owner,
    std::chrono::steady_clock::now(), 0s, record);
    ASSERT_TRUE(previous) << "failed to replace a retained session owner";
    ASSERT_TRUE(replacement) << "failed to replace a retained session owner";
    EXPECT_TRUE(previous->Closed()) << "failed to replace a retained session owner";
    previous.reset();
    EXPECT_EQ(record->session.lock(), replacement) << "old session destruction detached its live replacement";
    ingress.CleanupClientSessions(*socket);
    replacement.reset();
    EXPECT_FALSE(record->session.owner_before(empty_session)) << "replacement retained its closed session allocation";
    EXPECT_FALSE(empty_session.owner_before(record->session)) << "replacement retained its closed session allocation";
    const std::weak_ptr<UdpHandoffRecord> tombstone = record;
    record.reset();
    configuration.reset();
    EXPECT_FALSE(tombstone.expired()) << "directory discarded its replay tombstone or settings snapshot";
    EXPECT_FALSE(configuration_lifetime.expired()) << "directory discarded its replay tombstone or settings snapshot";
    auto resumed = directory.Claim(key, configuration_lifetime.lock(), policy);
    ASSERT_TRUE(resumed) << "association closure reopened a protected replay window";
    EXPECT_EQ(resumed, tombstone.lock()) << "association closure reopened a protected replay window";
    EXPECT_FALSE(resumed->association->Check(31, 0, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "association closure reopened a protected replay window";
    EXPECT_FALSE(resumed->association->Check(30, 1, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "association closure reopened a protected replay window";
    EXPECT_TRUE(resumed->association->Check(32, 1, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "association closure reopened a protected replay window";
    EXPECT_FALSE(resumed->association->Check(30, 0, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "association closure reopened a protected replay window";
    EXPECT_TRUE(resumed->association->Check(30, 1, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "association closure reopened a protected replay window";
    resumed->association->claimed = false;
    ingress.RequestStop();
}

TEST_F(UdpNativeLifecycleTest, DirectoryCapacityProtectsUnexpiredAndClaimedTombstones) {
    using namespace ::app;
    UdpHandoffDirectory directory;
    const auto& policy = ::proxy::Ss2022UdpAssociation::Policy();
    auto configuration = std::make_shared<const ::app::ProtocolSettings>();
    ::proxy::InboundDatagramOwner owner;
    constexpr std::array<uint8_t, 32> credential{0x63};
    EXPECT_TRUE(owner.Assign(credential)) << "failed to prepare capacity credential";
    UdpHandoffIdentity key{
        .socket = nullptr, .client = ClientSessionKey{owner, 0, {}, configuration.get()}};
    const ::udp::endpoint endpoint{::net::ip::address_v4::loopback(), 48234};
    std::shared_ptr<UdpHandoffRecord> first;
    for (size_t i = 0; i < policy.capacity; ++i) {
        key.client.session_id = i;
        auto record = directory.Claim(key, configuration, policy);
        ASSERT_TRUE(record) << "directory rejected a session before reaching capacity";
        EXPECT_TRUE(record->association->Check(11, 0, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "directory rejected a session before reaching capacity";
        record->association->claimed = false;
        if (i == 0) first = std::move(record);
    }
    key.client.session_id = policy.capacity;
    EXPECT_FALSE(directory.Claim(key, configuration, policy)) << "full directory evicted an unexpired closed-session replay tombstone";
    auto protected_key = key;
    protected_key.client.session_id = 0;
    auto protected_record = directory.Claim(protected_key, configuration, policy);
    ASSERT_EQ(protected_record, first) << "capacity rejection lost an existing session or its replay history";
    EXPECT_FALSE(protected_record->association->Check(11, 0, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "capacity rejection lost an existing session or its replay history";
    const auto expired = std::chrono::steady_clock::now() -
        policy.retention - 1s;
    EXPECT_TRUE(first->association->Check(12, 0, endpoint, ::proxy::InboundDatagramCheck::Commit, expired)) << "failed to commit an expired protocol retention deadline";
    EXPECT_FALSE(directory.Claim(key, configuration, policy)) << "directory reclaimed a still-claimed expired tombstone";
    first->association->claimed = false;
    std::shared_ptr<UdpHandoffRecord> replacement;
    for (size_t attempts = 0; !replacement && attempts <= policy.capacity / 64; ++attempts)
        replacement = directory.Claim(key, configuration, policy);
    ASSERT_TRUE(replacement) << "directory did not reclaim an expired unclaimed tombstone";
    EXPECT_NE(replacement, first) << "directory did not reclaim an expired unclaimed tombstone";
    EXPECT_TRUE(replacement->association->Check(11, 0, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "directory did not reclaim an expired unclaimed tombstone";
    replacement->association->claimed = false;
    EXPECT_FALSE(directory.Claim(protected_key, configuration, policy)) << "directory exceeded capacity after reclaiming one expired tombstone";
}

TEST(UdpHandoffDirectory, ClaimsAreExclusiveAndRetainCommittedReplay) {
    using namespace ::app;
    UdpHandoffDirectory directory;
    const auto& policy = ::proxy::Ss2022UdpAssociation::Policy();
    auto configuration = std::make_shared<const ::app::ProtocolSettings>();
    auto other_configuration = std::make_shared<const ::app::ProtocolSettings>();
    UdpSocketState listener_state, other_listener_state;
    ::proxy::InboundDatagramOwner owner;
    std::array<uint8_t, 32> credential{};
    for (size_t i = 0; i < credential.size(); ++i)
        credential[i] = static_cast<uint8_t>(i + 1);
    EXPECT_TRUE(owner.Assign(credential)) << "failed to prepare directory credential";
    UdpHandoffIdentity key{
        .socket = &listener_state,
        .client = ClientSessionKey{owner, 0x00123456789abcdeULL, {}, configuration.get()}};
    const ::udp::endpoint endpoint{::net::ip::address_v4::loopback(), 48234};
    auto record = directory.Claim(key, configuration, policy);
    ASSERT_TRUE(record) << "directory allowed duplicate ownership claims";
    EXPECT_TRUE(record->association->claimed) << "directory allowed duplicate ownership claims";
    EXPECT_FALSE(directory.Claim(key, configuration, policy)) << "directory allowed duplicate ownership claims";
    EXPECT_TRUE(record->association->Check(7, 0, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "directory allowed duplicate ownership claims";
    record->association->claimed = false;
    auto reclaimed = directory.Claim(key, configuration, policy);
    ASSERT_EQ(reclaimed, record) << "directory claim lost unique ownership or committed replay";
    EXPECT_FALSE(reclaimed->association->Check(7, 0, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "directory claim lost unique ownership or committed replay";
    EXPECT_FALSE(directory.Claim(key, configuration, policy)) << "directory claim lost unique ownership or committed replay";
    record->association->claimed = false;
}

class UdpHandoffNamespaceTest : public ::testing::TestWithParam<int> {};

TEST_P(UdpHandoffNamespaceTest, DistinctAuthenticatedNamespacesKeepIndependentReplay) {
    using namespace ::app;
    UdpHandoffDirectory directory;
    const auto& policy = ::proxy::Ss2022UdpAssociation::Policy();
    auto configuration = std::make_shared<const ::app::ProtocolSettings>();
    auto other_configuration = std::make_shared<const ::app::ProtocolSettings>();
    UdpSocketState listener_state, other_listener_state;
    ::proxy::InboundDatagramOwner owner;
    std::array<uint8_t, 32> credential{};
    for (size_t i = 0; i < credential.size(); ++i)
        credential[i] = static_cast<uint8_t>(i + 1);
    EXPECT_TRUE(owner.Assign(credential)) << "failed to prepare directory credential";
    UdpHandoffIdentity key{
        .socket = &listener_state,
        .client = ClientSessionKey{owner, 0x00123456789abcdeULL, {}, configuration.get()}};
    const ::udp::endpoint endpoint{::net::ip::address_v4::loopback(), 48234};
    auto record = directory.Claim(key, configuration, policy);
    ASSERT_TRUE(record) << "directory allowed duplicate ownership claims";
    EXPECT_TRUE(record->association->claimed) << "directory allowed duplicate ownership claims";
    EXPECT_FALSE(directory.Claim(key, configuration, policy)) << "directory allowed duplicate ownership claims";
    EXPECT_TRUE(record->association->Check(7, 0, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "directory allowed duplicate ownership claims";
    record->association->claimed = false;
    auto reclaimed = directory.Claim(key, configuration, policy);
    ASSERT_EQ(reclaimed, record) << "directory claim lost unique ownership or committed replay";
    EXPECT_FALSE(reclaimed->association->Check(7, 0, endpoint, ::proxy::InboundDatagramCheck::Commit)) << "directory claim lost unique ownership or committed replay";
    EXPECT_FALSE(directory.Claim(key, configuration, policy)) << "directory claim lost unique ownership or committed replay";
    record->association->claimed = false;

    auto distinct = key;
    auto snapshot = configuration;
    const int dimension = GetParam();
    if (dimension < 32) distinct.client.owner.bytes[dimension] ^= 0x80;
    else if (dimension == 32) distinct.client.owner.size = 16;
    else if (dimension == 33) distinct.client.session_id = *key.client.session_id + 1;
    else if (dimension == 34) distinct.socket = &other_listener_state;
    else {
        distinct.client.configuration = other_configuration.get();
        snapshot = other_configuration;
    }
    auto isolated = directory.Claim(distinct, snapshot, policy);
    ASSERT_NE(isolated, nullptr);
    EXPECT_NE(isolated, record);
    EXPECT_TRUE(isolated->association->Check(7, 1, endpoint, ::proxy::InboundDatagramCheck::Commit));
    EXPECT_FALSE(directory.Claim(distinct, snapshot, policy));
    isolated->association->claimed = false;
    auto repeated = directory.Claim(distinct, snapshot, policy);
    ASSERT_EQ(repeated, isolated);
    EXPECT_FALSE(repeated->association->Check(7, 1, endpoint, ::proxy::InboundDatagramCheck::Commit));
    EXPECT_TRUE(repeated->association->Check(6, 1, endpoint, ::proxy::InboundDatagramCheck::Commit));
    EXPECT_FALSE(repeated->association->Check(5, 0, endpoint, ::proxy::InboundDatagramCheck::Commit));
    repeated->association->claimed = false;
}

INSTANTIATE_TEST_SUITE_P(IdentityDimensions, UdpHandoffNamespaceTest, ::testing::Range(0, 36));

class UdpLocalProtocolTest : public ::testing::TestWithParam<const char*> {
protected:
    ::net::io_context io;
    WorkerCoordinatorFixture coordinator{io};
    std::shared_ptr<::app::ConnectionLimiter> limiter =
        ::app::ConnectionLimiter::Acquire({}, coordinator.Get());
    ::common::UserOnlineTracker tracker{*coordinator.Get()};
    ::app::StatsShard stats{};
    const ::app::AdmissionEnvironment admission{
        *coordinator.Get(), *limiter, tracker, stats};
    ::app::ProtocolSettings configuration{}, other_configuration{};
    const ::udp::endpoint first{::net::ip::address_v4::loopback(), 48234};
    const ::udp::endpoint second{::net::ip::address_v4::loopback(), 48235};
    const ::common::TargetAddress target{"127.0.0.1", 53};
    const std::array<uint8_t, 3> payload{1, 2, 3};
    ::proxy::SsCipherInfo cipher{};
    ::proxy::KeyBytes key;
    ::proxy::Ss2022UdpSessionState encoder;
    std::unique_ptr<::proxy::SsInboundHandler> handler;
    ::proxy::InboundDatagramAssociationIndex index;
    ::proxy::InboundDatagramRequest request{
        .tag = "protocol-association", .payload = {}, .associations = &index,
        .configuration = &configuration, .worker_id = 0, .client_endpoint = first};
    std::vector<uint8_t> packet;

    void SetUp() override {
        coordinator.Get()->RegisterWorker();
        const auto parsed = ::proxy::ParseCipherMethod(GetParam());
        ASSERT_TRUE(parsed);
        cipher = *parsed;
        const std::array<uint8_t, 32> credential{0x61, 0x72};
        ASSERT_TRUE(key.assign(std::span(credential).first(cipher.key_size)));
        ::app::PreparedShadowsocksUser user;
        ASSERT_TRUE(user.derived_key.assign(key.span()));
        user.profile.user_id = 41;
        ::app::UserSet users = ::app::PreparedShadowsocksUsers{std::move(user)};
        ::app::UserStore::InstallWorkerView(::app::UserStore::PrepareWorkerView(
            ::app::UserStore::PrepareUsers("protocol-association", users)));
        handler = std::make_unique<::proxy::SsInboundHandler>(admission, cipher);
        ASSERT_TRUE(::proxy::Init2022UdpSessionState(encoder, cipher, key));
    }
    void TearDown() override {
        handler.reset();
        ::app::UserStore::ClearWorkerView();
    }
    void Encode(uint64_t id) {
        encoder.next_packet_id = id;
        const auto size = ::proxy::Encode2022UdpRequestPacketTo(
            target, payload.data(), payload.size(), encoder, {}, nullptr, 0);
        if (size == 0) throw std::runtime_error("failed to size protocol packet");
        packet.resize(size);
        if (::proxy::Encode2022UdpRequestPacketTo(target, payload.data(), payload.size(), encoder, {},
                packet.data(), packet.size()) != size)
            throw std::runtime_error("failed to encode protocol packet");
        request.payload = packet;
    }
};

TEST_P(UdpLocalProtocolTest, ColdAndWarmPacketsShareReplayAuthority) {
    Encode(0);
    auto decoded = handler->Process(request);
    ASSERT_TRUE(decoded);
    ASSERT_EQ(decoded->association_policy, &::proxy::Ss2022UdpAssociation::Policy());
    ASSERT_TRUE(decoded->session_id);
    ASSERT_TRUE(decoded->packet_id);
    auto association = decoded->association_policy->create();
    ASSERT_NE(association, nullptr);
    ASSERT_TRUE(association->Check(*decoded->packet_id, 0, first, ::proxy::InboundDatagramCheck::Commit));
    index.emplace(::proxy::InboundDatagramAssociationKey{
        decoded->session_owner, *decoded->session_id, &configuration}, association.get());
    association->claimed = false;
    EXPECT_FALSE(handler->Process(request));
    Encode(2);
    auto accepted = handler->Process(request);
    ASSERT_TRUE(accepted);
    EXPECT_EQ(accepted->committed_association, association.get());
    EXPECT_TRUE(accepted->target.SameEndpoint(target));
    EXPECT_EQ(accepted->payload.byte_size(), payload.size());
    EXPECT_FALSE(handler->Process(request));
}

TEST_P(UdpLocalProtocolTest, ReorderedPacketsCannotStealResponsePath) {
    Encode(0);
    auto decoded = handler->Process(request);
    ASSERT_TRUE(decoded);
    ASSERT_EQ(decoded->association_policy, &::proxy::Ss2022UdpAssociation::Policy());
    ASSERT_TRUE(decoded->session_id);
    ASSERT_TRUE(decoded->packet_id);
    auto association = decoded->association_policy->create();
    ASSERT_NE(association, nullptr);
    ASSERT_TRUE(association->Check(*decoded->packet_id, 0, first, ::proxy::InboundDatagramCheck::Commit));
    index.emplace(::proxy::InboundDatagramAssociationKey{
        decoded->session_owner, *decoded->session_id, &configuration}, association.get());
    association->claimed = false;
    Encode(2);
    ASSERT_TRUE(handler->Process(request));
    Encode(1);
    request.client_endpoint = second;
    EXPECT_FALSE(handler->Process(request));
    request.client_endpoint = first;
    EXPECT_TRUE(handler->Process(request));
}

TEST_P(UdpLocalProtocolTest, ClaimedStateWaitsForExclusiveControlCommit) {
    Encode(0);
    auto decoded = handler->Process(request);
    ASSERT_TRUE(decoded);
    ASSERT_EQ(decoded->association_policy, &::proxy::Ss2022UdpAssociation::Policy());
    ASSERT_TRUE(decoded->session_id);
    ASSERT_TRUE(decoded->packet_id);
    auto association = decoded->association_policy->create();
    ASSERT_NE(association, nullptr);
    ASSERT_TRUE(association->Check(*decoded->packet_id, 0, first, ::proxy::InboundDatagramCheck::Commit));
    index.emplace(::proxy::InboundDatagramAssociationKey{
        decoded->session_owner, *decoded->session_id, &configuration}, association.get());
    association->claimed = false;
    Encode(3);
    association->claimed = true;
    auto pending = handler->Process(request);
    ASSERT_TRUE(pending);
    EXPECT_EQ(pending->committed_association, nullptr);
    EXPECT_TRUE(association->Check(3, 0, first, ::proxy::InboundDatagramCheck::Commit));
    association->claimed = false;
    EXPECT_FALSE(handler->Process(request));
}

TEST_P(UdpLocalProtocolTest, ConfigurationNamespacesDoNotShareLocalState) {
    Encode(0);
    auto decoded = handler->Process(request);
    ASSERT_TRUE(decoded);
    ASSERT_EQ(decoded->association_policy, &::proxy::Ss2022UdpAssociation::Policy());
    ASSERT_TRUE(decoded->session_id);
    ASSERT_TRUE(decoded->packet_id);
    auto association = decoded->association_policy->create();
    ASSERT_NE(association, nullptr);
    ASSERT_TRUE(association->Check(*decoded->packet_id, 0, first, ::proxy::InboundDatagramCheck::Commit));
    index.emplace(::proxy::InboundDatagramAssociationKey{
        decoded->session_owner, *decoded->session_id, &configuration}, association.get());
    association->claimed = false;
    Encode(4);
    request.configuration = &other_configuration;
    auto other = handler->Process(request);
    ASSERT_TRUE(other);
    EXPECT_EQ(other->committed_association, nullptr);
}

TEST_P(UdpLocalProtocolTest, InvalidCiphertextCannotPoisonReplayState) {
    Encode(0);
    auto decoded = handler->Process(request);
    ASSERT_TRUE(decoded);
    ASSERT_EQ(decoded->association_policy, &::proxy::Ss2022UdpAssociation::Policy());
    ASSERT_TRUE(decoded->session_id);
    ASSERT_TRUE(decoded->packet_id);
    auto association = decoded->association_policy->create();
    ASSERT_NE(association, nullptr);
    ASSERT_TRUE(association->Check(*decoded->packet_id, 0, first, ::proxy::InboundDatagramCheck::Commit));
    index.emplace(::proxy::InboundDatagramAssociationKey{
        decoded->session_owner, *decoded->session_id, &configuration}, association.get());
    association->claimed = false;
    Encode(4);
    packet.back() ^= 1;
    EXPECT_FALSE(handler->Process(request));
    packet.back() ^= 1;
    EXPECT_TRUE(handler->Process(request));
}

INSTANTIATE_TEST_SUITE_P(Ciphers, UdpLocalProtocolTest, ::testing::Values(
    "2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305"));

class NativeJobsTest : public UdpNativeLifecycleTest {
protected:
    UdpSocketFixtures sockets{io};
    ::app::UdpResourceBudget budget;
    Ingress ingress{"native-test", std::make_unique<NativeInbound>(), reclaimer, budget, io};
    GateDispatcher dispatcher{io};
    Ingress::SocketPtr socket;
    ::infra::TimeoutsConfig timeouts;
    ::app::ReceiverSettings receiver = MakeReceiver();
    const ::app::DatagramSessionEnvironment environment{
        .timeouts = timeouts, .dispatcher = &dispatcher,
        .admission = &admission, .request_load = &request_load};
    const std::array<uint8_t, 1> datagram{0x62};

    void SetUp() override {
        socket = Ingress::MakeSocket(io);
        ::IoErrorCode ec;
        socket->open(::udp::v4(), ec);
        ASSERT_FALSE(ec);
        socket->bind({::net::ip::address_v4::loopback(), 0}, ec);
        ASSERT_FALSE(ec);
        ASSERT_TRUE(sockets.Attach(ingress, "native-socket", socket));
        dispatcher.ingress = &ingress;
        dispatcher.reenter_stop = true;
    ingress.ProcessDatagram(::app::UdpDatagramContext{
        .socket = sockets.Find(ingress, socket.get()).get(),
        .client_endpoint = {::net::ip::address_v4::loopback(), 43123},
        .payload = datagram,
        .receiver = &receiver,
        .io_context = io,
        .worker_id = 3,
        .environment = environment,
    });
    constexpr std::array<uint8_t, 1> second_datagram{0x63};
    ingress.ProcessDatagram(::app::UdpDatagramContext{
        .socket = sockets.Find(ingress, socket.get()).get(),
        .client_endpoint = {::net::ip::address_v4::loopback(), 43124},
        .payload = second_datagram,
        .receiver = &receiver,
        .io_context = io,
        .worker_id = 3,
        .environment = environment,
    });
    receiver.inbound_tag.assign(256, 'x');
    receiver.inbound_tags.front().assign(256, 'y');
    receiver.protocol.assign(256, 'z');
    std::get<::routing::ForceOutbound>(receiver.dispatch_policy.outbound)
        .outbound_tag.assign(256, 'r');

        io.poll();
        io.restart();
    }
    void TearDown() override {
        ingress.RequestStop();
        dispatcher.gate.cancel();
        io.restart();
        bool joined = false;
        ::net::co_spawn(io, ObserveJoin(ingress, joined), ::net::detached);
        io.run();
        EXPECT_TRUE(joined);
    }
};

TEST_F(NativeJobsTest, DispatchOwnsReceiverMetadataAndFirstPackets) {
    EXPECT_EQ(dispatcher.dispatches, 2u);
    EXPECT_EQ(dispatcher.packets_read, 2u);
    EXPECT_EQ(ingress.GetResourceStats().associations, 2u);
    EXPECT_EQ(ingress.GetResourceStats().native_dispatches, 2u);
    EXPECT_EQ(request_load.ActiveConnections(), 2u);
}

TEST_F(NativeJobsTest, HandlerReplacementPreservesActiveNativeJobs) {
    EXPECT_TRUE(ingress.ReplaceHandler(std::make_unique<NativeInbound>())) << "same-socket handler replacement was rejected";

    io.poll();
    io.restart();
    EXPECT_EQ(dispatcher.dispatches, 2) << "native UDP requests did not dispatch their first packets exactly once";
    EXPECT_EQ(dispatcher.packets_read, 2) << "native UDP requests did not dispatch their first packets exactly once";
    auto* const session_a = dispatcher.sessions[0];
    auto* const session_b = dispatcher.sessions[1];
    // A datagram decoded by the replacement handler must reach the existing
    // row's queue instead of starting a new job.
    ingress.ProcessDatagram(::app::UdpDatagramContext{
        .socket = sockets.Find(ingress, socket.get()).get(),
        .client_endpoint = {::net::ip::address_v4::loopback(), 43123},
        .payload = datagram,
        .receiver = &receiver,
        .io_context = io,
        .worker_id = 3,
        .environment = environment,
    });
    const auto replaced = ingress.GetResourceStats();
    ASSERT_TRUE(session_a) << "same-socket handler replacement disturbed active native jobs";
    ASSERT_TRUE(session_b) << "same-socket handler replacement disturbed active native jobs";
    EXPECT_NE(session_a, session_b) << "same-socket handler replacement disturbed active native jobs";
    EXPECT_FALSE(session_a->Closed()) << "same-socket handler replacement disturbed active native jobs";
    EXPECT_FALSE(session_b->Closed()) << "same-socket handler replacement disturbed active native jobs";
    EXPECT_EQ(replaced.associations, 2) << "same-socket handler replacement disturbed active native jobs";
    EXPECT_EQ(replaced.closed_associations, 0) << "same-socket handler replacement disturbed active native jobs";
    EXPECT_EQ(replaced.native_dispatches, 2) << "same-socket handler replacement disturbed active native jobs";
    EXPECT_EQ(replaced.input_datagrams, 1) << "same-socket handler replacement disturbed active native jobs";
    EXPECT_EQ(dispatcher.dispatches, 2) << "same-socket handler replacement disturbed active native jobs";
}

class NativeJoinTest : public NativeJobsTest, public ::testing::WithParamInterface<bool> {};

TEST_P(NativeJoinTest, CancellationDoesNotCompleteJobsBeforeDispatchReturns) {
    ingress.CloseSocket(*sockets.Get(ingress, "native-socket"));
    auto stats_after_close = ingress.GetResourceStats();
    EXPECT_EQ(dispatcher.cancellations, 2) << "socket batch reentry confused row removal with native job completion";
    EXPECT_EQ(stats_after_close.associations, 0) << "socket batch reentry confused row removal with native job completion";
    EXPECT_EQ(stats_after_close.native_dispatches, 2) << "socket batch reentry confused row removal with native job completion";
    EXPECT_EQ(request_load.ActiveConnections(), 2u);


    bool joined = false;
    bool parent_cancelled = false;
    bool join_throw_setting = true;
    ::net::cancellation_signal parent_signal;
    if (GetParam()) {
        ::net::co_spawn(io, ObserveCancelledJoin(ingress, joined, parent_cancelled,
            join_throw_setting, parent_signal),
            ::net::bind_cancellation_slot(parent_signal.slot(), ::net::detached));
    } else {
        ::net::co_spawn(io, ObserveJoin(ingress, joined), ::net::detached);
    }
    io.run_for(20ms);
    io.restart();
    EXPECT_FALSE(joined) << "native join returned before actual dispatcher completion";
    EXPECT_EQ(ingress.GetResourceStats().native_dispatches, 2) << "native join returned before actual dispatcher completion";
    ingress.RequestStop();
    ingress.RequestStop();
    EXPECT_EQ(ingress.GetResourceStats().native_dispatches, 2) << "native stop treated cancellation as actual job completion";
    dispatcher.gate.cancel();
    io.run();

    EXPECT_TRUE(joined);
    EXPECT_EQ(ingress.GetResourceStats().native_dispatches, 0u);
    EXPECT_EQ(request_load.ActiveConnections(), 0u);
    if (GetParam()) {
        EXPECT_TRUE(parent_cancelled);
        EXPECT_FALSE(join_throw_setting);
    }
}

INSTANTIATE_TEST_SUITE_P(ParentCancellation, NativeJoinTest, ::testing::Bool());

} // namespace

struct SessionAllocationCounts {
    size_t allocations = 0;
    size_t live_bytes = 0;
    size_t peak_bytes = 0;
};

template <typename T>
struct SessionAllocationCounter {
    using value_type = T;
    SessionAllocationCounts* counts;
    explicit SessionAllocationCounter(SessionAllocationCounts& counts) : counts(&counts) {}
    template <typename U>
    SessionAllocationCounter(const SessionAllocationCounter<U>& other) : counts(other.counts) {}
    T* allocate(size_t n) {
        auto* result = std::allocator<T>{}.allocate(n);
        ++counts->allocations;
        counts->live_bytes += n * sizeof(T);
        counts->peak_bytes = std::max(counts->peak_bytes, counts->live_bytes);
        return result;
    }
    void deallocate(T* value, size_t n) {
        counts->live_bytes -= n * sizeof(T);
        std::allocator<T>{}.deallocate(value, n);
    }
    template <typename U>
    bool operator==(const SessionAllocationCounter<U>& other) const noexcept {
        return counts == other.counts;
    }
};

class ReplayTombstoneAllocationTest : public ::testing::TestWithParam<bool> {};

TEST_P(ReplayTombstoneAllocationTest, RetainedRecordsDoNotRetainBoundSessionAllocations) {
    constexpr size_t count = 4096;
    const bool bound_record = GetParam();
        ::net::io_context io;
        ::app::UdpResourceBudget budget;
        SessionAllocationCounts counts;
        std::vector<std::shared_ptr<::app::UdpHandoffRecord>> records;
        records.reserve(count);
        for (size_t index = 0; index != count; ++index) {
            auto record = std::make_shared<::app::UdpHandoffRecord>(
                ::proxy::Ss2022UdpAssociation::Policy());
            auto session = std::allocate_shared<Ingress::ClientSession>(
                SessionAllocationCounter<Ingress::ClientSession>{counts}, io,
                Ingress::ReplyRoute{}, ::udp::endpoint{}, ::proxy::InboundDatagramOwner{},
                budget, budget.AcquireAssociation(), bound_record ? record : nullptr);
            record->session = session;
            session.reset();
            records.push_back(std::move(record));
        }
        const auto retained_bytes = counts.live_bytes;
        EXPECT_EQ(counts.allocations, count);
        EXPECT_EQ(budget.GetUsage().associations, 0u);
        if (bound_record) EXPECT_EQ(retained_bytes, 0u);
        else EXPECT_GT(retained_bytes, 0u);
        records.clear();
        EXPECT_EQ(counts.live_bytes, 0u);
}

INSTANTIATE_TEST_SUITE_P(RecordBinding, ReplayTombstoneAllocationTest, ::testing::Bool());
