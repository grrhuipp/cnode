#include <stdexcept>
#include <gtest/gtest.h>

#include "allocation_hook.hpp"
#include "app/udp_ingress.hpp"
#include "udp_ingress_fixture.hpp"
#include "worker_coordinator_fixture.hpp"
#include "app/relay.hpp"
#include "app/inbound_handler.hpp"
#include "app/request_load.hpp"
#include "app/stats.hpp"
#include "common/user_online_tracker.hpp"
#include "routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "proxy/shadowsocks/ss_udp.hpp"
#include "transport/async_stream.hpp"
#include "transport/datagram_socket.hpp"
#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <tuple>
#include <vector>

namespace {
thread_local bool reject_next_new = false;

void RejectArmedNew(std::size_t) {
    if (!reject_next_new) return;
    reject_next_new = false;
    throw std::bad_alloc();
}
}  // namespace

constinit allocation_hook::Hooks allocation_hook::hooks{.before_new = RejectArmedNew};

namespace {

// Authenticated identity the test handler assigns to the next decoded datagram.
struct DatagramScript {
    ::proxy::InboundDatagramOwner owner;
    uint64_t session_id = 0;
    ::common::TargetAddress target;
    // One-shot: rejects the first PMR allocation after decoding completes, so
    // the fault lands in the ingress delivery path rather than the decoder.
    bool fail_next_allocation = false;
};

class DummyDatagramHandler final : public ::proxy::Inbound {
public:
    explicit DummyDatagramHandler(DatagramScript* script = nullptr)
        : script_(script) {}
    ::net::awaitable<::app::RelayResult> Process(
        std::unique_ptr<::transport::AsyncStream>,
        ::routing::Dispatcher&,
        const ::app::ReceiverSettings&,
        ::net::io_context&,
        ::common::Context&,
        const ::infra::TimeoutsConfig&,
        uint32_t) override {
        co_return ::app::RelayResult{};
    }

    tl::expected<
        ::proxy::InboundDatagramResult,
        ::common::ErrorCode> Process(
        const ::proxy::InboundDatagramRequest& request) override {
        if (!script_) return tl::unexpected(::common::ErrorCode::PROTOCOL_AUTH_FAILED);
        ::proxy::InboundDatagramResult result;
        result.user = &profile_;
        result.session_owner = script_->owner;
        result.session_id = script_->session_id;
        result.target = script_->target;
        if (!result.payload.AppendSpan(request.payload))
            return tl::unexpected(::common::ErrorCode::RESOURCE_EXHAUSTED);
#ifdef CNODE_TEST_ALLOCATOR
        if (script_->fail_next_allocation) {
            script_->fail_next_allocation = false;
            ::common::reject_next_process_allocation = true;
        }
#endif
        return result;
    }

private:
    DatagramScript* script_ = nullptr;
    ::common::UserProfile profile_;
};

class CountingUdpResponseContext final : public ::proxy::InboundDatagramResponse {
public:
    ::common::MultiBuffer Encode(::proxy::UDPPacketView packet) override {
        if (fail) throw 9;
        ++calls;
        last_size = packet.data.size();
        last_target = packet.target;
        ::common::MultiBuffer encoded;
        if (!encoded.AppendSpan(packet.data)) throw std::bad_alloc();
        return encoded;
    }

    size_t calls = 0;
    size_t last_size = 0;
    ::common::TargetAddress last_target;
    bool fail = false;
};

struct UdpReplyPeer final {
    explicit UdpReplyPeer(::net::io_context& io)
        : socket(io, ::udp::endpoint(::net::ip::address_v4::loopback(), 0)) {
        socket.non_blocking(true);
    }
    void Read() {
        std::vector<uint8_t> packet(65536);
        ::udp::endpoint sender;
        ::IoErrorCode ec;
        const auto size = socket.receive_from(::net::buffer(packet), sender, 0, ec);
        if (ec) return;
        packet.resize(size);
        bytes = std::move(packet);
        ++calls;
    }
    ::udp::socket socket;
    size_t calls = 0;
    std::vector<uint8_t> bytes;
};

// Uplink fixtures deliver only to pre-created rows; starting a job is a failure.
class NoDispatch final : public ::routing::Dispatcher {
public:
    ::net::awaitable<::app::RelayResult> Dispatch(
        ::net::io_context&, const ::routing::DispatchPolicy&,
        std::unique_ptr<::transport::AsyncStream>, ::transport::Link,
        ::common::InitialPayload, ::common::Context&, ::app::StatsShard&,
        const ::infra::TimeoutsConfig&) override {
        ADD_FAILURE() << "uplink fixture started an unexpected native job";
        co_return ::app::RelayResult{};
    }
};


// Fault hooks are thread-local and must not escape an assertion or exception.
struct AllocationFaultScope {
#ifdef CNODE_TEST_ALLOCATOR
    const bool new_reject = reject_next_new;
    const bool reject = ::common::reject_next_process_allocation;
    const size_t rejected = ::common::rejected_process_allocations;
    const std::ptrdiff_t budget = ::common::process_allocation_budget;
    void Reset() noexcept {
        reject_next_new = new_reject;
        ::common::reject_next_process_allocation = reject;
        ::common::rejected_process_allocations = rejected;
        ::common::process_allocation_budget = budget;
    }
    ~AllocationFaultScope() { Reset(); }
#else
    void Reset() noexcept {}
#endif
};

class UdpSocketOwnerTest : public ::testing::Test {
protected:
    ::common::TargetAddress callback_source{::net::ip::address_v4::loopback(), 5353};
    std::array<uint8_t, 1> callback_payload{0x5a};
    ::net::io_context io_context;
    WorkerCoordinatorFixture coordinator{io_context};
    std::shared_ptr<::app::ConnectionLimiter> limiter =
        ::app::ConnectionLimiter::Acquire({}, coordinator.Get());
    ::common::UserOnlineTracker online_users{*coordinator.Get()};
    UdpSocketFixtures sockets{io_context};
    UdpReplyPeer large_sink{io_context}, moved_sink{io_context};
    ::app::UdpResourceBudget udp_budget;
    ::IoErrorCode ec;
    const ::udp::endpoint reply_endpoint_a = large_sink.socket.local_endpoint();
    const ::udp::endpoint reply_endpoint_b = moved_sink.socket.local_endpoint();
    ::proxy::InboundDatagramOwner default_owner;
    ::transport::TimeoutScheduler& udp_scheduler = ::transport::TimeoutScheduler::ForIoContext(io_context);
    ::app::UdpAssociationReclaimer udp_reclaimer{
        udp_scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); }};
    DatagramScript uplink_script;
    ::app::UdpIngress worker{"test-inbound",
        std::make_unique<DummyDatagramHandler>(&uplink_script), udp_reclaimer, udp_budget, io_context};
    ::app::UdpIngress::SocketStatePtr callback_state;
    NoDispatch uplink_dispatcher;
    ::app::StatsShard uplink_stats;
    const ::app::AdmissionEnvironment admission{
        *coordinator.Get(), *limiter, online_users, uplink_stats};
    ::app::RequestLoadState request_load{1024, 0};
    const ::app::DatagramSessionEnvironment uplink_environment{
        .timeouts = {}, .dispatcher = &uplink_dispatcher,
        .admission = &admission, .request_load = &request_load};
    const ::app::ReceiverSettings uplink_receiver{
        .inbound_tag = {}, .inbound_tags = {}, .protocol = {}, .accounting_key = {},
        .stream_settings = {}, .dispatch_policy = {
            .sniffing = {}, .outbound = ::routing::ForceOutbound{"direct"}},
        .proxy_protocol = ::transport::ProxyProtocolMode::Auto};
    AllocationFaultScope fault_scope;

    void SetUp() override {
        coordinator.Get()->RegisterWorker();
        const std::array<uint8_t, 1> bytes{1};
        ASSERT_TRUE(default_owner.Assign(bytes));
        uplink_script.target = callback_source;
        callback_state = worker.AttachSocket(std::make_shared<::udp::socket>(io_context, ::udp::v4()));
        ASSERT_NE(callback_state, nullptr);
    }
    void TearDown() override {
        fault_scope.Reset();
        uplink_script.fail_next_allocation = false;
        worker.RequestStop();
        io_context.restart();
        bool joined = false;
        ::net::co_spawn(io_context, worker.AsyncJoin(), [&](std::exception_ptr failure) {
            EXPECT_FALSE(failure);
            joined = true;
        });
        io_context.run();
        EXPECT_TRUE(joined);
    }
    ::common::MultiBuffer make_tiny_payload() {
        ::common::MultiBuffer payload;
        const std::array<uint8_t, 1> bytes{0x7a};
        if (!payload.AppendSpan(bytes)) throw std::bad_alloc();
        return payload;
    }
    ::app::UdpIngress::SocketPtr attach_uplink_socket(std::string_view key) {
        auto socket = sockets.Attach(worker, key, ::app::UdpIngress::MakeSocket(io_context));
        if (!socket) throw std::runtime_error("failed to attach UDP fixture socket");
        return socket;
    }
    ::app::UdpIngress::SocketPtr AttachStableSocket() {
        auto socket = ::app::UdpIngress::MakeSocket(io_context);
        socket->open(::udp::v4());
        socket->bind({::net::ip::address_v4::loopback(), 0});
        auto attached = sockets.Attach(worker, "stable-socket", std::move(socket));
        if (!attached) throw std::runtime_error("failed to attach stable fixture socket");
        return attached;
    }
    void deliver_uplink(std::string_view,
                        const ::app::UdpIngress::SocketPtr& socket,
                        const ::proxy::InboundDatagramOwner& owner, uint64_t id, uint8_t marker) {
        uplink_script.owner = owner;
        uplink_script.session_id = id;
        const std::array<uint8_t, 1> packet{marker};
        worker.ProcessDatagram(::app::UdpDatagramContext{
            .socket = sockets.Find(worker, socket.get()).get(), .client_endpoint = reply_endpoint_b,
            .payload = packet, .receiver = &uplink_receiver, .io_context = io_context,
            .worker_id = 0, .environment = uplink_environment});
    }
    int read_marker(::app::UdpIngress::ClientSession& session) {
        struct ReadResult { int marker = -1; bool completed = false; };
        auto result = std::make_shared<ReadResult>();
        ::net::co_spawn(io_context, session.ReadMultiBuffer(),
            [result](std::exception_ptr error, ::common::MultiBuffer payload) {
                result->completed = true;
                if (error || payload.byte_size() != 1) return;
                const auto bytes = payload.FrontSpan();
                if (bytes.size() == 1) result->marker = bytes[0];
            });
        io_context.poll();
        io_context.restart();
        if (!result->completed) {
            session.Close();
            io_context.poll();
            io_context.restart();
        }
        return result->marker;
    }
};

TEST(UdpResourceBudget, MovedReservationsReleaseOnlyTheirOriginBudget) {
    using Budget = ::app::UdpResourceBudget;
    constexpr size_t kMigrating = 128;
    Budget source({
        .associations = kMigrating + 1, .datagrams = kMigrating + 1,
        .payload_capacity = (kMigrating + 1) * ::common::Buffer::kSize});
    Budget target({
        .associations = 1, .datagrams = 1,
        .payload_capacity = ::common::Buffer::kSize});
    ::common::MultiBuffer payload;
    const std::array<uint8_t, 1> bytes{0x73};
    ASSERT_TRUE(payload.AppendSpan(bytes));
    std::array<Budget::AssociationLease, kMigrating> associations;
    std::array<Budget::PayloadReservation, kMigrating> reservations;
    for (size_t i = 0; i < kMigrating; ++i) {
        associations[i] = source.AcquireAssociation();
        reservations[i] = source.ReservePayload(payload);
        EXPECT_TRUE(associations[i]) << "failed to reserve migration source resources";
        EXPECT_TRUE(reservations[i]) << "failed to reserve migration source resources";
    }
    {
        auto last_association = source.AcquireAssociation();
        auto last_payload = source.ReservePayload(payload);
        EXPECT_TRUE(last_association) << "migration source budget did not enforce its exact limits";
        EXPECT_TRUE(last_payload) << "migration source budget did not enforce its exact limits";
        EXPECT_FALSE(source.AcquireAssociation()) << "migration source budget did not enforce its exact limits";
        EXPECT_FALSE(source.ReservePayload(payload)) << "migration source budget did not enforce its exact limits";
    }
    {
        auto moved_associations = std::move(associations);
        auto moved_reservations = std::move(reservations);
        auto target_association = target.AcquireAssociation();
        auto target_payload = target.ReservePayload(payload);
        EXPECT_TRUE(target_association) << "failed to reserve target Worker resources";
        EXPECT_TRUE(target_payload) << "failed to reserve target Worker resources";
        for (size_t i = 0; i < kMigrating; ++i) {
            moved_associations[i] = {};
            moved_reservations[i] = {};
        }
        const auto usage = target.GetUsage();
        EXPECT_EQ(usage.associations, 1) << "moved release was charged to the wrong budget";
        EXPECT_EQ(usage.datagrams, 1) << "moved release was charged to the wrong budget";
        EXPECT_EQ(usage.payload_capacity, ::common::Buffer::kSize) << "moved release was charged to the wrong budget";
    }
    for (size_t i = 0; i < kMigrating; ++i) {
        EXPECT_FALSE(associations[i]) << "moved reservation retained source ownership";
        EXPECT_FALSE(reservations[i]) << "moved reservation retained source ownership";
    }
    {
        std::array<Budget::AssociationLease, kMigrating + 1> restored_associations;
        std::array<Budget::PayloadReservation, kMigrating + 1> restored_reservations;
        for (size_t i = 0; i < kMigrating + 1; ++i) {
            restored_associations[i] = source.AcquireAssociation();
            restored_reservations[i] = source.ReservePayload(payload);
            EXPECT_TRUE(restored_associations[i]) << "moved release lost source budget admission capacity";
            EXPECT_TRUE(restored_reservations[i]) << "moved release lost source budget admission capacity";
        }
    }
    for (auto* budget : {&source, &target}) {
        const auto usage = budget->GetUsage();
        EXPECT_FALSE(usage.associations) << "reservation destruction leaked resource accounting";
        EXPECT_FALSE(usage.datagrams) << "reservation destruction leaked resource accounting";
        EXPECT_FALSE(usage.payload_capacity) << "reservation destruction leaked resource accounting";
        auto association = budget->AcquireAssociation();
        auto reservation = budget->ReservePayload(payload);
        EXPECT_TRUE(association) << "release did not restore admission";
        EXPECT_TRUE(reservation) << "release did not restore admission";
    }
}

TEST(UdpSessionIdentity, EndpointNormalizationPreservesPortAndSessionDiscrimination) {
    ::proxy::InboundDatagramOwner owner;
    const std::array<uint8_t, 1> owner_bytes{0x53};
    ASSERT_TRUE(owner.Assign(owner_bytes));
    const auto key = [&](uint64_t id) {
        return ::app::ClientSessionKey{owner, id};
    };
    const ::udp::endpoint endpoint(::net::ip::address_v4::loopback(), 12001);
    const ::app::ClientSessionKey endpoint_key{owner, std::nullopt, endpoint};
    const ::app::ClientSessionKey mapped_key{owner, std::nullopt,
        {::net::ip::make_address("::ffff:127.0.0.1"), endpoint.port()}};
    const ::app::ClientSessionKey moved_key{owner, std::nullopt,
        {endpoint.address(), static_cast<uint16_t>(endpoint.port() + 1)}};
    const ::app::ClientSessionKeyHash hash;

    EXPECT_TRUE((endpoint_key == mapped_key)) << "typed UDP identity lost normalization, endpoint port or zero-session distinction";
    EXPECT_EQ(hash(endpoint_key), hash(mapped_key)) << "typed UDP identity lost normalization, endpoint port or zero-session distinction";
    EXPECT_NE(endpoint_key, moved_key) << "typed UDP identity lost normalization, endpoint port or zero-session distinction";
    EXPECT_NE(endpoint_key, key(0)) << "typed UDP identity lost normalization, endpoint port or zero-session distinction";
    EXPECT_TRUE((key(0) == ::app::ClientSessionKey{owner, 0, endpoint})) << "typed UDP identity lost normalization, endpoint port or zero-session distinction";
}

TEST(UdpResourceBudget, AssociationAdmissionWaitsForLastSessionOwnerRelease) {
    using Ingress = ::app::UdpIngress;
    AllocationFaultScope allocation_fault_scope;
    ::net::io_context io;
    UdpSocketFixtures sockets(io);
    auto& scheduler = ::transport::TimeoutScheduler::ForIoContext(io);
    ::app::UdpAssociationReclaimer reclaimer(
        scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    ::app::UdpResourceBudget budget({
        .associations = 2, .datagrams = 3,
        .payload_capacity = 3 * ::common::Buffer::kSize});
    Ingress first("first", std::make_unique<DummyDatagramHandler>(),
                  reclaimer, budget, io);
    Ingress second("second", std::make_unique<DummyDatagramHandler>(),
                   reclaimer, budget, io);
    ::proxy::InboundDatagramOwner owner;
    const std::array<uint8_t, 1> owner_bytes{0x53};
    ASSERT_TRUE(owner.Assign(owner_bytes));
    const auto key = [&](uint64_t id) {
        return ::app::ClientSessionKey{owner, id};
    };
    const ::udp::endpoint endpoint(::net::ip::address_v4::loopback(), 12001);
    const ::app::ClientSessionKey endpoint_key{owner, std::nullopt, endpoint};
    const ::app::ClientSessionKey mapped_key{owner, std::nullopt,
        {::net::ip::make_address("::ffff:127.0.0.1"), endpoint.port()}};
    const ::app::ClientSessionKey moved_key{owner, std::nullopt,
        {endpoint.address(), static_cast<uint16_t>(endpoint.port() + 1)}};
    const ::common::TargetAddress target(endpoint.address(), 53);
    const auto create = [&](Ingress& ingress, uint64_t id) {
        return ingress.CreateClientSession(sockets.Get(ingress, "socket"), key(id), io,
            {}, endpoint, owner,
            std::chrono::steady_clock::now(), std::chrono::seconds::zero());
    };
    const auto payload = [&](size_t blocks = 1) {
        ::common::MultiBuffer result;
        ::common::BufferGuard buffer{::common::Buffer::New(blocks * ::common::Buffer::kSize)};
        if (!buffer) throw std::bad_alloc();
        buffer->Tail()[0] = 0x55;
        buffer->Produce(1);
        result.push_back(std::move(buffer));
        return result;
    };
    auto one = create(first, 1);
    auto two = create(second, 2);
    ASSERT_TRUE(one) << "association admission was not shared across ingresses";
    ASSERT_TRUE(two) << "association admission was not shared across ingresses";
    EXPECT_FALSE(create(first, 3)) << "association admission was not shared across ingresses";
    EXPECT_EQ(budget.GetUsage().associations, 2) << "association admission was not shared across ingresses";
    first.CleanupClientSessions(*sockets.Get(first, "socket"));
    EXPECT_TRUE(one->Closed()) << "map removal bypassed the live association budget";
    EXPECT_FALSE(create(second, 3)) << "map removal bypassed the live association budget";
    EXPECT_EQ(budget.GetUsage().associations, 2) << "map removal bypassed the live association budget";
    one.reset();
    auto three = create(first, 3);
    ASSERT_TRUE(three) << "association release failed to restore admission or existing request";
    EXPECT_EQ(budget.GetUsage().associations, 2) << "association release failed to restore admission or existing request";
    EXPECT_TRUE(two->Push(target, payload())) << "association release failed to restore admission or existing request";
    first.RequestStop();
    second.RequestStop();
    one.reset();
    two.reset();
    three.reset();
    EXPECT_EQ(budget.GetUsage().associations, 0u);
}

#ifdef CNODE_TEST_ALLOCATOR
TEST(UdpResourceBudget, SessionConstructionFailureReleasesAssociationLease) {
    using Ingress = ::app::UdpIngress;
    AllocationFaultScope allocation_fault_scope;
    ::net::io_context io;
    UdpSocketFixtures sockets(io);
    auto& scheduler = ::transport::TimeoutScheduler::ForIoContext(io);
    ::app::UdpAssociationReclaimer reclaimer(
        scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    ::app::UdpResourceBudget budget({
        .associations = 2, .datagrams = 3,
        .payload_capacity = 3 * ::common::Buffer::kSize});
    Ingress first("first", std::make_unique<DummyDatagramHandler>(),
                  reclaimer, budget, io);
    Ingress second("second", std::make_unique<DummyDatagramHandler>(),
                   reclaimer, budget, io);
    ::proxy::InboundDatagramOwner owner;
    const std::array<uint8_t, 1> owner_bytes{0x53};
    ASSERT_TRUE(owner.Assign(owner_bytes));
    const auto key = [&](uint64_t id) {
        return ::app::ClientSessionKey{owner, id};
    };
    const ::udp::endpoint endpoint(::net::ip::address_v4::loopback(), 12001);
    const ::app::ClientSessionKey endpoint_key{owner, std::nullopt, endpoint};
    const ::app::ClientSessionKey mapped_key{owner, std::nullopt,
        {::net::ip::make_address("::ffff:127.0.0.1"), endpoint.port()}};
    const ::app::ClientSessionKey moved_key{owner, std::nullopt,
        {endpoint.address(), static_cast<uint16_t>(endpoint.port() + 1)}};
    const ::common::TargetAddress target(endpoint.address(), 53);
    const auto create = [&](Ingress& ingress, uint64_t id) {
        return ingress.CreateClientSession(sockets.Get(ingress, "socket"), key(id), io,
            {}, endpoint, owner,
            std::chrono::steady_clock::now(), std::chrono::seconds::zero());
    };
    (void)sockets.Get(first, "socket");
    // Shared ownership still allocates its control block through global new.
    reject_next_new = true;
    bool association_oom = false;
    try {
        (void)create(first, 1);
    } catch (const std::bad_alloc&) {
        association_oom = !reject_next_new;
    }
    reject_next_new = false;
    EXPECT_TRUE(association_oom);
    EXPECT_EQ(budget.GetUsage().associations, 0u);
    EXPECT_EQ(first.GetResourceStats().associations, 0u);

    // Warm the reclaimer so this sweep reaches each session-index allocation,
    // rather than repeatedly failing the earlier heap reservation.
    auto warm = create(first, 0);
    ASSERT_TRUE(warm);
    first.CleanupClientSessions(*sockets.Get(first, "socket"));
    warm.reset();
    bool inserted = false;
    bool index_oom = false;
    for (int allocation_budget = 0; allocation_budget < 8; ++allocation_budget) {
        SCOPED_TRACE(allocation_budget);
        const auto rejected_before = ::common::rejected_process_allocations;
        ::common::process_allocation_budget = allocation_budget;
        Ingress::ClientSessionPtr session;
        bool allocation_failed = false;
        try {
            session = create(first, 1);
        } catch (const std::bad_alloc&) {
            allocation_failed = true;
        }
        ::common::process_allocation_budget = -1;
        if (allocation_failed) {
            EXPECT_GT(::common::rejected_process_allocations, rejected_before);
            EXPECT_EQ(first.GetResourceStats().associations, 0u);
            EXPECT_EQ(budget.GetUsage().associations, 0u);
            index_oom = true;
            continue;
        }
        ASSERT_TRUE(session);
        EXPECT_EQ(first.GetResourceStats().associations, 1u);
        first.CleanupClientSessions(*sockets.Get(first, "socket"));
        session.reset();
        EXPECT_EQ(budget.GetUsage().associations, 0u);
        inserted = true;
        break;
    }
    EXPECT_TRUE(index_oom);
    EXPECT_TRUE(inserted);
}
#endif

TEST(UdpResourceBudget, SharedPayloadSaturationRetainsInflightOwnershipAndRestoresAdmission) {
    using Ingress = ::app::UdpIngress;
    using Result = Ingress::ReplyEnqueueResult;
    AllocationFaultScope allocation_fault_scope;
    ::net::io_context io;
    UdpSocketFixtures sockets(io);
    auto& scheduler = ::transport::TimeoutScheduler::ForIoContext(io);
    ::app::UdpAssociationReclaimer reclaimer(
        scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    ::app::UdpResourceBudget budget({
        .associations = 2, .datagrams = 3,
        .payload_capacity = 3 * ::common::Buffer::kSize});
    Ingress first("first", std::make_unique<DummyDatagramHandler>(),
                  reclaimer, budget, io);
    Ingress second("second", std::make_unique<DummyDatagramHandler>(),
                   reclaimer, budget, io);
    ::proxy::InboundDatagramOwner owner;
    const std::array<uint8_t, 1> owner_bytes{0x53};
    ASSERT_TRUE(owner.Assign(owner_bytes));
    const auto key = [&](uint64_t id) {
        return ::app::ClientSessionKey{owner, id};
    };
    const ::udp::endpoint endpoint(::net::ip::address_v4::loopback(), 12001);
    const ::app::ClientSessionKey endpoint_key{owner, std::nullopt, endpoint};
    const ::app::ClientSessionKey mapped_key{owner, std::nullopt,
        {::net::ip::make_address("::ffff:127.0.0.1"), endpoint.port()}};
    const ::app::ClientSessionKey moved_key{owner, std::nullopt,
        {endpoint.address(), static_cast<uint16_t>(endpoint.port() + 1)}};
    const ::common::TargetAddress target(endpoint.address(), 53);
    const auto create = [&](Ingress& ingress, uint64_t id) {
        return ingress.CreateClientSession(sockets.Get(ingress, "socket"), key(id), io,
            {}, endpoint, owner,
            std::chrono::steady_clock::now(), std::chrono::seconds::zero());
    };
    const auto payload = [&](size_t blocks = 1) {
        ::common::MultiBuffer result;
        ::common::BufferGuard buffer{::common::Buffer::New(blocks * ::common::Buffer::kSize)};
        if (!buffer) throw std::bad_alloc();
        buffer->Tail()[0] = 0x55;
        buffer->Produce(1);
        result.push_back(std::move(buffer));
        return result;
    };
    auto one = create(first, 1);
    auto two = create(second, 2);
    ASSERT_TRUE(one) << "association admission was not shared across ingresses";
    ASSERT_TRUE(two) << "association admission was not shared across ingresses";
    EXPECT_FALSE(create(first, 3)) << "association admission was not shared across ingresses";
    EXPECT_EQ(budget.GetUsage().associations, 2) << "association admission was not shared across ingresses";
    first.CleanupClientSessions(*sockets.Get(first, "socket"));
    EXPECT_TRUE(one->Closed()) << "map removal bypassed the live association budget";
    EXPECT_FALSE(create(second, 3)) << "map removal bypassed the live association budget";
    EXPECT_EQ(budget.GetUsage().associations, 2) << "map removal bypassed the live association budget";
    one.reset();
    auto three = create(first, 3);
    ASSERT_TRUE(three) << "association release failed to restore admission or existing request";
    EXPECT_EQ(budget.GetUsage().associations, 2) << "association release failed to restore admission or existing request";
    EXPECT_TRUE(two->Push(target, payload())) << "association release failed to restore admission or existing request";

    EXPECT_EQ(first.EnqueueReply(sockets.Get(first, "reply"), endpoint, payload()), Result::StartSend) << "failed to reserve a shared reply payload";
#ifdef CNODE_TEST_ALLOCATOR
    ::common::reject_next_process_allocation = true;
#endif
    auto active = first.BeginReplySend(*sockets.Get(first, "reply"));
#ifdef CNODE_TEST_ALLOCATOR
    const bool allocated = !::common::reject_next_process_allocation;
    ::common::reject_next_process_allocation = false;
    EXPECT_FALSE(allocated) << "ordinary UDP send handoff allocated a packet node";
#endif
    ASSERT_TRUE(active) << "payload capacity did not include in-flight reply buffers";
    EXPECT_EQ(budget.GetUsage().datagrams, 2) << "payload capacity did not include in-flight reply buffers";
    EXPECT_EQ(budget.GetUsage().payload_capacity, 2 * ::common::Buffer::kSize) << "payload capacity did not include in-flight reply buffers";
    EXPECT_EQ(second.EnqueueReply(sockets.Get(second, "reply"), endpoint, payload(2)), Result::Rejected) << "payload capacity did not include in-flight reply buffers";
    EXPECT_FALSE(three->Push(target, payload(2))) << "shared payload rejection closed an existing association or leaked a reservation";
    EXPECT_FALSE(three->Closed()) << "shared payload rejection closed an existing association or leaked a reservation";
    EXPECT_EQ(budget.GetUsage().datagrams, 2) << "shared payload rejection closed an existing association or leaked a reservation";
    EXPECT_EQ(second.EnqueueReply(sockets.Get(second, "reply"), endpoint, payload()), Result::StartSend) << "global datagram saturation was not isolated to the incoming packet";
    EXPECT_FALSE(three->Push(target, payload())) << "global datagram saturation was not isolated to the incoming packet";
    EXPECT_FALSE(three->Closed()) << "global datagram saturation was not isolated to the incoming packet";
    first.ClearReplyQueue(*sockets.Get(first, "reply"));
    EXPECT_EQ(budget.GetUsage().datagrams, 3) << "clearing the reply map prematurely released an in-flight send";
    active.reset();
    EXPECT_EQ(budget.GetUsage().datagrams, 2) << "in-flight completion failed to restore shared payload capacity";
    EXPECT_TRUE(three->Push(target, payload())) << "in-flight completion failed to restore shared payload capacity";

    bool read = false;
    ::net::co_spawn(io, two->ReadMultiBuffer(),
        [&](std::exception_ptr error, ::common::MultiBuffer buffers) {
            read = !error && buffers.byte_size() == 1;
            EXPECT_EQ(budget.GetUsage().datagrams, 2) << "relay-owned payload still consumed queue budget";
        });
    io.poll();
    io.restart();
    EXPECT_TRUE(read) << "a saturated Worker stopped serving an existing association";
    EXPECT_FALSE(two->Closed()) << "a saturated Worker stopped serving an existing association";
    EXPECT_TRUE(two->Push(target, payload())) << "a saturated Worker stopped serving an existing association";
    second.ClearReplyQueue(*sockets.Get(second, "reply"));
    first.RequestStop();
    second.RequestStop();
    three.reset();
    two.reset();
    io.poll();
    io.restart();
    EXPECT_EQ(budget.GetUsage().associations, 0) << "stop and destruction retained shared UDP resources";
    EXPECT_EQ(budget.GetUsage().datagrams, 0) << "stop and destruction retained shared UDP resources";
    EXPECT_EQ(budget.GetUsage().payload_capacity, 0) << "stop and destruction retained shared UDP resources";
}

class UdpPayloadLimitTest : public ::testing::TestWithParam<bool> {};
TEST_P(UdpPayloadLimitTest, ReplyAdmissionReleasesCapacityOnQueueDestruction) {
    ::net::io_context io;
    UdpSocketFixtures sockets(io);
    auto& scheduler = ::transport::TimeoutScheduler::ForIoContext(io);
    ::app::UdpAssociationReclaimer reclaimer{
        scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); }};
    ::app::UdpResourceBudget budget({
        .associations = 1, .datagrams = GetParam() ? 1u : 8u,
        .payload_capacity = GetParam() ? 1024u * 1024u : ::common::Buffer::kSize});
    ::app::UdpIngress ingress{"limits", std::make_unique<DummyDatagramHandler>(), reclaimer, budget, io};
    const ::udp::endpoint endpoint{::net::ip::address_v4::loopback(), 12001};
    auto payload = [] {
        ::common::MultiBuffer result;
        const std::array<uint8_t, 1> bytes{0x55};
        if (!result.AppendSpan(bytes)) throw std::bad_alloc();
        return result;
    };
    using Result = ::app::UdpIngress::ReplyEnqueueResult;
    EXPECT_EQ(ingress.EnqueueReply(sockets.Get(ingress, "reply"), endpoint, payload()), Result::StartSend);
    EXPECT_EQ(ingress.EnqueueReply(sockets.Get(ingress, "reply"), endpoint, payload()), Result::Rejected);
    EXPECT_EQ(budget.GetUsage().datagrams, 1u);
    EXPECT_EQ(budget.GetUsage().payload_capacity, ::common::Buffer::kSize);
    ingress.RequestStop();
    EXPECT_EQ(budget.GetUsage().datagrams, 0u);
    EXPECT_EQ(budget.GetUsage().payload_capacity, 0u);
}
INSTANTIATE_TEST_SUITE_P(CountOrCapacity, UdpPayloadLimitTest, ::testing::Bool());

TEST(UdpResourceBudget, EmptyDatagramsRetainBoundariesAndReleaseQueueReservations) {
    using Ingress = ::app::UdpIngress;
    AllocationFaultScope allocation_fault_scope;
    ::net::io_context io;
    UdpSocketFixtures sockets(io);
    auto& scheduler = ::transport::TimeoutScheduler::ForIoContext(io);
    ::app::UdpAssociationReclaimer reclaimer(
        scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    ::app::UdpResourceBudget budget({
        .associations = 2, .datagrams = 3,
        .payload_capacity = 3 * ::common::Buffer::kSize});
    Ingress first("first", std::make_unique<DummyDatagramHandler>(),
                  reclaimer, budget, io);
    Ingress second("second", std::make_unique<DummyDatagramHandler>(),
                   reclaimer, budget, io);
    ::proxy::InboundDatagramOwner owner;
    const std::array<uint8_t, 1> owner_bytes{0x53};
    ASSERT_TRUE(owner.Assign(owner_bytes));
    const auto key = [&](uint64_t id) {
        return ::app::ClientSessionKey{owner, id};
    };
    const ::udp::endpoint endpoint(::net::ip::address_v4::loopback(), 12001);
    const ::app::ClientSessionKey endpoint_key{owner, std::nullopt, endpoint};
    const ::app::ClientSessionKey mapped_key{owner, std::nullopt,
        {::net::ip::make_address("::ffff:127.0.0.1"), endpoint.port()}};
    const ::app::ClientSessionKey moved_key{owner, std::nullopt,
        {endpoint.address(), static_cast<uint16_t>(endpoint.port() + 1)}};
    const ::common::TargetAddress target(endpoint.address(), 53);
    const auto create = [&](Ingress& ingress, uint64_t id) {
        return ingress.CreateClientSession(sockets.Get(ingress, "socket"), key(id), io,
            {}, endpoint, owner,
            std::chrono::steady_clock::now(), std::chrono::seconds::zero());
    };
    ::app::UdpResourceBudget empty_budget({
        .associations = 1, .datagrams = 2,
        .payload_capacity = 2 * ::common::Buffer::kSize});
    Ingress empty_ingress("empty", std::make_unique<DummyDatagramHandler>(),
                          reclaimer,
                          empty_budget, io);
    auto empty_session = create(empty_ingress, 1);
    ASSERT_TRUE(empty_session) << "zero-length input bypassed datagram count or Buffer capacity admission";
    EXPECT_TRUE(empty_session->Push(target, {})) << "zero-length input bypassed datagram count or Buffer capacity admission";
    EXPECT_TRUE(empty_session->Push(target, {})) << "zero-length input bypassed datagram count or Buffer capacity admission";
    EXPECT_FALSE(empty_session->Push(target, {})) << "zero-length input bypassed datagram count or Buffer capacity admission";
    EXPECT_FALSE(empty_session->Closed()) << "zero-length input bypassed datagram count or Buffer capacity admission";
    EXPECT_EQ(empty_budget.GetUsage().datagrams, 2) << "zero-length input bypassed datagram count or Buffer capacity admission";
    EXPECT_EQ(empty_budget.GetUsage().payload_capacity, 2 * ::common::Buffer::kSize) << "zero-length input bypassed datagram count or Buffer capacity admission";
    bool empty_read = false;
    ::net::co_spawn(io, empty_session->ReadMultiBuffer(),
        [&](std::exception_ptr error, ::common::MultiBuffer packet) {
            const auto datagram = ::common::InspectUdpDatagram(packet);
            empty_read = !error && datagram.Valid() && datagram.payload_size == 0 &&
                datagram.single_buffer != nullptr && datagram.target->SameEndpoint(target);
        });
    io.poll();
    io.restart();
    EXPECT_TRUE(empty_read) << "reading zero-length input lost its boundary or failed to restore admission";
    EXPECT_EQ(empty_budget.GetUsage().datagrams, 1) << "reading zero-length input lost its boundary or failed to restore admission";
    EXPECT_EQ(empty_budget.GetUsage().payload_capacity, ::common::Buffer::kSize) << "reading zero-length input lost its boundary or failed to restore admission";
    EXPECT_TRUE(empty_session->Push(target, {})) << "reading zero-length input lost its boundary or failed to restore admission";
    empty_session->Close();
    EXPECT_EQ(empty_budget.GetUsage().datagrams, 0) << "closing zero-length input failed to release queue reservations";
    EXPECT_EQ(empty_budget.GetUsage().payload_capacity, 0) << "closing zero-length input failed to release queue reservations";
    EXPECT_FALSE(empty_session->Push(target, {})) << "closing zero-length input failed to release queue reservations";
    empty_ingress.RequestStop();
}

TEST_F(UdpSocketOwnerTest, ResponseEncodingFailureReachesWriter) {
    const auto failing_response = std::make_shared<CountingUdpResponseContext>();
    failing_response->fail = true;
    ::app::UdpIngress::ClientSession failing_reply_session(io_context,
        {.socket = callback_state, .response = failing_response, .owner = &worker},
        reply_endpoint_a,
        default_owner, udp_budget, udp_budget.AcquireAssociation());
    ::common::BufferGuard reply_buffer{::common::Buffer::New()};
    EXPECT_TRUE(reply_buffer) << "failed to allocate UDP callback test buffer";
    reply_buffer->Tail()[0] = 0x33;
    reply_buffer->Produce(1);
    reply_buffer->SetUDP(callback_source);
    ::common::MultiBuffer reply_payload{std::move(reply_buffer)};
    bool reply_failure_reported = false;
    ::net::co_spawn(
        io_context,
        failing_reply_session.WriteMultiBuffer(std::move(reply_payload)),
        [&](std::exception_ptr error) {
            reply_failure_reported = error != nullptr;
        });
    io_context.run();
    EXPECT_TRUE(reply_failure_reported) << "UDP client response encoding failure was silently ignored";
    io_context.restart();
}

TEST_F(UdpSocketOwnerTest, RawScatterWriteIsRejectedWithoutEncoding) {
    ::proxy::Ss2022UdpSessionState state;
    const ::proxy::SsCipherInfo cipher{::proxy::SsCipherType::AES_128_GCM_2022, 16, 16};
    ::proxy::KeyBytes key;
    key.size = cipher.key_size;
    key.bytes.fill(0x71);
    ASSERT_TRUE(::proxy::Init2022UdpSessionState(state, cipher, key));
    auto raw_response = std::make_shared<::proxy::UdpResponse>(
        static_cast<const ::proxy::Ss2022UdpTxState&>(state));

    ::app::UdpIngress::ClientSession raw_reply_session(io_context,
        {.socket = callback_state, .response = raw_response, .owner = &worker},
        reply_endpoint_a,
        default_owner, udp_budget, udp_budget.AcquireAssociation());
    std::array<::net::const_buffer, 1> raw_reply_buffers{
        ::net::buffer(callback_payload)};
    bool raw_reply_rejected = false;
    ::net::co_spawn(
        io_context,
        raw_reply_session.WriteBuffers(raw_reply_buffers),
        [&](std::exception_ptr error) {
            raw_reply_rejected = error != nullptr;
        });
    io_context.run();
    EXPECT_TRUE(raw_reply_rejected) << "UDP raw scatter write was silently reported as delivered";
    // An attempted SS2022 encoding would consume a packet id. The first real
    // response must still carry id zero after the rejected scatter write.
    const auto encoded = raw_response->Encode({callback_source, callback_payload});
    std::vector<uint8_t> bytes(encoded.byte_size());
    ASSERT_EQ(encoded.CopyPrefixTo(bytes), bytes.size());
    ASSERT_GE(bytes.size(), 16u);
    std::array<uint8_t, 16> encrypted_header{}, header{};
    std::copy_n(bytes.begin(), encrypted_header.size(), encrypted_header.begin());
    ASSERT_TRUE(::proxy::AesBlocksCrypt<16>(state.key.span(), encrypted_header, header, false));
    uint64_t packet_id = 0;
    for (size_t i = 8; i < header.size(); ++i)
        packet_id = (packet_id << 8) | header[i];
    EXPECT_EQ(packet_id, 0u) << "UDP raw scatter write invoked response encoding";
    auto decoded = ::proxy::Decode2022UdpResponsePacket(bytes.data(), bytes.size(), state);
    ASSERT_TRUE(decoded);
    EXPECT_TRUE(decoded->target.SameEndpoint(callback_source));
    std::array<uint8_t, 1> decoded_payload{};
    EXPECT_EQ(decoded->payload.byte_size(), callback_payload.size());
    EXPECT_EQ(decoded->payload.CopyPrefixTo(decoded_payload), callback_payload.size());
    EXPECT_EQ(decoded_payload, callback_payload);
    large_sink.Read();
    EXPECT_EQ(large_sink.calls, 0u);
    io_context.restart();
}

TEST_F(UdpSocketOwnerTest, EmptyInputQueueEnforcesAndReleasesDatagramBound) {
    ::app::UdpIngress::ClientSession bounded_input_session(io_context,
        {},
        reply_endpoint_a,
        default_owner, udp_budget, udp_budget.AcquireAssociation());
    auto make_empty_payload = [&]() {
        return ::common::MultiBuffer{};
    };
    const auto before_empty_queue = udp_budget.GetUsage();
    for (size_t i = 0; i < 256; ++i) {
        EXPECT_TRUE(bounded_input_session.Push(
                        callback_source, make_empty_payload())) << "UDP input queue rejected a datagram below its bound";
    }
    EXPECT_EQ(udp_budget.GetUsage().datagrams, before_empty_queue.datagrams + 256) << "zero-length input queue did not charge one Buffer per datagram";
    EXPECT_EQ(udp_budget.GetUsage().payload_capacity, before_empty_queue.payload_capacity + 256 * ::common::Buffer::kSize) << "zero-length input queue did not charge one Buffer per datagram";
    EXPECT_FALSE(bounded_input_session.Push(callback_source, make_empty_payload())) << "UDP input queue accepted more than its datagram bound";
    bounded_input_session.Close();
    EXPECT_EQ(udp_budget.GetUsage().datagrams, before_empty_queue.datagrams) << "overflowed zero-length input queue retained reservations";
    EXPECT_EQ(udp_budget.GetUsage().payload_capacity, before_empty_queue.payload_capacity) << "overflowed zero-length input queue retained reservations";
}

TEST_F(UdpSocketOwnerTest, DestroyedSocketCancelsReceiveAndReleasesPort) {
    auto first = ::app::UdpIngress::MakeSocket(io_context);
    first->open(::udp::v4(), ec);
    EXPECT_FALSE(ec) << "failed to open first UDP socket";
    first->bind(::udp::endpoint(::net::ip::address_v4::loopback(), 0), ec);
    EXPECT_FALSE(ec) << "failed to bind first UDP socket";
    const auto endpoint = first->local_endpoint(ec);
    EXPECT_FALSE(ec) << "failed to resolve first UDP endpoint";
    EXPECT_NE(endpoint.port(), 0) << "failed to resolve first UDP endpoint";

    std::array<uint8_t, 1> receive_buffer{};
    ::udp::endpoint peer;
    bool receive_cancelled = false;
    first->async_receive_from(
        ::net::buffer(receive_buffer),
        peer,
        [&](::IoErrorCode receive_ec, size_t) {
            receive_cancelled = receive_ec == ::io_error::operation_aborted;
        });
    first.reset();
    io_context.run();
    EXPECT_TRUE(receive_cancelled) << "destroyed UDP socket did not cancel its pending receive";
    io_context.restart();
    auto second = ::app::UdpIngress::MakeSocket(io_context);
    second->open(::udp::v4(), ec);
    EXPECT_FALSE(ec) << "failed to open second UDP socket";
    second->bind(endpoint, ec);
    EXPECT_FALSE(ec) << "owned UDP socket did not release its bound port";
}

TEST_F(UdpSocketOwnerTest, ReceivePreservesDatagramsLargerThanOneBuffer) {
    ::udp::socket large_receiver(io_context, ::udp::v4());
    large_receiver.bind(
        ::udp::endpoint(::net::ip::address_v4::loopback(), 0), ec);
    EXPECT_FALSE(ec) << "failed to bind large UDP receiver";
    ::udp::socket large_sender(io_context, ::udp::v4());
    const auto large_endpoint = large_receiver.local_endpoint(ec);
    EXPECT_FALSE(ec) << "failed to query large UDP receiver endpoint";

    std::vector<uint8_t> large_payload(::common::Buffer::kSize + 257, 0x6d);
    bool large_received = false;
    ::net::co_spawn(
        io_context,
        [&]() -> ::net::awaitable<void> {
            auto [wait_ec] = co_await large_receiver.async_wait(
                ::udp::socket::wait_read,
                ::net::as_tuple(::net::use_awaitable));
            if (wait_ec) co_return;

            ::IoErrorCode available_ec;
            const size_t available = large_receiver.available(available_ec);
            if (available_ec) co_return;
            ::transport::UdpReceiveBuffer receive_buffer;
            const auto storage = receive_buffer.Prepare(available);
            ::udp::endpoint sender_endpoint;
            auto [receive_ec, bytes] = co_await large_receiver.async_receive_from(
                storage,
                sender_endpoint,
                ::net::as_tuple(::net::use_awaitable));
            if (receive_ec) co_return;
            const auto received = receive_buffer.Bytes(bytes);
            large_received = received.size() == large_payload.size() &&
                std::equal(received.begin(), received.end(), large_payload.begin());
        },
        ::net::detached);
    large_sender.send_to(::net::buffer(large_payload), large_endpoint, 0, ec);
    EXPECT_FALSE(ec) << "failed to send large UDP datagram";
    if (ec) large_receiver.cancel();
    io_context.run();
    EXPECT_TRUE(large_received) << "UDP receive path truncated a datagram larger than one Buffer";
    io_context.restart();
}

TEST_F(UdpSocketOwnerTest, BoundedReplyQueueAccountsForActiveAndPendingDatagrams) {
    for (size_t i = 0; i < 512; ++i) {
        (void)worker.EnqueueReply(sockets.Get(worker, "bounded-replies"), reply_endpoint_a, make_tiny_payload());
    }
    size_t drained_replies = 0;
    auto reply_stats = worker.GetResourceStats();
    EXPECT_EQ(reply_stats.reply_datagrams, 256) << "UDP reply stats did not report queued resource occupancy";
    EXPECT_EQ(reply_stats.reply_bytes, 256) << "UDP reply stats did not report queued resource occupancy";
    EXPECT_EQ(reply_stats.active_reply_senders, 0) << "UDP reply stats did not report queued resource occupancy";
    auto first_bounded_reply = worker.BeginReplySend(*sockets.Get(worker, "bounded-replies"));
    reply_stats = worker.GetResourceStats();
    ASSERT_TRUE(first_bounded_reply) << "UDP reply stats omitted the active sender";
    EXPECT_EQ(reply_stats.reply_datagrams, 256) << "UDP reply stats omitted the active sender";
    EXPECT_EQ(reply_stats.reply_bytes, 256) << "UDP reply stats omitted the active sender";
    EXPECT_EQ(reply_stats.active_reply_senders, 1) << "UDP reply stats omitted the active sender";
    ++drained_replies;
    auto bounded_reply = worker.CompleteReplySend(*sockets.Get(worker, "bounded-replies"), first_bounded_reply->id);
    reply_stats = worker.GetResourceStats();
    ASSERT_TRUE(bounded_reply) << "UDP reply completion did not hand off the next pending datagram";
    EXPECT_EQ(reply_stats.reply_datagrams, 255) << "UDP reply completion did not hand off the next pending datagram";
    EXPECT_EQ(reply_stats.reply_bytes, 255) << "UDP reply completion did not hand off the next pending datagram";
    EXPECT_EQ(reply_stats.active_reply_senders, 1) << "UDP reply completion did not hand off the next pending datagram";
    while (bounded_reply) {
        ++drained_replies;
        bounded_reply = worker.CompleteReplySend(*sockets.Get(worker, "bounded-replies"), bounded_reply->id);
    }
    EXPECT_EQ(drained_replies, 256) << "UDP reply queue exceeded or undershot its datagram bound";
    worker.ClearReplyQueue(*sockets.Get(worker, "bounded-replies"));
    reply_stats = worker.GetResourceStats();
    EXPECT_EQ(reply_stats.reply_datagrams, 0) << "UDP reply cleanup retained resource stats";
    EXPECT_EQ(reply_stats.reply_bytes, 0) << "UDP reply cleanup retained resource stats";
    EXPECT_EQ(reply_stats.active_reply_senders, 0) << "UDP reply cleanup retained resource stats";
}

TEST_F(UdpSocketOwnerTest, StaleReplyCompletionCannotReleaseReplacementQueue) {
    EXPECT_EQ(worker.EnqueueReply(sockets.Get(worker, "reply-generation"), reply_endpoint_a, make_tiny_payload()), ::app::UdpIngress::ReplyEnqueueResult::StartSend) << "failed to start the first UDP reply generation";
    auto stale_reply = worker.BeginReplySend(*sockets.Get(worker, "reply-generation"));
    ASSERT_TRUE(stale_reply) << "failed to acquire the first UDP reply generation";
    worker.ClearReplyQueue(*sockets.Get(worker, "reply-generation"));

    EXPECT_EQ(worker.EnqueueReply(sockets.Get(worker, "reply-generation"), reply_endpoint_a, make_tiny_payload()), ::app::UdpIngress::ReplyEnqueueResult::StartSend) << "failed to start the replacement UDP reply generation";
    auto active_reply = worker.BeginReplySend(*sockets.Get(worker, "reply-generation"));
    ASSERT_TRUE(active_reply) << "failed to acquire the replacement UDP reply generation";
    EXPECT_FALSE(worker.CompleteReplySend(*sockets.Get(worker, "reply-generation"), stale_reply->id)) << "stale UDP reply completion matched a replacement queue";
    EXPECT_EQ(worker.EnqueueReply(sockets.Get(worker, "reply-generation"), reply_endpoint_a, make_tiny_payload()), ::app::UdpIngress::ReplyEnqueueResult::Queued) << "stale UDP reply completion released a replacement queue";
    auto queued_reply = worker.CompleteReplySend(*sockets.Get(worker, "reply-generation"), active_reply->id);
    ASSERT_TRUE(queued_reply) << "replacement UDP reply queue lost its pending datagram";
    EXPECT_FALSE(worker.CompleteReplySend(*sockets.Get(worker, "reply-generation"), queued_reply->id)) << "drained UDP reply queue still reported pending datagrams";
    worker.ClearReplyQueue(*sockets.Get(worker, "reply-generation"));
}

TEST_F(UdpSocketOwnerTest, SameSessionIdIsIsolatedByAuthenticatedOwner) {
    ::proxy::InboundDatagramOwner owner_a;
    ::proxy::InboundDatagramOwner owner_b;
    std::array<uint8_t, 16> owner_a_bytes{};
    std::array<uint8_t, 16> owner_b_bytes{};
    owner_a_bytes.fill(0x11);
    owner_b_bytes.fill(0x22);
    EXPECT_TRUE(owner_a.Assign(owner_a_bytes)) << "failed to initialize UDP session owners";
    EXPECT_TRUE(owner_b.Assign(owner_b_bytes)) << "failed to initialize UDP session owners";
    const ::app::ClientSessionKey owner_a_session_key{owner_a, 0x1234};
    const ::app::ClientSessionKey owner_b_session_key{owner_b, 0x1234};
    EXPECT_NE(owner_a_session_key, owner_b_session_key) << "UDP protocol session key was not scoped by authenticated owner";
    const auto owner_socket = attach_uplink_socket("owner-socket");
    const auto owner_session = worker.CreateClientSession(sockets.Get(worker, "owner-socket"), owner_a_session_key,
    io_context,
    {},
    reply_endpoint_a,
    owner_a,
    std::chrono::steady_clock::now(),
    std::chrono::seconds(60));
    ASSERT_TRUE(owner_session) << "failed to create the first UDP owner session";
    // The same protocol session id authenticated as owner_b keys a different
    // row. None exists yet and this handler prepares no response, so the
    // datagram must be dropped rather than fed into owner_a's association.
    deliver_uplink("owner-socket", owner_socket, owner_b, 0x1234, 0xb0);
    auto input_stats = worker.GetResourceStats();
    EXPECT_EQ(input_stats.associations, 1) << "UDP session key collision crossed authenticated owners";
    EXPECT_EQ(input_stats.input_datagrams, 0) << "UDP session key collision crossed authenticated owners";
    EXPECT_EQ(input_stats.native_dispatches, 0) << "UDP session key collision crossed authenticated owners";
    deliver_uplink("owner-socket", owner_socket, owner_a, 0x1234, 0xa1);
    input_stats = worker.GetResourceStats();
    EXPECT_EQ(input_stats.input_datagrams, 1) << "UDP session rejected its authenticated owner";
    EXPECT_EQ(input_stats.input_bytes, 1) << "UDP session rejected its authenticated owner";
    const auto second_owner_session = worker.CreateClientSession(sockets.Get(worker, "owner-socket"), owner_b_session_key,
    io_context,
    {},
    reply_endpoint_a,
    owner_b,
    std::chrono::steady_clock::now(),
    std::chrono::seconds(60));
    ASSERT_TRUE(second_owner_session) << "UDP session ID collision blocked a different authenticated owner";
    EXPECT_NE(second_owner_session, owner_session) << "UDP session ID collision blocked a different authenticated owner";
    EXPECT_EQ(worker.GetResourceStats().associations, 2) << "UDP session ID collision blocked a different authenticated owner";
    deliver_uplink("owner-socket", owner_socket, owner_b, 0x1234, 0xb2);
    input_stats = worker.GetResourceStats();
    EXPECT_EQ(input_stats.input_datagrams, 2) << "UDP input stats did not include both queued sessions";
    EXPECT_EQ(input_stats.input_bytes, 2) << "UDP input stats did not include both queued sessions";
    EXPECT_EQ(read_marker(*owner_session), 0xa1) << "UDP owner session did not receive exactly its own payload";
    input_stats = worker.GetResourceStats();
    EXPECT_EQ(input_stats.input_datagrams, 1) << "UDP input stats did not drain after ReadMultiBuffer";
    EXPECT_EQ(input_stats.input_bytes, 1) << "UDP input stats did not drain after ReadMultiBuffer";
    EXPECT_EQ(read_marker(*second_owner_session), 0xb2) << "UDP same-id session of another owner did not receive its own payload";
    input_stats = worker.GetResourceStats();
    EXPECT_EQ(input_stats.input_datagrams, 0) << "UDP input stats did not drain both owner sessions";
    EXPECT_EQ(input_stats.input_bytes, 0) << "UDP input stats did not drain both owner sessions";
    owner_session->Close();
    auto association_stats = worker.GetResourceStats();
    EXPECT_EQ(association_stats.associations, 2) << "UDP association stats did not count live and closed sessions";
    EXPECT_EQ(association_stats.closed_associations, 1) << "UDP association stats did not count live and closed sessions";
    worker.CloseSocket(*sockets.Get(worker, "owner-socket"));
    association_stats = worker.GetResourceStats();
    EXPECT_EQ(association_stats.associations, 0) << "UDP association cleanup retained resource stats";
}

TEST_F(UdpSocketOwnerTest, InputOverflowReportsNoBufferSpaceInsteadOfEof) {
    ::app::UdpIngress::ClientSession overflow_session(io_context,
        {},
        reply_endpoint_a,
        default_owner, udp_budget, udp_budget.AcquireAssociation());
    ::common::MultiBuffer oversized_input;
    size_t oversized_bytes = 0;
    while (oversized_bytes <= 512 * 1024) {
        ::common::BufferGuard buffer{::common::Buffer::New()};
        EXPECT_TRUE(buffer) << "failed to allocate oversized UDP input";
        const size_t n = buffer->Available();
        std::memset(buffer->Tail().data(), 0x5a, n);
        buffer->Produce(static_cast<uint32_t>(n));
        oversized_bytes += n;
        oversized_input.push_back(std::move(buffer));
    }
    EXPECT_FALSE(overflow_session.Push(callback_source, std::move(oversized_input))) << "oversized UDP input did not terminate its session";
    EXPECT_TRUE(overflow_session.Closed()) << "oversized UDP input did not terminate its session";
    bool overflow_reported = false;
    ::net::co_spawn(
        io_context,
        overflow_session.ReadMultiBuffer(),
        [&](std::exception_ptr error, ::common::MultiBuffer) {
            try {
                if (error) std::rethrow_exception(error);
            } catch (const ::IoSystemError& e) {
                overflow_reported = e.code() == ::io_error::no_buffer_space;
            }
        });
    io_context.poll();
    EXPECT_TRUE(overflow_reported) << "UDP input overflow was exposed as a clean EOF";
    io_context.restart();
}

TEST_F(UdpSocketOwnerTest, LongSocketKeysReleaseEveryCycleResource) {
    const std::string long_socket_key(160, 's');
    const auto long_socket = attach_uplink_socket(long_socket_key);
    for (size_t cycle = 0; cycle < 1000; ++cycle) {
        SCOPED_TRACE(cycle);
        const ::app::ClientSessionKey long_client_key{default_owner, cycle};
        auto cycle_session = worker.CreateClientSession(sockets.Get(worker, long_socket_key), long_client_key,
        io_context,
        {},
        reply_endpoint_a,
        default_owner,
        std::chrono::steady_clock::now(),
        std::chrono::seconds(60));
        ASSERT_TRUE(cycle_session) << "failed to create a long-key UDP session";
        AllocationFaultScope allocation_fault_scope;
        reject_next_new = true;
        ::common::reject_next_process_allocation = true;
        const auto inspected = worker.GetResourceStats();
        const bool new_fault_unused = reject_next_new;
        const bool process_fault_unused = ::common::reject_next_process_allocation;
        reject_next_new = false;
        ::common::reject_next_process_allocation = false;
        EXPECT_EQ(inspected.associations, 1u);
        EXPECT_TRUE(new_fault_unused);
        EXPECT_TRUE(process_fault_unused);
        // Reaching the pre-created row proves the borrowed long-key lookup.
        deliver_uplink(long_socket_key, long_socket, default_owner, cycle, 0x6c);
        EXPECT_EQ(worker.GetResourceStats().input_datagrams, 1) << "long UDP keys failed heterogeneous session lookup";
        EXPECT_EQ(worker.EnqueueReply(sockets.Get(worker, long_socket_key), reply_endpoint_a, make_tiny_payload()), ::app::UdpIngress::ReplyEnqueueResult::StartSend) << "long UDP socket key failed reply queue insertion";
        auto long_reply = worker.BeginReplySend(*sockets.Get(worker, long_socket_key));
        ASSERT_TRUE(long_reply) << "long UDP reply queue was absent from resource stats";
        EXPECT_EQ(worker.GetResourceStats().active_reply_senders, 1) << "long UDP reply queue was absent from resource stats";
        (void)worker.CompleteReplySend(*sockets.Get(worker, long_socket_key), long_reply->id);
        long_reply.reset();
        worker.ClearReplyQueue(*sockets.Get(worker, long_socket_key));
        std::weak_ptr<::app::UdpIngress::ClientSession> cycle_weak = cycle_session;
        cycle_session->Close();
        worker.CleanupClientSessions(*sockets.Get(worker, long_socket_key));
        cycle_session.reset();
        EXPECT_TRUE(cycle_weak.expired()) << "long-key UDP session remained alive after cleanup";
        const auto cycle_stats = worker.GetResourceStats();
        EXPECT_EQ(cycle_stats.associations, 0) << "UDP resource cycle retained map-owned state";
        EXPECT_EQ(cycle_stats.input_datagrams, 0) << "UDP resource cycle retained map-owned state";
        EXPECT_EQ(cycle_stats.input_bytes, 0) << "UDP resource cycle retained map-owned state";
        EXPECT_EQ(cycle_stats.reply_datagrams, 0) << "UDP resource cycle retained map-owned state";
        EXPECT_EQ(cycle_stats.reply_bytes, 0) << "UDP resource cycle retained map-owned state";
        EXPECT_EQ(cycle_stats.active_reply_senders, 0) << "UDP resource cycle retained map-owned state";
        if ((cycle + 1) % 50 == 0) {
            io_context.run_for(std::chrono::milliseconds(1));
            io_context.restart();
        }
    }
    worker.CloseSocket(*sockets.Get(worker, long_socket_key));
}

class UdpReplyEndpointTest : public UdpSocketOwnerTest, public ::testing::WithParamInterface<bool> {};

TEST_P(UdpReplyEndpointTest, MultibufferReplyUsesCurrentEndpointWithoutSplittingDatagram) {
    std::vector<uint8_t> callback_large_payload(
        ::common::Buffer::kSize + 257, 0x6d);
    ::common::MultiBuffer callback_large_buffers;
    EXPECT_TRUE(callback_large_buffers.AppendSpan(
                callback_large_payload)) << "failed to allocate large UDP callback payload";
    ASSERT_TRUE(::common::SetUdpTarget(callback_large_buffers, callback_source));

    auto response_context = std::make_shared<CountingUdpResponseContext>();
    ::app::UdpIngress::ClientSession large_reply_session(io_context,
        {.socket = callback_state, .response = response_context,
         .owner = &worker},
        reply_endpoint_a,
        default_owner, udp_budget, udp_budget.AcquireAssociation());
    if (GetParam()) large_reply_session.UpdateReplyEndpoint(reply_endpoint_b);
    bool large_reply_failed = false;
    ::net::co_spawn(
        io_context,
        large_reply_session.WriteMultiBuffer(std::move(callback_large_buffers)),
        [&](std::exception_ptr error) {
            large_reply_failed = error != nullptr;
        });
    io_context.run();
    auto& sink = GetParam() ? moved_sink : large_sink;
    sink.Read();
    EXPECT_FALSE(large_reply_failed);
    EXPECT_EQ(sink.calls, 1u);
    EXPECT_EQ(response_context->calls, 1u);
    EXPECT_EQ(response_context->last_size, callback_large_payload.size());
    EXPECT_TRUE(response_context->last_target.SameEndpoint(callback_source));
    EXPECT_EQ(sink.bytes, callback_large_payload);
}

INSTANTIATE_TEST_SUITE_P(EndpointMigration, UdpReplyEndpointTest, ::testing::Bool());

TEST_F(UdpSocketOwnerTest, DuplicateAttachmentPreservesLiveSocketIdentity) {
    auto attached = AttachStableSocket();
    auto duplicate = ::app::UdpIngress::MakeSocket(io_context);
    duplicate->open(::udp::v4(), ec);
    EXPECT_FALSE(ec) << "failed to open duplicate UDP socket";
    EXPECT_EQ(sockets.Attach(worker, "stable-socket", std::move(duplicate)), nullptr) << "duplicate UDP socket attachment was accepted";
    EXPECT_EQ(sockets.Find(worker, "stable-socket"), attached) << "duplicate attachment replaced the live UDP socket";
    EXPECT_TRUE(attached->is_open()) << "duplicate attachment replaced the live UDP socket";
}

TEST_F(UdpSocketOwnerTest, RetiringSocketCancelsWaitOnExternalLifetimeHandle) {
    auto attached = AttachStableSocket();
    bool attached_wait_cancelled = false;
    attached->async_wait(
        ::udp::socket::wait_read,
        [&](::IoErrorCode wait_ec) {
            attached_wait_cancelled =
                wait_ec == ::io_error::operation_aborted;
        });
    worker.CloseSocket(*sockets.Get(worker, "stable-socket"));
    EXPECT_EQ(sockets.Find(worker, "stable-socket"), nullptr) << "closed UDP socket remained registered";
    EXPECT_TRUE(attached) << "retired UDP socket lifetime handle did not observe closure";
    EXPECT_FALSE(attached->is_open()) << "retired UDP socket lifetime handle did not observe closure";
    EXPECT_FALSE(sockets.Owns(worker, "stable-socket", attached.get())) << "retired UDP socket lifetime handle did not observe closure";
    io_context.run();
    EXPECT_TRUE(attached_wait_cancelled) << "retired UDP socket did not deliver cancellation to its lifetime handle";
    io_context.restart();
}

class UdpHandlerReplacementTest : public UdpSocketOwnerTest, public ::testing::WithParamInterface<bool> {};
TEST_P(UdpHandlerReplacementTest, ReplacementResultDoesNotDisturbSocketSessionOrResponseSnapshot) {
    auto attached = AttachStableSocket();
    auto owner_session = worker.CreateClientSession(sockets.Get(worker, "owner-socket"),
        ::app::ClientSessionKey{default_owner, 1}, io_context, {}, reply_endpoint_a,
        default_owner, std::chrono::steady_clock::now(), std::chrono::seconds(60));
    ASSERT_NE(owner_session, nullptr);
    auto response_context = std::make_shared<CountingUdpResponseContext>();
    ::app::UdpIngress::ClientSession snapshot_reply_session(io_context,
        {.socket = callback_state, .response = response_context, .owner = &worker},
        reply_endpoint_a,
        default_owner, udp_budget, udp_budget.AcquireAssociation());
    std::unique_ptr<::proxy::Inbound> replacement;
    if (GetParam()) replacement = std::make_unique<DummyDatagramHandler>(&uplink_script);
    EXPECT_EQ(worker.ReplaceHandler(std::move(replacement)), GetParam());
    EXPECT_FALSE(owner_session->Closed()) << "UDP handler replacement closed a live client session";
    ::common::BufferGuard snapshot_reply{::common::Buffer::New()};
    EXPECT_TRUE(snapshot_reply) << "failed to allocate snapshot UDP reply";
    snapshot_reply->Tail()[0] = 0x55;
    snapshot_reply->Produce(1);
    snapshot_reply->SetUDP(callback_source);
    bool snapshot_reply_failed = false;
    ::net::co_spawn(
        io_context,
        snapshot_reply_session.WriteMultiBuffer(
            ::common::MultiBuffer{std::move(snapshot_reply)}),
        [&](std::exception_ptr error) {
            snapshot_reply_failed = error != nullptr;
        });
    io_context.poll();
    EXPECT_FALSE(snapshot_reply_failed) << "UDP handler replacement changed a live response context";
    large_sink.Read();
    EXPECT_EQ(large_sink.calls, 1u) << "UDP handler replacement changed a live response context";
    EXPECT_EQ(response_context->calls, 1u) << "UDP handler replacement changed a live response context";
    EXPECT_EQ(response_context->last_size, 1u) << "UDP handler replacement changed a live response context";
    EXPECT_TRUE(response_context->last_target.SameEndpoint(callback_source));
    EXPECT_EQ(large_sink.bytes, (std::vector<uint8_t>{0x55}));
    io_context.restart();
    EXPECT_EQ(sockets.Find(worker, "stable-socket"), attached) << "UDP handler replacement disturbed the live socket";
    EXPECT_TRUE(attached->is_open()) << "UDP handler replacement disturbed the live socket";
}
INSTANTIATE_TEST_SUITE_P(ValidOrNullHandler, UdpHandlerReplacementTest, ::testing::Bool());

#ifdef CNODE_TEST_ALLOCATOR
TEST_F(UdpSocketOwnerTest, ReplyAllocationFailurePreservesActiveAndPendingDatagrams) {
        const auto budget_before = udp_budget.GetUsage();
        auto enqueue_one = [&]() {
            return worker.EnqueueReply(sockets.Get(worker, "oom-reply"), reply_endpoint_a, make_tiny_payload());
        };
        auto enqueue_with_fault = [&]() {
            auto payload = make_tiny_payload();
            // The reply deque grows through the process resource.
            ::common::reject_next_process_allocation = true;
            return worker.EnqueueReply(sockets.Get(worker, "oom-reply"), reply_endpoint_a, std::move(payload));
        };
        EXPECT_EQ(enqueue_one(), ::app::UdpIngress::ReplyEnqueueResult::StartSend) << "failed to prime UDP reply OOM queue";
        auto active = worker.BeginReplySend(*sockets.Get(worker, "oom-reply"));
        ASSERT_TRUE(active) << "failed to retain pending and active UDP replies before OOM";
        EXPECT_EQ(enqueue_one(), ::app::UdpIngress::ReplyEnqueueResult::Queued) << "failed to retain pending and active UDP replies before OOM";
        size_t pending_before_failure = 1;
        bool reply_oom_observed = false;
        for (size_t attempt = 0; attempt < 250; ++attempt) {
            ::app::UdpIngress::ReplyEnqueueResult result;
            try {
                result = enqueue_with_fault();
            } catch (const std::bad_alloc&) {
                reply_oom_observed = !::common::reject_next_process_allocation;
                ::common::reject_next_process_allocation = false;
                break;
            }
            const bool fault_unused = ::common::reject_next_process_allocation;
            ::common::reject_next_process_allocation = false;
            ASSERT_EQ(result, ::app::UdpIngress::ReplyEnqueueResult::Queued);
            ASSERT_TRUE(fault_unused);
            ++pending_before_failure;
        }
        EXPECT_TRUE(reply_oom_observed) << "UDP reply queue did not exercise deque allocation failure";
        const auto before_recovery = worker.GetResourceStats();
        EXPECT_EQ(before_recovery.reply_datagrams, pending_before_failure + 1) << "UDP reply OOM changed pending or active queue accounting";
        EXPECT_EQ(before_recovery.reply_bytes, pending_before_failure + 1) << "UDP reply OOM changed pending or active queue accounting";
        EXPECT_EQ(before_recovery.active_reply_senders, 1) << "UDP reply OOM changed pending or active queue accounting";
        EXPECT_EQ(udp_budget.GetUsage().datagrams, budget_before.datagrams + pending_before_failure + 1) << "reply deque allocation failure leaked a shared payload reservation";
        EXPECT_EQ(udp_budget.GetUsage().payload_capacity, budget_before.payload_capacity +
                        (pending_before_failure + 1) * ::common::Buffer::kSize) << "reply deque allocation failure leaked a shared payload reservation";
        const auto active_buffers =
            active->SendBuffers();
        ASSERT_FALSE(active_buffers.empty()) << "UDP reply OOM changed the active datagram";
        EXPECT_EQ(static_cast<const uint8_t*>(active_buffers.front().data())[0], 0x7a) << "UDP reply OOM changed the active datagram";
        EXPECT_EQ(active->endpoint, reply_endpoint_a) << "UDP reply OOM changed the active datagram";
        EXPECT_EQ(enqueue_one(), ::app::UdpIngress::ReplyEnqueueResult::Queued) << "UDP reply queue did not recover after injected OOM";
        size_t handed_off = 0;
        auto next = worker.CompleteReplySend(*sockets.Get(worker, "oom-reply"), active->id);
        while (next) {
            ++handed_off;
            next = worker.CompleteReplySend(*sockets.Get(worker, "oom-reply"), next->id);
        }
        EXPECT_EQ(handed_off, pending_before_failure + 1) << "UDP reply queue lost a pending packet after OOM";
        active.reset();
        const auto drained_stats = worker.GetResourceStats();
        EXPECT_EQ(drained_stats.reply_datagrams, 0) << "UDP reply OOM recovery did not drain to zero";
        EXPECT_EQ(drained_stats.reply_bytes, 0) << "UDP reply OOM recovery did not drain to zero";
        EXPECT_EQ(drained_stats.active_reply_senders, 0) << "UDP reply OOM recovery did not drain to zero";
        worker.ClearReplyQueue(*sockets.Get(worker, "oom-reply"));
        EXPECT_EQ(udp_budget.GetUsage().datagrams, budget_before.datagrams) << "reply OOM recovery did not return its shared budget";
        EXPECT_EQ(udp_budget.GetUsage().payload_capacity, budget_before.payload_capacity) << "reply OOM recovery did not return its shared budget";
}

TEST_F(UdpSocketOwnerTest, InputAllocationFailureRestoresAdmissionWithoutLosingQueuedDatagrams) {
    const auto input_baseline = worker.GetResourceStats();
    const auto input_budget_baseline = udp_budget.GetUsage();
    const std::string oom_input_socket = "oom-input-socket";
    const auto oom_socket = attach_uplink_socket(oom_input_socket);
    auto oom_input_session = worker.CreateClientSession(sockets.Get(worker, oom_input_socket), ::app::ClientSessionKey{default_owner, 9},
    io_context,
    {},
    reply_endpoint_a,
    default_owner,
    std::chrono::steady_clock::now(),
    std::chrono::seconds(60));
    ASSERT_TRUE(oom_input_session) << "failed to create UDP input OOM session";
    const auto deliver_oom_input = [&]() {
        deliver_uplink(oom_input_socket, oom_socket, default_owner, 9, 0x44);
    };
    const auto queued_oom_inputs = [&]() {
        return worker.GetResourceStats().input_datagrams - input_baseline.input_datagrams;
    };
    deliver_oom_input();
    EXPECT_EQ(queued_oom_inputs(), 1) << "failed to prime UDP input OOM queue";
    size_t input_oom_items = 1;
    bool input_oom_observed = false;
    for (; input_oom_items < 250; ++input_oom_items) {
        // Decoding finishes first; the rejected allocation is the next one in
        // the delivery of an already admitted payload to the existing row.
        uplink_script.fail_next_allocation = true;
        try {
            deliver_oom_input();
        } catch (const std::bad_alloc&) {
            input_oom_observed = !::common::reject_next_process_allocation;
            ::common::reject_next_process_allocation = false;
            break;
        }
        const bool fault_unused = ::common::reject_next_process_allocation;
        ::common::reject_next_process_allocation = false;
        ASSERT_EQ(queued_oom_inputs(), input_oom_items + 1);
        ASSERT_TRUE(fault_unused);
    }
    EXPECT_TRUE(input_oom_observed) << "UDP input queue did not exercise deque allocation failure";
    auto input_stats = worker.GetResourceStats();
    EXPECT_EQ(input_stats.input_datagrams, input_baseline.input_datagrams + input_oom_items) << "UDP input OOM changed queued occupancy accounting";
    EXPECT_EQ(input_stats.input_bytes, input_baseline.input_bytes + input_oom_items) << "UDP input OOM changed queued occupancy accounting";
    EXPECT_EQ(udp_budget.GetUsage().datagrams, input_budget_baseline.datagrams + input_oom_items) << "input deque allocation failure leaked a shared payload reservation";
    EXPECT_EQ(udp_budget.GetUsage().payload_capacity, input_budget_baseline.payload_capacity +
                input_oom_items * ::common::Buffer::kSize) << "input deque allocation failure leaked a shared payload reservation";
    deliver_oom_input();
    EXPECT_EQ(queued_oom_inputs(), input_oom_items + 1) << "UDP input queue did not recover after injected OOM";
    ++input_oom_items;
    while (input_oom_items != 0) {
        bool read_ok = false;
        ::net::co_spawn(
            io_context,
            oom_input_session->ReadMultiBuffer(),
            [&](std::exception_ptr error, ::common::MultiBuffer payload) {
                read_ok = !error && payload.byte_size() == 1;
            });
        io_context.poll();
        io_context.restart();
        EXPECT_TRUE(read_ok) << "UDP input queue failed to drain after OOM recovery";
        if (!read_ok) {
            oom_input_session->Close();
            io_context.poll();
            io_context.restart();
            break;
        }
        --input_oom_items;
    }
    oom_input_session->Close();
    worker.CloseSocket(*sockets.Get(worker, oom_input_socket));
    oom_input_session.reset();
    input_stats = worker.GetResourceStats();
    EXPECT_EQ(input_stats.input_datagrams, input_baseline.input_datagrams) << "UDP input queue occupancy did not return to baseline";
    EXPECT_EQ(input_stats.input_bytes, input_baseline.input_bytes) << "UDP input queue occupancy did not return to baseline";
    EXPECT_EQ(udp_budget.GetUsage().datagrams, input_budget_baseline.datagrams) << "input OOM cleanup did not return its shared resource budget";
    EXPECT_EQ(udp_budget.GetUsage().payload_capacity, input_budget_baseline.payload_capacity) << "input OOM cleanup did not return its shared resource budget";
    EXPECT_EQ(udp_budget.GetUsage().associations, input_budget_baseline.associations) << "input OOM cleanup did not return its shared resource budget";
}
#endif

class UdpRetirementTest : public UdpSocketOwnerTest,
    public ::testing::WithParamInterface<std::tuple<int, bool, bool>> {};

TEST_P(UdpRetirementTest, ClosedAndExpiredRowsRetireWithoutDisturbingRetainedRows) {
    const auto [idle_seconds, closed, expired] = GetParam();
    const auto now = std::chrono::steady_clock::now();
    auto session = worker.CreateClientSession(sockets.Get(worker, "retirement"),
        ::app::ClientSessionKey{default_owner, 1}, io_context, {}, reply_endpoint_a,
        default_owner, expired ? now - std::chrono::seconds(2) : now,
        std::chrono::seconds(idle_seconds));
    ASSERT_NE(session, nullptr);
    if (closed) session->Close();
    io_context.run_for(std::chrono::milliseconds(150));
    io_context.restart();
    const bool retired = closed || (idle_seconds != 0 && expired);
    EXPECT_EQ(worker.GetResourceStats().associations, retired ? 0u : 1u);
    EXPECT_EQ(worker.GetResourceStats().closed_associations, 0u);
    EXPECT_EQ(session->Closed(), retired);
}
INSTANTIATE_TEST_SUITE_P(IdleAndClosureModes, UdpRetirementTest,
    ::testing::Combine(::testing::Values(0, 1), ::testing::Bool(), ::testing::Bool()));

struct DrainReplyIngress {
    ::net::io_context& io;
    ::app::UdpIngress& ingress;
    ~DrainReplyIngress() {
        ingress.RequestStop();
        io.restart();
        bool joined = false;
        ::net::co_spawn(io, ingress.AsyncJoin(), [&](std::exception_ptr failure) {
            EXPECT_FALSE(failure);
            joined = true;
        });
        io.run();
        EXPECT_TRUE(joined);
    }
};

} // namespace

TEST(UdpSocketOwner, ReplySenderDrain) {
    ::net::io_context io;
    auto& scheduler = ::transport::TimeoutScheduler::ForIoContext(io);
    ::app::UdpAssociationReclaimer reclaimer(
        scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    ::app::UdpResourceBudget budget;
    ::app::UdpIngress ingress(
        "sender-drain", std::make_unique<DummyDatagramHandler>(), reclaimer, budget, io);
    auto socket = ingress.AttachSocket(std::make_shared<::udp::socket>(io, ::udp::v4()));
    ::udp::socket peer(io, {::net::ip::address_v4::loopback(), 0});
    ::common::MultiBuffer payload;
    const std::array<uint8_t, 1> bytes{0x31};
    ASSERT_TRUE(payload.AppendSpan(bytes));
    DrainReplyIngress drain{io, ingress};
    ASSERT_TRUE(ingress.SendReply(socket, peer.local_endpoint(), std::move(payload), 0));
    EXPECT_EQ(budget.GetUsage().datagrams, 1u);
    io.poll_one();
    io.restart();
    ingress.RequestStop();
    bool joined = false;
    ::net::co_spawn(io, ingress.AsyncJoin(), [&](std::exception_ptr failure) {
        EXPECT_FALSE(failure);
        EXPECT_EQ(budget.GetUsage().datagrams, 0u);
        EXPECT_EQ(budget.GetUsage().payload_capacity, 0u);
        joined = true;
    });
    io.run();
    EXPECT_TRUE(joined);
    EXPECT_FALSE(socket->socket->is_open());
    EXPECT_EQ(socket->owner, nullptr);
}
