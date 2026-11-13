#include <stdexcept>
#include <gtest/gtest.h>

#include "app/udp_ingress.hpp"
#include "udp_ingress_fixture.hpp"
#include "worker_coordinator_fixture.hpp"
#include "app/relay.hpp"

#include "app/inbound_handler.hpp"
#include "app/request_load.hpp"
#include "app/stats.hpp"
#include "common/user_online_tracker.hpp"
#include "common/session.hpp"
#include "common/target_address.hpp"
#include "routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <initializer_list>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

// Rows a single maintenance wake may reclaim (README: bounded batch).
constexpr size_t kBatchLimit = 64;


class DummyInbound : public ::proxy::Inbound {
public:
    ::net::awaitable<::app::RelayResult> Process(
        std::unique_ptr<::transport::AsyncStream>, ::routing::Dispatcher&,
        const ::app::ReceiverSettings&, ::net::io_context&,
        ::common::Context&, const ::infra::TimeoutsConfig&, uint32_t) override {
        co_return ::app::RelayResult{};
    }

    tl::expected<::proxy::InboundDatagramResult, ::common::ErrorCode> Process(
        const ::proxy::InboundDatagramRequest&) override {
        return tl::unexpected(::common::ErrorCode::PROTOCOL_AUTH_FAILED);
    }
};

using Ingress = ::app::UdpIngress;
using Reclaimer = ::app::UdpAssociationReclaimer;
using SessionPtr = Ingress::ClientSessionPtr;

struct ReenterOnCancel {
    Ingress* ingress = nullptr;
    UdpSocketFixtures* sockets = nullptr;
    std::string key;
    bool close_all = false;
    size_t calls = 0;

    void Cancel() noexcept {
        ++calls;
        const auto close = [&](std::string_view name) {
            if (auto socket = sockets->Find(*ingress, name)) {
                if (auto state = sockets->Find(*ingress, socket.get()))
                    ingress->CloseSocket(*state);
            }
        };
        if (close_all) {
            close("all-a");
            close("all-b");
        } else close(key);
    }
};

struct ReentryCancellation final : ::transport::CancellationSubscription {
    explicit ReentryCancellation(ReenterOnCancel& owner) noexcept : owner(owner) {}
    ReenterOnCancel& owner;
private:
    void OnCancellation(::transport::Cancellation) noexcept override {
        owner.Cancel();
    }
};

class DatagramResponse final : public ::proxy::InboundDatagramResponse {
public:
    ::common::MultiBuffer Encode(::proxy::UDPPacketView) override { return {}; }
};

class AcceptedReplyResponse final : public ::proxy::InboundDatagramResponse {
public:
    ::common::MultiBuffer Encode(::proxy::UDPPacketView packet) override {
        ::common::MultiBuffer result;
        if (!result.AppendSpan(packet.data)) throw std::bad_alloc();
        return result;
    }
};


// Decodes every datagram as owner 0x71 carrying one 0x42 byte; a first byte of
// 0x43 selects protocol session 2, anything else session 1.
class DatagramInbound final : public DummyInbound {
public:
    tl::expected<::proxy::InboundDatagramResult, ::common::ErrorCode> Process(
        const ::proxy::InboundDatagramRequest& request) override {
        ::proxy::InboundDatagramResult result;
        result.user = &profile_;
        const std::array<uint8_t, 1> owner{0x71};
        if (!result.session_owner.Assign(owner)) {
            return tl::unexpected(::common::ErrorCode::RESOURCE_EXHAUSTED);
        }
        result.session_id = !request.payload.empty() && request.payload[0] == 0x43 ? 2 : 1;
        result.target = ::common::TargetAddress(
            ::net::ip::address_v4::loopback(), 53);
        ::common::BufferGuard payload{::common::Buffer::New()};
        if (!payload) return tl::unexpected(::common::ErrorCode::RESOURCE_EXHAUSTED);
        payload->Tail()[0] = 0x42;
        payload->Produce(1);
        result.payload.push_back(std::move(payload));
        return result;
    }
    tl::expected<std::shared_ptr<::proxy::InboundDatagramResponse>, ::common::ErrorCode>
    CreateDatagramResponse(const ::proxy::InboundDatagramResult&) override {
        return std::make_shared<DatagramResponse>();
    }
private:
    ::common::UserProfile profile_;
};

bool IsDecodedPayload(const ::common::MultiBuffer& payload) {
    const auto bytes = payload.FrontSpan();
    return bytes.size() == 1 && bytes[0] == 0x42;
}

// The reader of a dispatched native request is the association's session.
class DatagramDispatcher final : public ::routing::Dispatcher {
public:
    unsigned dispatched = 0;
    unsigned packets_read = 0;
    const ::transport::MultiBufferReader* last_reader = nullptr;
    ::net::awaitable<::app::RelayResult> Dispatch(
        ::net::io_context&, const ::routing::DispatchPolicy&,
        std::unique_ptr<::transport::AsyncStream>, ::transport::Link link,
        ::common::InitialPayload, ::common::Context&, ::app::StatsShard&,
        const ::infra::TimeoutsConfig&) override {
        ++dispatched;
        EXPECT_NE(link.reader, nullptr);
        if (!link.reader) co_return ::app::RelayResult{};
        last_reader = link.reader;
        auto payload = co_await link.reader->ReadMultiBuffer();
        EXPECT_TRUE(IsDecodedPayload(payload)) << "rebuilt native request did not receive exactly its decoded first packet";
        ++packets_read;
        co_return ::app::RelayResult{};
    }
};


// Everything ProcessDatagram needs besides the ingress, socket and packet.
struct DatagramSource {
    explicit DatagramSource(::net::io_context& io)
        : coordinator(io),
          limiter(::app::ConnectionLimiter::Acquire({}, coordinator.Get())),
          online_users(*coordinator.Get()) {
        coordinator.Get()->RegisterWorker();
    }
    WorkerCoordinatorFixture coordinator;
    std::shared_ptr<::app::ConnectionLimiter> limiter;
    ::common::UserOnlineTracker online_users;
    DatagramDispatcher dispatcher;
    ::app::StatsShard stats;
    const ::app::AdmissionEnvironment admission{
        *coordinator.Get(), *limiter, online_users, stats};
    ::app::RequestLoadState request_load{1024, 0};
    ::app::ReceiverSettings receiver{
        .inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {},
        .dispatch_policy = {.sniffing = {}, .outbound = ::routing::ForceOutbound{"loopback"}}};

    void Send(UdpSocketFixtures& sockets, Ingress& ingress, ::net::io_context& io, std::string_view,
              ::udp::socket* sock, uint16_t client_port,
              std::span<const uint8_t> packet, const ::infra::TimeoutsConfig& timeouts) {
        const ::app::DatagramSessionEnvironment environment{
            .timeouts = timeouts, .dispatcher = &dispatcher,
            .admission = &admission, .request_load = &request_load};
        ingress.ProcessDatagram(::app::UdpDatagramContext{
            .socket = sockets.Find(ingress, sock).get(),
            .client_endpoint = {::net::ip::address_v4::loopback(), client_port},
            .payload = packet,
            .receiver = &receiver,
            .io_context = io,
            .environment = environment,
        });
    }
};

::net::awaitable<void> ReadDecodedPayload(SessionPtr session, std::shared_ptr<bool> received) {
    auto payload = co_await session->ReadMultiBuffer();
    *received = IsDecodedPayload(payload);
}

::app::ClientSessionKey Key(uint64_t id) {
    ::proxy::InboundDatagramOwner owner;
    const std::array<uint8_t, 1> bytes{0x71};
    if (!owner.Assign(bytes)) throw std::runtime_error("failed to prepare typed session owner");
    return {owner, id};
}

SessionPtr MakeSession(UdpSocketFixtures& sockets, Ingress& ingress, ::net::io_context& io,
                       std::string socket_key, ::app::ClientSessionKey client_key,
                       Clock::time_point last_active,
                       std::chrono::seconds idle_timeout) {
    auto session = ingress.CreateClientSession(sockets.Get(ingress, socket_key), client_key, io,
        {}, {::net::ip::address_v4::loopback(), 10001}, client_key.owner, last_active, idle_timeout);
    if (!session) throw std::runtime_error("failed to prepare UDP session");
    return session;
}

Ingress::SocketPtr AttachOpenSocket(UdpSocketFixtures& sockets, Ingress& ingress, ::net::io_context& io,
                                    std::string_view socket_key) {
    auto socket = Ingress::MakeSocket(io);
    ::IoErrorCode ec;
    socket->open(::udp::v4(), ec);
    if (ec || !sockets.Attach(ingress, socket_key, socket))
        throw std::runtime_error("failed to attach an open UDP socket");
    return socket;
}

size_t Associations(std::initializer_list<const Ingress*> ingresses) {
    size_t total = 0;
    for (const auto* ingress : ingresses) total += ingress->GetResourceStats().associations;
    return total;
}

size_t ActiveEvents(const ::transport::TimeoutScheduler& scheduler) {
    return scheduler.GetResourceStats().active_events;
}

void RunFor(::net::io_context& io, std::chrono::milliseconds duration) {
    io.run_for(duration);
    io.restart();
}

// Runs handlers until `done` holds or the generous bound elapses.
template <class Done>
bool RunUntil(::net::io_context& io, Done done, std::chrono::milliseconds limit = 5000ms) {
    const auto deadline = Clock::now() + limit;
    while (!done()) {
        if (Clock::now() >= deadline) return false;
        if (io.stopped()) io.restart();
        io.run_one_for(10ms);
    }
    if (io.stopped()) io.restart();
    return true;
}

// Executes one handler at a time until `count()` reaches `target`. Fails if a
// single handler reclaims more than one batch. `after_batch` runs after every
// handler that reclaimed rows.
template <class Count, class AfterBatch>
bool StepReclaimBatches(::net::io_context& io, Count count, size_t target,
                        AfterBatch after_batch, size_t& reclaiming_handlers) {
    const auto deadline = Clock::now() + 5000ms;
    size_t current = count();
    while (current > target) {
        if (Clock::now() >= deadline) return false;
        if (io.stopped()) io.restart();
        if (io.run_one_for(10ms) == 0) continue;
        const size_t next = count();
        EXPECT_LE(next, current);
        if (next > current) return false;
        EXPECT_LE(current - next, kBatchLimit);
        if (next != current) {
            ++reclaiming_handlers;
            after_batch();
        }
        current = next;
    }
    if (io.stopped()) io.restart();
    return true;
}

class UdpAssociationReclaimerTest : public ::testing::Test {
protected:
    ::net::io_context io;
    UdpSocketFixtures sockets{io};
    ::transport::TimeoutScheduler& scheduler = ::transport::TimeoutScheduler::ForIoContext(io);
    const size_t idle_events = ActiveEvents(scheduler);
    Reclaimer reclaimer{scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); }};
    ::app::UdpResourceBudget budget;
    Ingress first{"first", std::make_unique<DummyInbound>(), reclaimer, budget, io};
    Ingress second{"second", std::make_unique<DummyInbound>(), reclaimer, budget, io};
    const Clock::time_point now = Clock::now();
    ~UdpAssociationReclaimerTest() override {
        first.RequestStop();
        second.RequestStop();
        reclaimer.Stop();
        io.restart();
        io.run();
    }
};

// Native dispatch and reply jobs must finish before their local ingress dies.
struct DrainIngress {
    ::net::io_context& io;
    Ingress& ingress;
    ~DrainIngress() {
        ingress.RequestStop();
        io.restart();
        io.run();
    }
};
} // namespace

TEST_F(UdpAssociationReclaimerTest, ClosedRowsYieldBetweenWorkerWideBatches) {
    // Many map insertions force rehashes while hooks remain embedded in nodes.
    // Closed rows across both ingresses share one Worker-wide batch bound.
    std::vector<SessionPtr> closed_sessions;
    closed_sessions.reserve(130);
    for (size_t i = 0; i < 65; ++i) {
        auto one = MakeSession(sockets, first, io, "batch", Key(i), now, 0s);
        auto two = MakeSession(sockets, second, io, "batch", Key(i), now, 0s);
        ASSERT_TRUE(one) << "failed to create batch associations";
        ASSERT_TRUE(two) << "failed to create batch associations";
        one->Close();
        two->Close();
        closed_sessions.push_back(std::move(one));
        closed_sessions.push_back(std::move(two));
    }
    EXPECT_EQ(Associations({&first, &second}), 130) << "closed associations were removed before the maintenance wake ran";
    EXPECT_EQ(ActiveEvents(scheduler), idle_events + 1) << "closed associations did not arm exactly one maintenance event";
    bool loop_progress = false;
    bool progress_posted = false;
    size_t associations_at_progress = 0;
    size_t batch_handlers = 0;
    const auto batch_count = [&] { return Associations({&first, &second}); };
    EXPECT_TRUE(StepReclaimBatches(io, batch_count, 0, [&] {
                if (progress_posted) return;
                progress_posted = true;
                asio::post(io, [&] {
                    loop_progress = true;
                    associations_at_progress = batch_count();
                });
            }, batch_handlers)) << "UDP reclaimer did not enforce the shared 64-row batch limit";
    EXPECT_GE(batch_handlers, (130 + kBatchLimit - 1) / kBatchLimit) << "UDP reclaimer drained more than one batch per maintenance wake";
    EXPECT_TRUE(loop_progress) << "event loop did not progress between bounded UDP maintenance batches";
    EXPECT_NE(associations_at_progress, 0) << "event loop did not progress between bounded UDP maintenance batches";
    EXPECT_EQ(ActiveEvents(scheduler), idle_events) << "drained reclaimer kept a maintenance event armed";
    closed_sessions.clear();
}

TEST_F(UdpAssociationReclaimerTest, IdleDisabledRowsDoNotConsumeReclaimBatches) {
    // Open rows with idle expiry disabled never become due, so they neither
    // consume batch budget nor keep the maintenance event armed.
    std::vector<SessionPtr> mixed_live;
    std::vector<SessionPtr> mixed_closed;
    mixed_live.reserve(65);
    mixed_closed.reserve(65);
    for (size_t i = 0; i < 65; ++i) {
        auto closed = MakeSession(sockets, first, io, "mixed", Key(i), now, 0s);
        auto live = MakeSession(sockets, second, io, "mixed", Key(i), now, 0s);
        ASSERT_TRUE(closed) << "failed to create mixed associations";
        ASSERT_TRUE(live) << "failed to create mixed associations";
        closed->Close();
        mixed_closed.push_back(std::move(closed));
        mixed_live.push_back(std::move(live));
    }
    size_t mixed_handlers = 0;
    EXPECT_TRUE(StepReclaimBatches(io, [&] { return Associations({&first, &second}); }, 65,
                                [] {}, mixed_handlers)) << "mixed live/closed associations did not progress across bounded batches";
    EXPECT_GE(mixed_handlers, 2) << "mixed live/closed associations did not progress across bounded batches";
    EXPECT_EQ(first.GetResourceStats().associations, 0) << "mixed live/closed associations did not progress across bounded batches";
    EXPECT_EQ(second.GetResourceStats().associations, 65) << "mixed live/closed associations did not progress across bounded batches";
    EXPECT_EQ(ActiveEvents(scheduler), idle_events) << "open associations with idle expiry disabled armed a maintenance event";
    for (const auto& live : mixed_live) {
        EXPECT_FALSE(live->Closed()) << "maintenance closed an open association with idle expiry disabled";
    }
    second.CleanupAllClientSessions();
    EXPECT_EQ(second.GetResourceStats().associations, 0) << "live mixed rows remained registered";
    mixed_live.clear();
    mixed_closed.clear();
}

TEST_F(UdpAssociationReclaimerTest, ReclaimsRowsBeforeExternalSessionRelease) {
    // Removing a row is independent of the lifetime of an externally held session.
    Ingress detached_ingress("detached", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto detached = MakeSession(sockets, detached_ingress, io, "detached", Key(1), now, 0s);
    std::weak_ptr<Ingress::ClientSession> detached_weak = detached;
    detached->Close();
    EXPECT_TRUE(RunUntil(io, [&] { return detached_ingress.GetResourceStats().associations == 0; })) << "row reclamation was incorrectly coupled to external session lifetime";
    EXPECT_FALSE(detached_weak.expired()) << "row reclamation was incorrectly coupled to external session lifetime";
    detached.reset();
    EXPECT_TRUE(detached_weak.expired()) << "released detached UDP session remained alive";
}

TEST_F(UdpAssociationReclaimerTest, IdleDisabledRowsRetireOnlyAfterClose) {
    Ingress disabled_ingress("disabled", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto disabled_open = MakeSession(sockets, disabled_ingress, io, "disabled", Key(1), now, 0s);
    RunFor(io, 20ms);
    EXPECT_EQ(disabled_ingress.GetResourceStats().associations, 1) << "zero idle timeout did not retain an open UDP association";
    EXPECT_FALSE(disabled_open->Closed()) << "zero idle timeout did not retain an open UDP association";
    disabled_open->Close();
    EXPECT_TRUE(RunUntil(io, [&] { return disabled_ingress.GetResourceStats().associations == 0; })) << "closed UDP association was retained with idle timeout disabled";
}

TEST_F(UdpAssociationReclaimerTest, IdleExpiryAllowsSynchronousSocketRetirement) {
    // Idle expiry closes the session; its cancellation may synchronously
    // retire the socket that owns the expiring row.
    Ingress idle_ingress("idle", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto idle_socket = AttachOpenSocket(sockets, idle_ingress, io, "idle");
    auto idle = MakeSession(sockets, idle_ingress, io, "idle", Key(1), Clock::now() - 2s, 1s);
    ReenterOnCancel expiry_reentry{.ingress = &idle_ingress, .sockets = &sockets, .key = "idle"};
    ReentryCancellation expiry_subscription(expiry_reentry);
    expiry_subscription.Resubscribe(idle->Cancellation());
    EXPECT_TRUE(idle_ingress.ReplaceHandler(std::make_unique<DummyInbound>())) << "UDP handler replacement was rejected";
    EXPECT_TRUE(RunUntil(io, [&] { return idle->Closed(); })) << "natural expiry reentry did not safely retire the association and socket";
    EXPECT_EQ(idle_ingress.GetResourceStats().associations, 0) << "natural expiry reentry did not safely retire the association and socket";
    EXPECT_EQ(expiry_reentry.calls, 1) << "natural expiry reentry did not safely retire the association and socket";
    EXPECT_FALSE(sockets.Find(idle_ingress, "idle")) << "natural expiry reentry did not safely retire the association and socket";
}

TEST_F(UdpAssociationReclaimerTest, DownlinkDoesNotRefreshIdleDeadline) {
    // Downlink traffic does not refresh idle time: the row still expires at
    // its original deadline, well before a refreshed deadline could pass.
    ::common::TargetAddress target;
    target.type = ::common::AddressType::IPv4;
    target.resolved_addr = ::net::ip::address_v4::loopback();
    target.port = 53;
    Ingress downlink_ingress("downlink", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto downlink_socket = sockets.Get(downlink_ingress, "activity");
    downlink_socket->socket->open(::udp::v4());
    auto accepted_reply = std::make_shared<AcceptedReplyResponse>();
    ::udp::socket peer(io, {::net::ip::address_v4::loopback(), 0});
    peer.non_blocking(true);
    constexpr auto downlink_idle = 2s;
    auto downlink = downlink_ingress.CreateClientSession(sockets.Get(downlink_ingress, "activity"), Key(1), io,
    {.socket = downlink_socket, .response = accepted_reply, .owner = &downlink_ingress},
    peer.local_endpoint(), Key(1).owner,
    Clock::now() - downlink_idle + 200ms, downlink_idle);
    ASSERT_NE(downlink, nullptr);
    ::common::BufferGuard reply{::common::Buffer::New()};
    ASSERT_TRUE(reply) << "failed to allocate UDP downlink activity payload";
    reply->Tail()[0] = 2;
    reply->Produce(1);
    reply->SetUDP(target);
    bool reply_completed = false;
    DrainIngress drain{io, downlink_ingress};
    ::net::co_spawn(io,
        downlink->WriteMultiBuffer(::common::MultiBuffer{std::move(reply)}),
        [&](std::exception_ptr error) {
            EXPECT_FALSE(error);
            reply_completed = true;
        });
    EXPECT_TRUE(RunUntil(io, [&] { return reply_completed; })) << "UDP downlink write did not complete";
    const auto downlink_written = Clock::now();
    std::array<uint8_t, 1> received{};
    ::udp::endpoint sender;
    size_t received_size = 0;
    ASSERT_TRUE(RunUntil(io, [&] {
        ::IoErrorCode error;
        received_size = peer.receive_from(::net::buffer(received), sender, 0, error);
        return !error;
    }));
    EXPECT_EQ(received_size, 1u);
    EXPECT_EQ(received[0], 2);
    EXPECT_TRUE(RunUntil(io, [&] { return downlink->Closed(); })) << "UDP downlink traffic incorrectly refreshed association idle time";
    EXPECT_LT(Clock::now() - downlink_written, downlink_idle) << "UDP downlink traffic incorrectly refreshed association idle time";
    EXPECT_EQ(downlink_ingress.GetResourceStats().associations, 0) << "UDP downlink traffic incorrectly refreshed association idle time";
    downlink.reset();
}

TEST_F(UdpAssociationReclaimerTest, UplinkRefreshesAndRearmsIdleDeadline) {
    // Valid uplink only moves last activity. When the original deadline passes
    // the row is re-checked and re-armed; it expires one idle period after the
    // uplink, not before.
    Ingress activity_ingress("activity", std::make_unique<DatagramInbound>(), reclaimer, budget, io);
    auto activity_socket = AttachOpenSocket(sockets, activity_ingress, io, "activity");
    DatagramSource activity_source{io};
    DrainIngress drain{io, activity_ingress};
    ::infra::TimeoutsConfig activity_timeouts;
    activity_timeouts.idle = 1;
    constexpr auto uplink_idle = 1s;
    auto uplink = MakeSession(sockets, activity_ingress, io, "activity", Key(1),
                              Clock::now() - uplink_idle + 300ms, uplink_idle);
    const std::array<uint8_t, 1> uplink_packet{0x42};
    const auto uplink_sent = Clock::now();
    activity_source.Send(sockets, activity_ingress, io, "activity", activity_socket.get(), 10002,
                         uplink_packet, activity_timeouts);
    const auto uplink_stats = activity_ingress.GetResourceStats();
    EXPECT_EQ(uplink_stats.associations, 1) << "UDP uplink was not delivered to its existing association";
    EXPECT_EQ(uplink_stats.input_datagrams, 1) << "UDP uplink was not delivered to its existing association";
    EXPECT_EQ(uplink_stats.input_bytes, 1) << "UDP uplink was not delivered to its existing association";
    EXPECT_EQ(uplink_stats.native_dispatches, 0) << "UDP uplink was not delivered to its existing association";
    auto uplink_received = std::make_shared<bool>(false);
    ::net::co_spawn(io, ReadDecodedPayload(uplink, uplink_received), asio::detached);
    RunFor(io, 600ms);
    EXPECT_TRUE(*uplink_received) << "UDP uplink activity did not refresh association idle time";
    EXPECT_FALSE(uplink->Closed()) << "UDP uplink activity did not refresh association idle time";
    EXPECT_EQ(activity_ingress.GetResourceStats().associations, 1) << "UDP uplink activity did not refresh association idle time";
    EXPECT_TRUE(RunUntil(io, [&] { return uplink->Closed(); })) << "refreshed UDP association was not re-armed to expire after its idle period";
    EXPECT_GE(Clock::now() - uplink_sent, uplink_idle) << "refreshed UDP association was not re-armed to expire after its idle period";
    EXPECT_EQ(activity_ingress.GetResourceStats().associations, 0) << "refreshed UDP association was not re-armed to expire after its idle period";
    uplink.reset();
}

TEST_F(UdpAssociationReclaimerTest, SameKeyReplacementAllowsCancellationReentry) {
    // Closing the replaced session re-enters CloseSocket and retires the replacement.
    Ingress replace_ingress("replace", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto replace_socket = AttachOpenSocket(sockets, replace_ingress, io, "replace");
    auto prior = MakeSession(sockets, replace_ingress, io, "replace", Key(1), now, 0s);
    ReenterOnCancel replacement_reentry{.ingress = &replace_ingress, .sockets = &sockets, .key = "replace"};
    ReentryCancellation replacement_subscription(replacement_reentry);
    replacement_subscription.Resubscribe(prior->Cancellation());
    auto replacement = MakeSession(sockets, replace_ingress, io, "replace", Key(1), Clock::now(), 0s);
    ASSERT_TRUE(replacement) << "same-key replacement was unsafe under synchronous cancellation reentry";
    EXPECT_NE(replacement, prior) << "same-key replacement was unsafe under synchronous cancellation reentry";
    EXPECT_TRUE(prior->Closed()) << "same-key replacement was unsafe under synchronous cancellation reentry";
    EXPECT_TRUE(replacement->Closed()) << "same-key replacement was unsafe under synchronous cancellation reentry";
    EXPECT_EQ(replace_ingress.GetResourceStats().associations, 0) << "same-key replacement was unsafe under synchronous cancellation reentry";
    EXPECT_EQ(replacement_reentry.calls, 1) << "same-key replacement was unsafe under synchronous cancellation reentry";
    EXPECT_FALSE(sockets.Find(replace_ingress, "replace")) << "same-key replacement was unsafe under synchronous cancellation reentry";
}

TEST_F(UdpAssociationReclaimerTest, BulkCleanupAllowsCancellationReentry) {
    Ingress bulk_ingress("bulk", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto bulk_socket = AttachOpenSocket(sockets, bulk_ingress, io, "bulk");
    auto bulk_a = MakeSession(sockets, bulk_ingress, io, "bulk", Key(1), now, 0s);
    auto bulk_b = MakeSession(sockets, bulk_ingress, io, "bulk", Key(2), now, 0s);
    ReenterOnCancel bulk_reentry_a{.ingress = &bulk_ingress, .sockets = &sockets, .key = "bulk"};
    ReenterOnCancel bulk_reentry_b{.ingress = &bulk_ingress, .sockets = &sockets, .key = "bulk"};
    ReentryCancellation bulk_subscription_a(bulk_reentry_a);
    ReentryCancellation bulk_subscription_b(bulk_reentry_b);
    bulk_subscription_a.Resubscribe(bulk_a->Cancellation());
    bulk_subscription_b.Resubscribe(bulk_b->Cancellation());
    EXPECT_EQ(bulk_ingress.GetResourceStats().associations, 2) << "bulk associations were not registered";
    bulk_ingress.CleanupClientSessions(*sockets.Get(bulk_ingress, "bulk"));
    EXPECT_EQ(bulk_ingress.GetResourceStats().associations, 0) << "bulk cleanup was unsafe under synchronous cancellation reentry";
    EXPECT_TRUE(bulk_a->Closed()) << "bulk cleanup was unsafe under synchronous cancellation reentry";
    EXPECT_TRUE(bulk_b->Closed()) << "bulk cleanup was unsafe under synchronous cancellation reentry";
    EXPECT_EQ(bulk_reentry_a.calls, 1) << "bulk cleanup was unsafe under synchronous cancellation reentry";
    EXPECT_EQ(bulk_reentry_b.calls, 1) << "bulk cleanup was unsafe under synchronous cancellation reentry";
    EXPECT_FALSE(sockets.Find(bulk_ingress, "bulk")) << "bulk cleanup was unsafe under synchronous cancellation reentry";
}

TEST_F(UdpAssociationReclaimerTest, StopAllowsReentrantRetirementOfAllSockets) {
    Ingress all_ingress("all", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto all_socket_a = AttachOpenSocket(sockets, all_ingress, io, "all-a");
    auto all_socket_b = AttachOpenSocket(sockets, all_ingress, io, "all-b");
    auto all_session = MakeSession(sockets, all_ingress, io, "all-a", Key(1), now, 0s);
    ReenterOnCancel all_reentry{.ingress = &all_ingress, .sockets = &sockets, .key = {}, .close_all = true};
    ReentryCancellation all_subscription(all_reentry);
    all_subscription.Resubscribe(all_session->Cancellation());
    all_ingress.RequestStop();
    EXPECT_FALSE(sockets.Find(all_ingress, "all-a")) << "CloseAllSockets used an invalid borrowed key after reentry";
    EXPECT_FALSE(sockets.Find(all_ingress, "all-b")) << "CloseAllSockets used an invalid borrowed key after reentry";
    EXPECT_TRUE(all_session->Closed()) << "CloseAllSockets used an invalid borrowed key after reentry";
    EXPECT_EQ(all_reentry.calls, 1) << "CloseAllSockets used an invalid borrowed key after reentry";
    EXPECT_EQ(all_ingress.GetResourceStats().associations, 0) << "CloseAllSockets used an invalid borrowed key after reentry";
}

TEST_F(UdpAssociationReclaimerTest, SocketRetirementUnlinksEveryAssociation) {
    // Socket retirement must unlink every row before its map disappears.
    Ingress retire_ingress("retire", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto retire_socket = AttachOpenSocket(sockets, retire_ingress, io, "retire");
    auto retire_a = MakeSession(sockets, retire_ingress, io, "retire", Key(1), now, 0s);
    auto retire_b = MakeSession(sockets, retire_ingress, io, "retire", Key(2), now, 0s);
    EXPECT_EQ(retire_ingress.GetResourceStats().associations, 2) << "retire rows were not registered";
    retire_ingress.CloseSocket(*sockets.Get(retire_ingress, "retire"));
    EXPECT_EQ(retire_ingress.GetResourceStats().associations, 0) << "socket retirement left an association row registered";
    EXPECT_FALSE(sockets.Find(retire_ingress, "retire")) << "socket retirement left an association row registered";
    retire_a.reset();
    retire_b.reset();
    RunFor(io, 20ms);
}

TEST_F(UdpAssociationReclaimerTest, SocketRetirementDisarmsDueRows) {
    // A due closed row unlinked by CloseSocket before its wake runs must not
    // be visited, and its now-empty reclaimer must disarm.
    Reclaimer cursor_reclaimer(scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    Ingress cursor_ingress("cursor", std::make_unique<DummyInbound>(), cursor_reclaimer, budget, io);
    auto cursor_socket = AttachOpenSocket(sockets, cursor_ingress, io, "cursor-key");
    const size_t events_before_cursor = ActiveEvents(scheduler);
    auto cursor_row = MakeSession(sockets, cursor_ingress, io, "cursor-key", Key(1), now, 0s);
    EXPECT_EQ(ActiveEvents(scheduler), events_before_cursor) << "open association with idle expiry disabled armed a maintenance event";
    cursor_row->Close();
    EXPECT_EQ(ActiveEvents(scheduler), events_before_cursor + 1) << "closed association was not marked due for the next maintenance wake";
    EXPECT_EQ(cursor_ingress.GetResourceStats().associations, 1) << "closed association was not marked due for the next maintenance wake";
    cursor_ingress.CloseSocket(*sockets.Get(cursor_ingress, "cursor-key"));
    EXPECT_EQ(cursor_ingress.GetResourceStats().associations, 0) << "CloseSocket did not unlink the due reclaimer row";
    EXPECT_EQ(ActiveEvents(scheduler), events_before_cursor) << "CloseSocket did not unlink the due reclaimer row";
    RunFor(io, 50ms);
    EXPECT_EQ(cursor_ingress.GetResourceStats().associations, 0) << "retired reclaimer row was visited after socket close";
    cursor_row.reset();
    cursor_ingress.RequestStop();
    cursor_reclaimer.Stop();
}

TEST_F(UdpAssociationReclaimerTest, StopCancelsMaintenanceWithoutClosingRows) {
    // One event per reclaimer: idle-disabled open rows arm nothing, the first
    // expiring row arms the event and an earlier deadline reuses it.
    Reclaimer stopped_reclaimer(scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    Ingress stopped_ingress("stopped", std::make_unique<DummyInbound>(), stopped_reclaimer, budget, io);
    const size_t events_before_stop = ActiveEvents(scheduler);
    auto never_expiring = MakeSession(sockets, stopped_ingress, io, "stopped-key", Key(1), Clock::now(), 0s);
    EXPECT_EQ(ActiveEvents(scheduler), events_before_stop) << "open association with idle expiry disabled armed a maintenance event";
    auto later_expiring = MakeSession(sockets, stopped_ingress, io, "stopped-key", Key(2), Clock::now(), 1s);
    EXPECT_EQ(ActiveEvents(scheduler), events_before_stop + 1) << "expiring association did not arm exactly one maintenance event";
    auto due_row = MakeSession(sockets, stopped_ingress, io, "stopped-key", Key(3), Clock::now() - 2s, 1s);
    EXPECT_EQ(ActiveEvents(scheduler), events_before_stop + 1) << "an earlier association deadline armed a second maintenance event";
    stopped_reclaimer.Stop();
    EXPECT_EQ(ActiveEvents(scheduler), events_before_stop) << "Stop did not cancel the pending association event";
    RunFor(io, 50ms);
    EXPECT_EQ(stopped_ingress.GetResourceStats().associations, 3) << "stopped reclaimer processed a due association";
    EXPECT_FALSE(due_row->Closed()) << "stopped reclaimer processed a due association";
    EXPECT_FALSE(later_expiring->Closed()) << "stopped reclaimer processed a due association";
    EXPECT_FALSE(never_expiring->Closed()) << "stopped reclaimer processed a due association";
    stopped_ingress.RequestStop();
    RunFor(io, 20ms);
    EXPECT_EQ(stopped_ingress.GetResourceStats().associations, 0) << "owner cleanup after Stop left an association registered";
    EXPECT_EQ(ActiveEvents(scheduler), events_before_stop) << "owner cleanup after Stop left an association registered";
    never_expiring.reset();
    later_expiring.reset();
    due_row.reset();
}

TEST_F(UdpAssociationReclaimerTest, EmptyGroupRetiresBeforeExternalSessionRelease) {
    Reclaimer allocation_reclaimer(scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    Ingress allocation_ingress("allocation", std::make_unique<DummyInbound>(), allocation_reclaimer, budget, io);
    const std::string long_socket_key(4096, 'k');
    auto allocation_row = MakeSession(sockets, allocation_ingress, io, long_socket_key, Key(1), Clock::now() - 2s, 1s);
    std::weak_ptr<Ingress::ClientSession> allocation_weak = allocation_row;
    EXPECT_TRUE(RunUntil(io, [&] { return allocation_ingress.GetResourceStats().associations == 0; })) << "expired association in an otherwise empty group was not reclaimed";
    EXPECT_TRUE(allocation_row->Closed()) << "empty association group did not retire independently of session lifetime";
    EXPECT_FALSE(allocation_weak.expired()) << "empty association group did not retire independently of session lifetime";
    allocation_row.reset();
    EXPECT_TRUE(allocation_weak.expired()) << "released empty-group session remained alive";
    allocation_ingress.RequestStop();
    allocation_reclaimer.Stop();
}

class UdpStoredTimeoutTest : public UdpAssociationReclaimerTest,
    public ::testing::WithParamInterface<bool> {};

TEST_P(UdpStoredTimeoutTest, SameKeyRequestsUseStoredTimeoutRatherThanPacketSnapshot) {
    const bool expired = GetParam();
    Ingress ingress("request", std::make_unique<DatagramInbound>(), reclaimer, budget, io);
    DatagramSource source{io};
    DrainIngress drain{io, ingress};
    auto socket = AttachOpenSocket(sockets, ingress, io, "request");
    auto prior = MakeSession(sockets, ingress, io, "request", Key(1), Clock::now() - 2s,
        expired ? 1s : 0s);
    ASSERT_NE(prior, nullptr);
    ::infra::TimeoutsConfig packet_timeouts;
    packet_timeouts.idle = expired ? 0 : 1;
    const std::array<uint8_t, 1> packet{0x42};
    source.Send(sockets, ingress, io, "request", socket.get(), 20001, packet, packet_timeouts);
    EXPECT_EQ(prior->Closed(), expired);
    EXPECT_EQ(ingress.GetResourceStats().associations, 1u);
    EXPECT_EQ(ingress.GetResourceStats().native_dispatches, expired ? 1u : 0u);
    auto received = std::make_shared<bool>(false);
    if (!expired) ::net::co_spawn(io, ReadDecodedPayload(prior, received), asio::detached);
    io.poll();
    io.restart();
    EXPECT_EQ(source.dispatcher.dispatched, expired ? 1u : 0u);
    EXPECT_EQ(source.dispatcher.packets_read, expired ? 1u : 0u);
    if (expired) {
        EXPECT_NE(source.dispatcher.last_reader, nullptr);
        EXPECT_NE(source.dispatcher.last_reader, prior.get());
    } else {
        EXPECT_TRUE(*received);
        EXPECT_FALSE(prior->Closed());
    }
}

INSTANTIATE_TEST_SUITE_P(StoredIdleMode, UdpStoredTimeoutTest, ::testing::Bool());

TEST_F(UdpAssociationReclaimerTest, CurrentKeyExpiryDoesNotRebuildRetiredSocket) {
    Ingress request_ingress("request", std::make_unique<DatagramInbound>(),
                            reclaimer, budget, io);
    DatagramSource request_source{io};
    DrainIngress drain{io, request_ingress};
    ::infra::TimeoutsConfig packet_timeouts;
    const std::array<uint8_t, 1> request_packet{0x42};
    auto request_socket = AttachOpenSocket(sockets, request_ingress, io, "request");
    const auto scoped_key = Key(1);
    // Expiring the current key can synchronously retire the original socket.
    // Do not recreate a row or launch a request for that retired identity.
    auto retiring_current_key = MakeSession(sockets, request_ingress, io, "request", scoped_key, Clock::now() - 2s, 1s);
    ReenterOnCancel retiring_key_reentry{.ingress = &request_ingress, .sockets = &sockets, .key = "request"};
    ReentryCancellation retiring_key_subscription(retiring_key_reentry);
    retiring_key_subscription.Resubscribe(retiring_current_key->Cancellation());
    request_source.Send(sockets, request_ingress, io, "request", request_socket.get(), 20001,
                        request_packet, packet_timeouts);
    io.poll();
    io.restart();
    EXPECT_EQ(retiring_key_reentry.calls, 1) << "current-key expiry recreated a request for its synchronously retired socket";
    EXPECT_FALSE(request_socket->is_open()) << "current-key expiry recreated a request for its synchronously retired socket";
    EXPECT_TRUE(retiring_current_key->Closed()) << "current-key expiry recreated a request for its synchronously retired socket";
    EXPECT_EQ(request_ingress.GetResourceStats().associations, 0) << "current-key expiry recreated a request for its synchronously retired socket";
    EXPECT_EQ(request_ingress.GetResourceStats().native_dispatches, 0) << "current-key expiry recreated a request for its synchronously retired socket";
    EXPECT_EQ(request_source.dispatcher.dispatched, 0) << "current-key expiry recreated a request for its synchronously retired socket";
    EXPECT_EQ(request_source.dispatcher.packets_read, 0) << "current-key expiry recreated a request for its synchronously retired socket";
}
