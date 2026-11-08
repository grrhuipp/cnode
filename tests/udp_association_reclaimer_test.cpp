#include <stdexcept>
#include <gtest/gtest.h>

#include "worker/udp_association_reclaimer.hpp"
#include "worker/udp_ingress.hpp"

#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/stats.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/user_profile.hpp"
#include "common/session.hpp"
#include "common/target_address.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
#include "proxy/inbound_datagram.hpp"
#include "transport/async_stream.hpp"
#include "transport/cancellation.hpp"

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/post.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <initializer_list>
#include <iostream>
#include <memory>
#include <memory_resource>
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

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

class DummyInbound : public ::Inbound {
public:
    ::net::awaitable<::RelayResult> Process(
        std::unique_ptr<::AsyncStream>, ::routing::Dispatcher&,
        const ::proxyman::inbound::ReceiverSettings&, ::net::io_context&,
        ::session::Context&, const ::TimeoutsConfig&, uint32_t) override {
        co_return ::RelayResult{};
    }

    tl::expected<::InboundDatagramResult, ::ErrorCode> Process(
        const ::InboundDatagramRequest&) override {
        return tl::unexpected(::ErrorCode::PROTOCOL_AUTH_FAILED);
    }
};

using Ingress = ::worker_detail::UdpIngress;
using Reclaimer = ::worker_detail::UdpAssociationReclaimer;
using SessionPtr = Ingress::ClientSessionPtr;

class CountingPmrResource final : public std::pmr::memory_resource {
public:
    size_t allocation_calls = 0;
    size_t deallocation_calls = 0;
    size_t deallocated_bytes = 0;

private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        ++allocation_calls;
        if (void* ptr = ::memory::AllocatePmr(bytes, alignment)) return ptr;
        throw std::bad_alloc();
    }
    void do_deallocate(void* ptr, size_t bytes, size_t alignment) override {
        ++deallocation_calls;
        deallocated_bytes += bytes;
        ::memory::DeallocatePmr(ptr, bytes, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

struct ReenterOnCancel {
    Ingress* ingress = nullptr;
    std::string key;
    bool close_all = false;
    size_t calls = 0;

    void Cancel() noexcept {
        ++calls;
        if (close_all) ingress->CloseAllSockets();
        else ingress->CloseSocket(key);
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

class DatagramResponse final : public ::InboundDatagramResponse {
public:
    ::buf::MultiBuffer Encode(::UDPPacketView) override { return {}; }
};

class AcceptedReplyResponse final : public ::InboundDatagramResponse {
public:
    ::buf::MultiBuffer Encode(::UDPPacketView packet) override {
        ::buf::MultiBuffer result;
        if (!::buf::AppendSpanToMultiBuffer(packet.data, result)) throw std::bad_alloc();
        return result;
    }
};

class AcceptedReplySink final : public ::worker_detail::UdpReplySink {
public:
    bool EnqueueUdpReply(std::string_view, ::udp::socket*, ::udp::endpoint,
                         ::buf::MultiBuffer, uint32_t,
                         std::shared_ptr<::worker_detail::UdpReplyFence> = {}) override {
        ++packets;
        return true;
    }
    size_t packets = 0;
};

// Decodes every datagram as owner 0x71 carrying one 0x42 byte; a first byte of
// 0x43 selects protocol session 2, anything else session 1.
class DatagramInbound final : public DummyInbound {
public:
    tl::expected<::InboundDatagramResult, ::ErrorCode> Process(
        const ::InboundDatagramRequest& request) override {
        ::InboundDatagramResult result;
        result.user = &profile_;
        result.tracker = tracker_;
        const std::array<uint8_t, 1> owner{0x71};
        if (!result.session_owner.Assign(owner)) {
            return tl::unexpected(::ErrorCode::RESOURCE_EXHAUSTED);
        }
        result.session_id = !request.payload.empty() && request.payload[0] == 0x43 ? 2 : 1;
        result.target = ::TargetAddress(
            ::net::ip::address_v4::loopback(), 53);
        ::buf::BufferGuard payload{::buf::Buffer::New()};
        if (!payload) return tl::unexpected(::ErrorCode::RESOURCE_EXHAUSTED);
        payload->Tail()[0] = 0x42;
        payload->Produce(1);
        result.payload.push_back(std::move(payload));
        return result;
    }
    tl::expected<std::shared_ptr<::InboundDatagramResponse>, ::ErrorCode>
    CreateDatagramResponse(const ::InboundDatagramResult&) override {
        return std::make_shared<DatagramResponse>();
    }
private:
    std::shared_ptr<::UserOnlineTracker> tracker_ = std::make_shared<::UserOnlineTracker>();
    ::UserProfile profile_;
};

bool IsDecodedPayload(const ::buf::MultiBuffer& payload) {
    if (payload.size() != 1) return false;
    for (const auto* buffer : payload)
        if (!buffer || buffer->Len() != 1 || buffer->Bytes()[0] != 0x42) return false;
    return true;
}

// The reader of a dispatched native request is the association's session.
class DatagramDispatcher final : public ::routing::Dispatcher {
public:
    unsigned dispatched = 0;
    unsigned packets_read = 0;
    const ::transport::MultiBufferReader* last_reader = nullptr;
    ::net::awaitable<::RelayResult> Dispatch(
        ::net::io_context&, const ::routing::DispatchPolicy&,
        std::unique_ptr<::AsyncStream>, ::transport::Link link,
        ::InitialPayload, ::session::Context&, ::StatsShard&,
        const ::TimeoutsConfig&) override {
        ++dispatched;
        if (!link.reader) Fail("rebuilt native request has no reader");
        last_reader = link.reader;
        auto payload = co_await link.reader->ReadMultiBuffer();
        if (!IsDecodedPayload(payload))
            Fail("rebuilt native request did not receive exactly its decoded first packet");
        ++packets_read;
        co_return ::RelayResult{};
    }
};

class DiscardReplySink final : public ::worker_detail::UdpReplySink {
public:
    bool EnqueueUdpReply(std::string_view, ::udp::socket*,
                         ::udp::endpoint, ::buf::MultiBuffer,
                         uint32_t,
                         std::shared_ptr<::worker_detail::UdpReplyFence> = {}) override {
        return false;
    }
};

// Everything ProcessDatagram needs besides the ingress, socket and packet.
struct DatagramSource {
    DatagramDispatcher dispatcher;
    DiscardReplySink reply_sink;
    ::StatsShard stats;
    ::proxyman::inbound::ReceiverSettings receiver{
        .inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {},
        .dispatch_policy = {.sniffing = {}, .outbound = ::routing::ForceOutbound{"loopback"}}};

    void Send(Ingress& ingress, ::net::io_context& io, std::string_view socket_key,
              ::udp::socket* sock, uint16_t client_port,
              std::span<const uint8_t> packet, const ::TimeoutsConfig& timeouts) {
        ingress.ProcessDatagram(::worker_detail::UdpDatagramContext{
            .socket_key = socket_key,
            .sock = sock,
            .client_endpoint = {::net::ip::address_v4::loopback(), client_port},
            .payload = packet,
            .receiver = &receiver,
            .io_context = io,
            .dispatcher = &dispatcher,
            .stats = stats,
            .timeouts = timeouts,
            .reply_sink = reply_sink,
        });
    }
};

::net::awaitable<void> ReadDecodedPayload(SessionPtr session, bool& received) {
    auto payload = co_await session->ReadMultiBuffer();
    received = IsDecodedPayload(payload);
}

::worker_detail::ClientSessionKey Key(uint64_t id) {
    ::InboundDatagramOwner owner;
    const std::array<uint8_t, 1> bytes{0x71};
    if (!owner.Assign(bytes)) Fail("failed to prepare typed session owner");
    return {owner, id};
}

SessionPtr MakeSession(Ingress& ingress, ::net::io_context& io,
                       std::string socket_key, ::worker_detail::ClientSessionKey client_key,
                       Clock::time_point last_active,
                       std::chrono::seconds idle_timeout) {
    return ingress.CreateClientSession(
        socket_key, client_key, io,
        {},
        {::net::ip::address_v4::loopback(), 10001}, client_key.owner, last_active,
        idle_timeout);
}

Ingress::SocketPtr AttachOpenSocket(Ingress& ingress, ::net::io_context& io,
                                    std::string_view socket_key) {
    auto socket = Ingress::MakeSocket(io);
    ::IoErrorCode ec;
    socket->open(::udp::v4(), ec);
    if (ec || !ingress.AttachSocket(socket_key, socket)) {
        Fail("failed to attach an open UDP socket");
    }
    return socket;
}

size_t Associations(std::initializer_list<const Ingress*> ingresses) {
    size_t total = 0;
    for (const auto* ingress : ingresses) total += ingress->GetResourceStats().associations;
    return total;
}

size_t ActiveEvents(const ::TimeoutScheduler& scheduler) {
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
        if (next > current || current - next > kBatchLimit) return false;
        if (next != current) {
            ++reclaiming_handlers;
            after_batch();
        }
        current = next;
    }
    if (io.stopped()) io.restart();
    return true;
}
} // namespace

TEST(UdpAssociationReclaimer, Contract) {
    struct PmrScope {
        CountingPmrResource resource;
        std::pmr::memory_resource* previous = std::pmr::set_default_resource(&resource);
        ~PmrScope() { std::pmr::set_default_resource(previous); }
    } pmr_scope;
    ::net::io_context io;
    auto& scheduler = ::TimeoutScheduler::ForIoContext(io);
    const size_t idle_events = ActiveEvents(scheduler);
    Reclaimer reclaimer(scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    ::worker_detail::UdpResourceBudget budget;
    Ingress first("first", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    Ingress second("second", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    const auto now = Clock::now();

    // Many map insertions force rehashes while hooks remain embedded in nodes.
    // Closed rows across both ingresses share one Worker-wide batch bound.
    std::vector<SessionPtr> closed_sessions;
    closed_sessions.reserve(130);
    for (size_t i = 0; i < 65; ++i) {
        auto one = MakeSession(first, io, "batch", Key(i), now, 0s);
        auto two = MakeSession(second, io, "batch", Key(i), now, 0s);
        if (!one || !two) Fail("failed to create batch associations");
        one->Close();
        two->Close();
        closed_sessions.push_back(std::move(one));
        closed_sessions.push_back(std::move(two));
    }
    if (Associations({&first, &second}) != 130) {
        Fail("closed associations were removed before the maintenance wake ran");
    }
    if (ActiveEvents(scheduler) != idle_events + 1) {
        Fail("closed associations did not arm exactly one maintenance event");
    }
    bool loop_progress = false;
    bool progress_posted = false;
    size_t associations_at_progress = 0;
    size_t batch_handlers = 0;
    const auto batch_count = [&] { return Associations({&first, &second}); };
    if (!StepReclaimBatches(io, batch_count, 0, [&] {
            if (progress_posted) return;
            progress_posted = true;
            asio::post(io, [&] {
                loop_progress = true;
                associations_at_progress = batch_count();
            });
        }, batch_handlers)) {
        Fail("UDP reclaimer did not enforce the shared 64-row batch limit");
    }
    if (batch_handlers < (130 + kBatchLimit - 1) / kBatchLimit) {
        Fail("UDP reclaimer drained more than one batch per maintenance wake");
    }
    if (!loop_progress || associations_at_progress == 0) {
        Fail("event loop did not progress between bounded UDP maintenance batches");
    }
    if (ActiveEvents(scheduler) != idle_events) {
        Fail("drained reclaimer kept a maintenance event armed");
    }
    closed_sessions.clear();

    // Open rows with idle expiry disabled never become due, so they neither
    // consume batch budget nor keep the maintenance event armed.
    std::vector<SessionPtr> mixed_live;
    std::vector<SessionPtr> mixed_closed;
    mixed_live.reserve(65);
    mixed_closed.reserve(65);
    for (size_t i = 0; i < 65; ++i) {
        auto closed = MakeSession(first, io, "mixed", Key(i), now, 0s);
        auto live = MakeSession(second, io, "mixed", Key(i), now, 0s);
        if (!closed || !live) Fail("failed to create mixed associations");
        closed->Close();
        mixed_closed.push_back(std::move(closed));
        mixed_live.push_back(std::move(live));
    }
    size_t mixed_handlers = 0;
    if (!StepReclaimBatches(io, [&] { return Associations({&first, &second}); }, 65,
                            [] {}, mixed_handlers) ||
        mixed_handlers < 2 || first.GetResourceStats().associations != 0 ||
        second.GetResourceStats().associations != 65) {
        Fail("mixed live/closed associations did not progress across bounded batches");
    }
    if (ActiveEvents(scheduler) != idle_events) {
        Fail("open associations with idle expiry disabled armed a maintenance event");
    }
    for (const auto& live : mixed_live) {
        if (live->Closed()) Fail("maintenance closed an open association with idle expiry disabled");
    }
    second.CleanupAllClientSessions();
    if (second.GetResourceStats().associations != 0) Fail("live mixed rows remained registered");
    mixed_live.clear();
    mixed_closed.clear();

    // Removing a row is independent of the lifetime of an externally held session.
    Ingress detached_ingress("detached", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto detached = MakeSession(detached_ingress, io, "detached", Key(1), now, 0s);
    std::weak_ptr<Ingress::ClientSession> detached_weak = detached;
    detached->Close();
    if (!RunUntil(io, [&] { return detached_ingress.GetResourceStats().associations == 0; }) ||
        detached_weak.expired()) {
        Fail("row reclamation was incorrectly coupled to external session lifetime");
    }
    detached.reset();
    if (!detached_weak.expired()) Fail("released detached UDP session remained alive");

    Ingress disabled_ingress("disabled", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto disabled_open = MakeSession(disabled_ingress, io, "disabled", Key(1), now, 0s);
    RunFor(io, 20ms);
    if (disabled_ingress.GetResourceStats().associations != 1 || disabled_open->Closed()) {
        Fail("zero idle timeout did not retain an open UDP association");
    }
    disabled_open->Close();
    if (!RunUntil(io, [&] { return disabled_ingress.GetResourceStats().associations == 0; })) {
        Fail("closed UDP association was retained with idle timeout disabled");
    }

    // Idle expiry closes the session; its cancellation may synchronously
    // retire the socket that owns the expiring row.
    Ingress idle_ingress("idle", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto idle_socket = AttachOpenSocket(idle_ingress, io, "idle");
    auto idle = MakeSession(idle_ingress, io, "idle", Key(1), Clock::now() - 2s, 1s);
    ReenterOnCancel expiry_reentry{.ingress = &idle_ingress, .key = "idle"};
    ReentryCancellation expiry_subscription(expiry_reentry);
    expiry_subscription.Resubscribe(idle->Cancellation());
    if (!idle_ingress.ReplaceHandler(std::make_unique<DummyInbound>())) {
        Fail("UDP handler replacement was rejected");
    }
    if (!RunUntil(io, [&] { return idle->Closed(); }) ||
        idle_ingress.GetResourceStats().associations != 0 ||
        expiry_reentry.calls != 1 || idle_ingress.FindSocket("idle")) {
        Fail("natural expiry reentry did not safely retire the association and socket");
    }

    // Downlink traffic does not refresh idle time: the row still expires at
    // its original deadline, well before a refreshed deadline could pass.
    ::TargetAddress target;
    target.type = ::AddressType::IPv4;
    target.resolved_addr = ::net::ip::address_v4::loopback();
    target.port = 53;
    Ingress downlink_ingress("downlink", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    AcceptedReplySink accepted_reply;
    constexpr auto downlink_idle = 2s;
    auto downlink = downlink_ingress.CreateClientSession(
        "activity", Key(1), io,
        {.socket_key = {}, .socket = {}, .response = std::make_shared<AcceptedReplyResponse>(),
         .sink = &accepted_reply, .worker_id = 0, .fence = {}},
        {::net::ip::address_v4::loopback(), 10001}, Key(1).owner,
        Clock::now() - downlink_idle + 200ms, downlink_idle);
    ::buf::BufferGuard reply{::buf::Buffer::New()};
    if (!reply) Fail("failed to allocate UDP downlink activity payload");
    reply->Tail()[0] = 2;
    reply->Produce(1);
    reply->SetUDP(target);
    bool reply_completed = false;
    ::net::co_spawn(io,
        downlink->WriteMultiBuffer(::buf::MultiBuffer{std::move(reply)}),
        [&](std::exception_ptr error) { reply_completed = !error; });
    if (!RunUntil(io, [&] { return reply_completed; }) || accepted_reply.packets != 1) {
        Fail("UDP downlink write did not complete");
    }
    const auto downlink_written = Clock::now();
    if (!RunUntil(io, [&] { return downlink->Closed(); }) ||
        Clock::now() - downlink_written >= downlink_idle ||
        downlink_ingress.GetResourceStats().associations != 0) {
        Fail("UDP downlink traffic incorrectly refreshed association idle time");
    }
    downlink.reset();

    // Valid uplink only moves last activity. When the original deadline passes
    // the row is re-checked and re-armed; it expires one idle period after the
    // uplink, not before.
    Ingress activity_ingress("activity", std::make_unique<DatagramInbound>(), reclaimer, budget, io);
    auto activity_socket = AttachOpenSocket(activity_ingress, io, "activity");
    DatagramSource activity_source;
    ::TimeoutsConfig activity_timeouts;
    activity_timeouts.idle = 1;
    constexpr auto uplink_idle = 1s;
    auto uplink = MakeSession(activity_ingress, io, "activity", Key(1),
                              Clock::now() - uplink_idle + 300ms, uplink_idle);
    const std::array<uint8_t, 1> uplink_packet{0x42};
    const auto uplink_sent = Clock::now();
    activity_source.Send(activity_ingress, io, "activity", activity_socket.get(), 10002,
                         uplink_packet, activity_timeouts);
    const auto uplink_stats = activity_ingress.GetResourceStats();
    if (uplink_stats.associations != 1 || uplink_stats.input_datagrams != 1 ||
        uplink_stats.input_bytes != 1 || uplink_stats.native_dispatches != 0) {
        Fail("UDP uplink was not delivered to its existing association");
    }
    bool uplink_received = false;
    ::net::co_spawn(io, ReadDecodedPayload(uplink, uplink_received), asio::detached);
    RunFor(io, 600ms);
    if (!uplink_received || uplink->Closed() ||
        activity_ingress.GetResourceStats().associations != 1) {
        Fail("UDP uplink activity did not refresh association idle time");
    }
    if (!RunUntil(io, [&] { return uplink->Closed(); }) ||
        Clock::now() - uplink_sent < uplink_idle ||
        activity_ingress.GetResourceStats().associations != 0) {
        Fail("refreshed UDP association was not re-armed to expire after its idle period");
    }
    uplink.reset();

    // Closing the replaced session re-enters CloseSocket and retires the replacement.
    Ingress replace_ingress("replace", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto replace_socket = AttachOpenSocket(replace_ingress, io, "replace");
    auto prior = MakeSession(replace_ingress, io, "replace", Key(1), now, 0s);
    ReenterOnCancel replacement_reentry{.ingress = &replace_ingress, .key = "replace"};
    ReentryCancellation replacement_subscription(replacement_reentry);
    replacement_subscription.Resubscribe(prior->Cancellation());
    auto replacement = MakeSession(replace_ingress, io, "replace", Key(1), Clock::now(), 0s);
    if (!replacement || replacement == prior || !prior->Closed() ||
        !replacement->Closed() || replace_ingress.GetResourceStats().associations != 0 ||
        replacement_reentry.calls != 1 || replace_ingress.FindSocket("replace")) {
        Fail("same-key replacement was unsafe under synchronous cancellation reentry");
    }

    Ingress bulk_ingress("bulk", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto bulk_socket = AttachOpenSocket(bulk_ingress, io, "bulk");
    auto bulk_a = MakeSession(bulk_ingress, io, "bulk", Key(1), now, 0s);
    auto bulk_b = MakeSession(bulk_ingress, io, "bulk", Key(2), now, 0s);
    ReenterOnCancel bulk_reentry_a{.ingress = &bulk_ingress, .key = "bulk"};
    ReenterOnCancel bulk_reentry_b{.ingress = &bulk_ingress, .key = "bulk"};
    ReentryCancellation bulk_subscription_a(bulk_reentry_a);
    ReentryCancellation bulk_subscription_b(bulk_reentry_b);
    bulk_subscription_a.Resubscribe(bulk_a->Cancellation());
    bulk_subscription_b.Resubscribe(bulk_b->Cancellation());
    if (bulk_ingress.GetResourceStats().associations != 2) Fail("bulk associations were not registered");
    bulk_ingress.CleanupClientSessions("bulk");
    if (bulk_ingress.GetResourceStats().associations != 0 ||
        !bulk_a->Closed() || !bulk_b->Closed() || bulk_reentry_a.calls != 1 ||
        bulk_reentry_b.calls != 1 || bulk_ingress.FindSocket("bulk")) {
        Fail("bulk cleanup was unsafe under synchronous cancellation reentry");
    }

    // Existing row timeout snapshots, not the current packet snapshot, decide
    // whether same-key datagrams reuse or rebuild an association.
    Ingress request_ingress("request", std::make_unique<DatagramInbound>(),
                            reclaimer, budget, io);
    DatagramSource request_source;
    ::TimeoutsConfig packet_timeouts;
    auto request_socket = AttachOpenSocket(request_ingress, io, "request");
    const auto scoped_key = Key(1);
    auto expired_same_key = MakeSession(
        request_ingress, io, "request", scoped_key, Clock::now() - 2s, 1s);
    packet_timeouts.idle = 0;
    const std::array<uint8_t, 1> request_packet{0x42};
    request_source.Send(request_ingress, io, "request", request_socket.get(), 20001,
                        request_packet, packet_timeouts);
    if (!expired_same_key->Closed() || request_ingress.GetResourceStats().associations != 1 ||
        request_ingress.GetResourceStats().native_dispatches != 1) {
        Fail("current-key request revived an expired association before its scan turn");
    }

    auto zero_timeout_row = MakeSession(
        request_ingress, io, "request", Key(2), Clock::now() - 2s, 0s);
    packet_timeouts.idle = 1;
    const std::array<uint8_t, 1> zero_timeout_packet{0x43};
    request_source.Send(request_ingress, io, "request", request_socket.get(), 20002,
                        zero_timeout_packet, packet_timeouts);
    if (zero_timeout_row->Closed() || request_ingress.GetResourceStats().associations != 2 ||
        request_ingress.GetResourceStats().native_dispatches != 1) {
        Fail("current packet timeout overwrote the row's zero-timeout snapshot");
    }
    bool zero_timeout_received = false;
    ::net::co_spawn(io, ReadDecodedPayload(zero_timeout_row, zero_timeout_received),
                        asio::detached);

    io.poll();
    io.restart();
    const ::transport::MultiBufferReader* expired_reader = expired_same_key.get();
    const ::transport::MultiBufferReader* zero_timeout_reader = zero_timeout_row.get();
    if (request_source.dispatcher.dispatched != 1 || request_source.dispatcher.packets_read != 1)
        Fail("same-key rebuild did not dispatch exactly one request with its first packet");
    if (!request_source.dispatcher.last_reader ||
        request_source.dispatcher.last_reader == expired_reader ||
        request_source.dispatcher.last_reader == zero_timeout_reader) {
        Fail("same-key rebuild dispatched a request for a stale association");
    }
    if (!zero_timeout_received || zero_timeout_row->Closed()) {
        Fail("zero-timeout association did not receive its same-key packet");
    }

    // Expiring the current key can synchronously retire the original socket.
    // Do not recreate a row or launch a request for that retired identity.
    auto retiring_current_key = MakeSession(
        request_ingress, io, "request", scoped_key, Clock::now() - 2s, 1s);
    ReenterOnCancel retiring_key_reentry{.ingress = &request_ingress, .key = "request"};
    ReentryCancellation retiring_key_subscription(retiring_key_reentry);
    retiring_key_subscription.Resubscribe(retiring_current_key->Cancellation());
    request_source.Send(request_ingress, io, "request", request_socket.get(), 20001,
                        request_packet, packet_timeouts);
    io.poll();
    io.restart();
    if (retiring_key_reentry.calls != 1 || request_socket->is_open() ||
        !retiring_current_key->Closed() ||
        request_ingress.GetResourceStats().associations != 0 ||
        request_ingress.GetResourceStats().native_dispatches != 0 ||
        request_source.dispatcher.dispatched != 1 || request_source.dispatcher.packets_read != 1)
        Fail("current-key expiry recreated a request for its synchronously retired socket");

    Ingress all_ingress("all", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto all_socket_a = AttachOpenSocket(all_ingress, io, "all-a");
    auto all_socket_b = AttachOpenSocket(all_ingress, io, "all-b");
    auto all_session = MakeSession(all_ingress, io, "all-a", Key(1), now, 0s);
    ReenterOnCancel all_reentry{.ingress = &all_ingress, .key = {}, .close_all = true};
    ReentryCancellation all_subscription(all_reentry);
    all_subscription.Resubscribe(all_session->Cancellation());
    all_ingress.CloseAllSockets();
    if (all_ingress.FindSocket("all-a") || all_ingress.FindSocket("all-b") ||
        !all_session->Closed() || all_reentry.calls != 1 ||
        all_ingress.GetResourceStats().associations != 0) {
        Fail("CloseAllSockets used an invalid borrowed key after reentry");
    }

    // Socket retirement must unlink every row before its map disappears.
    Ingress retire_ingress("retire", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    auto retire_socket = AttachOpenSocket(retire_ingress, io, "retire");
    auto retire_a = MakeSession(retire_ingress, io, "retire", Key(1), now, 0s);
    auto retire_b = MakeSession(retire_ingress, io, "retire", Key(2), now, 0s);
    if (retire_ingress.GetResourceStats().associations != 2) Fail("retire rows were not registered");
    retire_ingress.CloseSocket("retire");
    if (retire_ingress.GetResourceStats().associations != 0 || retire_ingress.FindSocket("retire")) {
        Fail("socket retirement left an association row registered");
    }
    retire_a.reset();
    retire_b.reset();
    RunFor(io, 20ms);

    // A due closed row unlinked by CloseSocket before its wake runs must not
    // be visited, and its now-empty reclaimer must disarm.
    Reclaimer cursor_reclaimer(scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    Ingress cursor_ingress("cursor", std::make_unique<DummyInbound>(), cursor_reclaimer, budget, io);
    auto cursor_socket = AttachOpenSocket(cursor_ingress, io, "cursor-key");
    const size_t events_before_cursor = ActiveEvents(scheduler);
    auto cursor_row = MakeSession(cursor_ingress, io, "cursor-key", Key(1), now, 0s);
    if (ActiveEvents(scheduler) != events_before_cursor) {
        Fail("open association with idle expiry disabled armed a maintenance event");
    }
    cursor_row->Close();
    if (ActiveEvents(scheduler) != events_before_cursor + 1 ||
        cursor_ingress.GetResourceStats().associations != 1) {
        Fail("closed association was not marked due for the next maintenance wake");
    }
    cursor_ingress.CloseSocket("cursor-key");
    if (cursor_ingress.GetResourceStats().associations != 0 ||
        ActiveEvents(scheduler) != events_before_cursor) {
        Fail("CloseSocket did not unlink the due reclaimer row");
    }
    RunFor(io, 50ms);
    if (cursor_ingress.GetResourceStats().associations != 0) {
        Fail("retired reclaimer row was visited after socket close");
    }
    cursor_row.reset();
    cursor_ingress.RequestStop();
    cursor_reclaimer.Stop();

    // One event per reclaimer: idle-disabled open rows arm nothing, the first
    // expiring row arms the event and an earlier deadline reuses it.
    Reclaimer stopped_reclaimer(scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    Ingress stopped_ingress("stopped", std::make_unique<DummyInbound>(), stopped_reclaimer, budget, io);
    const size_t events_before_stop = ActiveEvents(scheduler);
    auto never_expiring = MakeSession(stopped_ingress, io, "stopped-key", Key(1), Clock::now(), 0s);
    if (ActiveEvents(scheduler) != events_before_stop) {
        Fail("open association with idle expiry disabled armed a maintenance event");
    }
    auto later_expiring = MakeSession(stopped_ingress, io, "stopped-key", Key(2), Clock::now(), 1s);
    if (ActiveEvents(scheduler) != events_before_stop + 1) {
        Fail("expiring association did not arm exactly one maintenance event");
    }
    auto due_row = MakeSession(stopped_ingress, io, "stopped-key", Key(3), Clock::now() - 2s, 1s);
    if (ActiveEvents(scheduler) != events_before_stop + 1) {
        Fail("an earlier association deadline armed a second maintenance event");
    }
    stopped_reclaimer.Stop();
    if (ActiveEvents(scheduler) != events_before_stop) {
        Fail("Stop did not cancel the pending association event");
    }
    RunFor(io, 50ms);
    if (stopped_ingress.GetResourceStats().associations != 3 || due_row->Closed() ||
        later_expiring->Closed() || never_expiring->Closed()) {
        Fail("stopped reclaimer processed a due association");
    }
    stopped_ingress.RequestStop();
    RunFor(io, 20ms);
    if (stopped_ingress.GetResourceStats().associations != 0 ||
        ActiveEvents(scheduler) != events_before_stop) {
        Fail("owner cleanup after Stop left an association registered");
    }
    never_expiring.reset();
    later_expiring.reset();
    due_row.reset();

    Reclaimer allocation_reclaimer(scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    Ingress allocation_ingress(
        "allocation", std::make_unique<DummyInbound>(), allocation_reclaimer, budget, io);
    const std::string long_socket_key(4096, 'k');
    const auto deallocated_before = pmr_scope.resource.deallocated_bytes;
    auto allocation_row = MakeSession(
        allocation_ingress, io, long_socket_key, Key(1), Clock::now() - 2s, 1s);
    std::weak_ptr<Ingress::ClientSession> allocation_weak = allocation_row;
    if (!RunUntil(io, [&] { return allocation_ingress.GetResourceStats().associations == 0; })) {
        Fail("expired association in an otherwise empty group was not reclaimed");
    }
    const auto deallocated_after = pmr_scope.resource.deallocated_bytes;
    if (!allocation_row->Closed() ||
        deallocated_after - deallocated_before < long_socket_key.size() ||
        allocation_weak.expired()) {
        Fail("empty association group did not release its long key independently of session lifetime");
    }
    allocation_row.reset();
    if (!allocation_weak.expired()) Fail("released empty-group session remained alive");
    allocation_ingress.RequestStop();
    allocation_reclaimer.Stop();

    RunFor(io, 20ms);
    prior.reset();
    replacement.reset();
    zero_timeout_row.reset();
    for (auto* ingress : {&first, &second, &detached_ingress, &disabled_ingress, &idle_ingress,
                          &downlink_ingress, &activity_ingress, &replace_ingress, &bulk_ingress,
                          &request_ingress, &all_ingress, &retire_ingress}) {
        ingress->RequestStop();
        if (ingress->GetResourceStats().associations != 0) {
            Fail("ingress retained association rows after owner cleanup");
        }
    }
    RunFor(io, 20ms);
    if (ActiveEvents(scheduler) != idle_events) {
        Fail("reclaimer kept a maintenance event armed after owner cleanup");
    }
    reclaimer.Stop();
}
