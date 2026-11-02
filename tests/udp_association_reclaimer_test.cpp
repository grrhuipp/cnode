#include "worker/udp_association_reclaimer.hpp"
#include "worker/udp_ingress.hpp"

#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/proxy/inbound_datagram.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/transport/cancellation.hpp"

#include <asio/co_spawn.hpp>
#include <asio/steady_timer.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <memory_resource>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
using namespace std::chrono_literals;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

class DummyInbound : public acpp::Inbound {
public:
    acpp::net::awaitable<acpp::RelayResult> Process(
        std::unique_ptr<acpp::AsyncStream>, acpp::routing::Dispatcher&,
        const acpp::proxyman::inbound::ReceiverSettings&, acpp::net::io_context&,
        acpp::session::Context&, const acpp::TimeoutsConfig&, uint32_t) override {
        co_return acpp::RelayResult{};
    }

    tl::expected<acpp::InboundDatagramResult, acpp::ErrorCode> Process(
        const acpp::InboundDatagramRequest&) override {
        return tl::unexpected(acpp::ErrorCode::PROTOCOL_AUTH_FAILED);
    }
};

using Ingress = acpp::worker_detail::UdpIngress;
using Reclaimer = acpp::worker_detail::UdpAssociationReclaimer;
using SessionPtr = Ingress::ClientSessionPtr;

class CountingPmrResource final : public std::pmr::memory_resource {
public:
    size_t allocation_calls = 0;
    size_t deallocation_calls = 0;
    size_t deallocated_bytes = 0;

private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        ++allocation_calls;
        if (void* ptr = acpp::memory::AllocatePmr(bytes, alignment)) return ptr;
        throw std::bad_alloc();
    }
    void do_deallocate(void* ptr, size_t bytes, size_t alignment) override {
        ++deallocation_calls;
        deallocated_bytes += bytes;
        acpp::memory::DeallocatePmr(ptr, bytes, alignment);
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

struct ReentryCancellation final : acpp::transport::CancellationSubscription {
    explicit ReentryCancellation(ReenterOnCancel& owner) noexcept : owner(owner) {}
    ReenterOnCancel& owner;
private:
    void OnCancellation(acpp::transport::Cancellation) noexcept override {
        owner.Cancel();
    }
};

class DatagramResponse final : public acpp::InboundDatagramResponse {
public:
    acpp::buf::MultiBuffer Encode(acpp::UDPPacketView) override { return {}; }
};

class AcceptedReplyResponse final : public acpp::InboundDatagramResponse {
public:
    acpp::buf::MultiBuffer Encode(acpp::UDPPacketView packet) override {
        acpp::buf::MultiBuffer result;
        if (!acpp::buf::AppendSpanToMultiBuffer(packet.data, result)) throw std::bad_alloc();
        return result;
    }
};

class AcceptedReplySink final : public acpp::worker_detail::UdpReplySink {
public:
    bool EnqueueUdpReply(std::string_view, acpp::udp::socket*, acpp::udp::endpoint,
                         acpp::buf::MultiBuffer, uint32_t) override { ++packets; return true; }
    size_t packets = 0;
};

class DatagramInbound final : public DummyInbound {
public:
    tl::expected<acpp::InboundDatagramResult, acpp::ErrorCode> Process(
        const acpp::InboundDatagramRequest& request) override {
        acpp::InboundDatagramResult result;
        const std::array<uint8_t, 1> owner{0x71};
        if (!result.session_owner.Assign(owner)) {
            return tl::unexpected(acpp::ErrorCode::RESOURCE_EXHAUSTED);
        }
        result.session_id = !request.payload.empty() && request.payload[0] == 0x43 ? 2 : 1;
        result.target = acpp::TargetAddress(
            acpp::net::ip::address_v4::loopback(), 53);
        acpp::buf::BufferGuard payload{acpp::buf::Buffer::New()};
        if (!payload) return tl::unexpected(acpp::ErrorCode::RESOURCE_EXHAUSTED);
        payload->Tail()[0] = 0x42;
        payload->Produce(1);
        result.payload.push_back(std::move(payload));
        return result;
    }
    tl::expected<std::shared_ptr<acpp::InboundDatagramResponse>, acpp::ErrorCode>
    CreateDatagramResponse(const acpp::InboundDatagramResult&) override {
        return std::make_shared<DatagramResponse>();
    }
};

class DatagramDispatcher final : public acpp::routing::Dispatcher {
public:
    unsigned dispatched = 0;
    unsigned packets_read = 0;
    acpp::net::awaitable<acpp::RelayResult> Dispatch(
        acpp::net::io_context&, const acpp::routing::DispatchPolicy&,
        std::unique_ptr<acpp::AsyncStream>, acpp::transport::Link link,
        acpp::InitialPayload, acpp::session::Context&, acpp::StatsShard&,
        const acpp::TimeoutsConfig&) override {
        ++dispatched;
        if (!link.reader) Fail("rebuilt native request has no reader");
        auto payload = co_await link.reader->ReadMultiBuffer();
        if (payload.size() != 1)
            Fail("rebuilt native request did not receive exactly one decoded packet");
        for (const auto* buffer : payload)
            if (!buffer || buffer->Len() != 1 || buffer->Bytes()[0] != 0x42)
                Fail("rebuilt native request did not receive its decoded first packet");
        ++packets_read;
        co_return acpp::RelayResult{};
    }
};

class DiscardReplySink final : public acpp::worker_detail::UdpReplySink {
public:
    bool EnqueueUdpReply(std::string_view, acpp::udp::socket*,
                         acpp::udp::endpoint, acpp::buf::MultiBuffer,
                         uint32_t) override {
        return false;
    }
};

acpp::worker_detail::ClientSessionKey Key(uint64_t id) {
    acpp::InboundDatagramOwner owner;
    const std::array<uint8_t, 1> bytes{0x71};
    if (!owner.Assign(bytes)) Fail("failed to prepare typed session owner");
    return {owner, id};
}

SessionPtr MakeSession(Ingress& ingress, acpp::net::io_context& io,
                       std::string socket_key, acpp::worker_detail::ClientSessionKey client_key,
                       std::chrono::steady_clock::time_point last_active,
                       std::chrono::seconds idle_timeout) {
    return ingress.CreateClientSession(
        socket_key, client_key, io,
        {},
        {acpp::net::ip::address_v4::loopback(), 10001}, client_key.owner, last_active,
        idle_timeout);
}

void RunFor(acpp::net::io_context& io, std::chrono::milliseconds duration) {
    io.run_for(duration);
    io.restart();
}
} // namespace

int main() {
    struct PmrScope {
        CountingPmrResource resource;
        std::pmr::memory_resource* previous = std::pmr::set_default_resource(&resource);
        ~PmrScope() { std::pmr::set_default_resource(previous); }
    } pmr_scope;
    acpp::net::io_context io;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io);
    Reclaimer reclaimer(scheduler, [](std::exception_ptr) { std::terminate(); });
    acpp::worker_detail::UdpResourceBudget budget;
    Ingress first("first", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    Ingress second("second", std::make_unique<DummyInbound>(), reclaimer, budget, io);
    const auto now = std::chrono::steady_clock::now();

    // Many map insertions force rehashes while hooks remain embedded in nodes.
    std::vector<SessionPtr> closed_sessions;
    closed_sessions.reserve(130);
    for (size_t i = 0; i < 65; ++i) {
        auto one = MakeSession(first, io, "batch", Key(i),
                               now, 0s);
        auto two = MakeSession(second, io, "batch", Key(i),
                               now, 0s);
        one->Close();
        two->Close();
        closed_sessions.push_back(std::move(one));
        closed_sessions.push_back(std::move(two));
    }
    if (reclaimer.GetStats().rows != 130) Fail("reclaimer did not register all Worker rows");

    bool loop_progress = false;
    asio::steady_timer progress(io);
    progress.expires_after(150ms);
    progress.async_wait([&](acpp::IoErrorCode ec) { loop_progress = !ec; });
    RunFor(io, 125ms);
    auto stats = reclaimer.GetStats();
    if (stats.rows != 66 || stats.last_batch_checks != 64 ||
        stats.max_batch_checks > 64 || loop_progress) {
        Fail("UDP reclaimer did not enforce the shared 64-row batch limit");
    }
    RunFor(io, 35ms);
    if (!loop_progress) Fail("event loop did not progress alongside UDP maintenance");
    RunFor(io, 240ms);
    if (reclaimer.GetStats().rows != 0 || first.GetResourceStats().associations != 0 ||
        second.GetResourceStats().associations != 0) {
        Fail("bounded UDP batches did not eventually reclaim closed rows across ingresses");
    }

    std::vector<SessionPtr> mixed_live;
    std::vector<SessionPtr> mixed_closed;
    mixed_live.reserve(65);
    mixed_closed.reserve(65);
    for (size_t i = 0; i < 65; ++i) {
        auto closed = MakeSession(first, io, "mixed", Key(i),
                                  now, 0s);
        auto live = MakeSession(second, io, "mixed", Key(i),
                                now, 0s);
        closed->Close();
        mixed_closed.push_back(std::move(closed));
        mixed_live.push_back(std::move(live));
    }
    RunFor(io, 125ms);
    stats = reclaimer.GetStats();
    if (stats.last_batch_checks != 64 || stats.max_batch_checks > 64 ||
        stats.rows != 98 || first.GetResourceStats().associations != 33 ||
        second.GetResourceStats().associations != 65) {
        Fail("mixed live/closed batch did not check 64 distinct Worker-global rows");
    }
    RunFor(io, 360ms);
    if (reclaimer.GetStats().rows != 65 || first.GetResourceStats().associations != 0 ||
        second.GetResourceStats().associations != 65) {
        Fail("mixed associations did not progress across bounded batches");
    }
    second.CleanupAllClientSessions();
    if (reclaimer.GetStats().rows != 0) Fail("closed mixed rows remained registered");
    mixed_live.clear();
    mixed_closed.clear();

    // Removing a row is independent of the lifetime of an externally held session.
    auto detached = MakeSession(first, io, "detached", Key(1), now, 0s);
    std::weak_ptr<Ingress::ClientSession> detached_weak = detached;
    detached->Close();
    RunFor(io, 120ms);
    if (first.FindClientSession("detached", Key(1)) || detached_weak.expired()) {
        Fail("row reclamation was incorrectly coupled to external session lifetime");
    }
    detached.reset();
    if (!detached_weak.expired()) Fail("released detached UDP session remained alive");

    auto disabled_open = MakeSession(first, io, "disabled", Key(1), now, 0s);
    RunFor(io, 120ms);
    if (first.FindClientSession("disabled", Key(1)) != disabled_open ||
        disabled_open->Closed()) {
        Fail("zero idle timeout did not retain an open UDP association");
    }
    disabled_open->Close();
    RunFor(io, 120ms);
    if (first.FindClientSession("disabled", Key(1))) {
        Fail("closed UDP association was retained with idle timeout disabled");
    }

    // Idle snapshots are per row. Uplink refreshes activity; downlink does not.
    const auto aged = std::chrono::steady_clock::now() - 2s;
    auto idle_socket = Ingress::MakeSocket(io);
    acpp::IoErrorCode idle_socket_ec;
    idle_socket->open(acpp::udp::v4(), idle_socket_ec);
    if (idle_socket_ec || !first.AttachSocket("idle", idle_socket)) {
        Fail("failed to attach socket for expiry reentry test");
    }
    auto idle = MakeSession(first, io, "idle", Key(1), aged, 1s);
    ReenterOnCancel expiry_reentry{.ingress = &first, .key = "idle"};
    ReentryCancellation expiry_subscription(expiry_reentry);
    expiry_subscription.Resubscribe(idle->Cancellation());
    if (!first.ReplaceHandler(std::make_unique<DummyInbound>())) {
        Fail("UDP handler replacement was rejected");
    }
    RunFor(io, 120ms);
    if (first.FindClientSession("idle", Key(1)) || !idle->Closed() ||
        expiry_reentry.calls != 1 || first.FindSocket("idle")) {
        Fail("natural expiry reentry did not safely retire the association and socket");
    }

    acpp::TargetAddress target;
    target.type = acpp::AddressType::IPv4;
    target.resolved_addr = acpp::net::ip::address_v4::loopback();
    target.port = 53;
    AcceptedReplySink accepted_reply;
    auto downlink = first.CreateClientSession(
        "activity", Key(1), io,
        {.socket_key = {}, .socket = {}, .response = std::make_shared<AcceptedReplyResponse>(),
         .sink = &accepted_reply},
        {acpp::net::ip::address_v4::loopback(), 10001}, Key(1).owner, aged, 1s);
    acpp::buf::BufferGuard reply{acpp::buf::Buffer::New()};
    if (!reply) Fail("failed to allocate UDP downlink activity payload");
    reply->Tail()[0] = 2;
    reply->Produce(1);
    reply->SetUDP(target);
    bool reply_completed = false;
    acpp::net::co_spawn(io,
        downlink->WriteMultiBuffer(acpp::buf::MultiBuffer{std::move(reply)}),
        [&](std::exception_ptr error) { reply_completed = !error; });
    RunFor(io, 120ms);
    if (!reply_completed || accepted_reply.packets != 1 ||
        first.FindClientSession("activity", Key(1)) ||
        !downlink->Closed()) {
        Fail("UDP downlink traffic incorrectly refreshed association idle time");
    }

    auto uplink = MakeSession(first, io, "activity", Key(2),
                              std::chrono::steady_clock::now() - 950ms, 1s);
    acpp::buf::BufferGuard input{acpp::buf::Buffer::New()};
    if (!input) Fail("failed to allocate UDP activity-test payload");
    input->Tail()[0] = 1;
    input->Produce(1);
    if (!first.PushClientPayload(
            "activity", Key(2), target,
            {acpp::net::ip::address_v4::loopback(), 10002}, Key(2).owner,
            acpp::buf::MultiBuffer{std::move(input)},
            std::chrono::steady_clock::now())) {
        Fail("UDP uplink activity update was rejected");
    }
    RunFor(io, 120ms);
    if (first.FindClientSession("activity", Key(2)) != uplink || uplink->Closed()) {
        Fail("UDP uplink activity did not refresh association idle time");
    }
    downlink.reset();

    // Closing the replaced session re-enters CloseSocket and retires the replacement.
    acpp::IoErrorCode ec;
    auto replace_socket = Ingress::MakeSocket(io);
    replace_socket->open(acpp::udp::v4(), ec);
    if (ec || !first.AttachSocket("replace", replace_socket)) {
        Fail("failed to attach socket for replacement reentry test");
    }
    auto prior = MakeSession(first, io, "replace", Key(1), now, 0s);
    ReenterOnCancel replacement_reentry{.ingress = &first, .key = "replace"};
    ReentryCancellation replacement_subscription(replacement_reentry);
    replacement_subscription.Resubscribe(prior->Cancellation());
    auto replacement = MakeSession(first, io, "replace", Key(1),
                                   std::chrono::steady_clock::now(), 0s);
    if (!replacement || replacement == prior || !prior->Closed() ||
        !replacement->Closed() || first.FindClientSession("replace", Key(1)) ||
        replacement_reentry.calls != 1 || first.FindSocket("replace")) {
        Fail("same-key replacement was unsafe under synchronous cancellation reentry");
    }

    auto bulk_socket = Ingress::MakeSocket(io);
    bulk_socket->open(acpp::udp::v4(), ec);
    if (ec || !first.AttachSocket("bulk", bulk_socket)) {
        Fail("failed to attach socket for bulk cleanup reentry test");
    }
    auto bulk_a = MakeSession(first, io, "bulk", Key(1), now, 0s);
    auto bulk_b = MakeSession(first, io, "bulk", Key(2), now, 0s);
    ReenterOnCancel bulk_reentry_a{.ingress = &first, .key = "bulk"};
    ReenterOnCancel bulk_reentry_b{.ingress = &first, .key = "bulk"};
    ReentryCancellation bulk_subscription_a(bulk_reentry_a);
    ReentryCancellation bulk_subscription_b(bulk_reentry_b);
    bulk_subscription_a.Resubscribe(bulk_a->Cancellation());
    bulk_subscription_b.Resubscribe(bulk_b->Cancellation());
    first.CleanupClientSessions("bulk");
    if (first.FindClientSession("bulk", Key(1)) || first.FindClientSession("bulk", Key(2)) ||
        !bulk_a->Closed() || !bulk_b->Closed() || bulk_reentry_a.calls != 1 ||
        bulk_reentry_b.calls != 1 || first.FindSocket("bulk")) {
        Fail("bulk cleanup was unsafe under synchronous cancellation reentry");
    }

    // Existing row timeout snapshots, not the current packet snapshot, decide
    // whether same-key datagrams reuse or rebuild an association.
    Ingress request_ingress("request", std::make_unique<DatagramInbound>(),
                            reclaimer, budget, io);
    DatagramDispatcher request_dispatcher;
    DiscardReplySink reply_sink;
    acpp::StatsShard request_stats;
    acpp::TimeoutsConfig packet_timeouts;
    acpp::proxyman::inbound::ReceiverSettings request_receiver{
        .inbound_tag = {}, .inbound_tags = {}, .protocol = {},
        .stream_settings = {},
        .dispatch_policy = {.sniffing = {}, .outbound = acpp::routing::ForceOutbound{"loopback"}}};
    auto request_socket = Ingress::MakeSocket(io);
    request_socket->open(acpp::udp::v4(), ec);
    if (ec || !request_ingress.AttachSocket("request", request_socket))
        Fail("failed to own datagram request socket");
    acpp::InboundDatagramOwner request_owner;
    const std::array<uint8_t, 1> request_owner_bytes{0x71};
    if (!request_owner.Assign(request_owner_bytes)) Fail("failed to assign request owner");
    const acpp::worker_detail::ClientSessionKey scoped_key{request_owner, 1};
    auto expired_same_key = MakeSession(
        request_ingress, io, "request", scoped_key,
        std::chrono::steady_clock::now() - 2s, 1s);
    packet_timeouts.idle = 0;
    const std::array<uint8_t, 1> request_packet{0x42};
    request_ingress.ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
        .socket_key = "request",
        .sock = request_socket.get(),
        .client_endpoint = {acpp::net::ip::address_v4::loopback(), 20001},
        .payload = request_packet,
        .receiver = &request_receiver,
        .io_context = io,
        .dispatcher = request_dispatcher,
        .stats = request_stats,
        .timeouts = packet_timeouts,
        .reply_sink = reply_sink,
    });
    auto rebuilt_same_key = request_ingress.FindClientSession("request", scoped_key);
    if (!rebuilt_same_key || rebuilt_same_key == expired_same_key ||
        !expired_same_key->Closed()) {
        Fail("current-key request revived an expired association before its scan turn");
    }

    const acpp::worker_detail::ClientSessionKey zero_timeout_key{request_owner, 2};
    auto zero_timeout_row = MakeSession(
        request_ingress, io, "request", zero_timeout_key,
        std::chrono::steady_clock::now() - 2s, 0s);
    packet_timeouts.idle = 1;
    const std::array<uint8_t, 1> zero_timeout_packet{0x43};
    request_ingress.ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
        .socket_key = "request",
        .sock = request_socket.get(),
        .client_endpoint = {acpp::net::ip::address_v4::loopback(), 20002},
        .payload = zero_timeout_packet,
        .receiver = &request_receiver,
        .io_context = io,
        .dispatcher = request_dispatcher,
        .stats = request_stats,
        .timeouts = packet_timeouts,
        .reply_sink = reply_sink,
    });
    if (request_ingress.FindClientSession("request", zero_timeout_key) != zero_timeout_row ||
        zero_timeout_row->Closed()) {
        Fail("current packet timeout overwrote the row's zero-timeout snapshot");
    }

    io.poll();
    io.restart();
    if (request_dispatcher.dispatched != 1 || request_dispatcher.packets_read != 1)
        Fail("same-key rebuild did not dispatch exactly one request with its first packet");

    // Expiring the current key can synchronously retire the original socket.
    // Do not recreate a row or launch a request for that retired identity.
    auto retiring_current_key = MakeSession(
        request_ingress, io, "request", scoped_key,
        std::chrono::steady_clock::now() - 2s, 1s);
    ReenterOnCancel retiring_key_reentry{.ingress = &request_ingress, .key = "request"};
    ReentryCancellation retiring_key_subscription(retiring_key_reentry);
    retiring_key_subscription.Resubscribe(retiring_current_key->Cancellation());
    request_ingress.ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
        .socket_key = "request",
        .sock = request_socket.get(),
        .client_endpoint = {acpp::net::ip::address_v4::loopback(), 20001},
        .payload = request_packet,
        .receiver = &request_receiver,
        .io_context = io,
        .dispatcher = request_dispatcher,
        .stats = request_stats,
        .timeouts = packet_timeouts,
        .reply_sink = reply_sink,
    });
    io.poll();
    io.restart();
    if (retiring_key_reentry.calls != 1 || request_socket->is_open() ||
        request_ingress.FindClientSession("request", scoped_key) ||
        request_ingress.GetResourceStats().associations != 0 ||
        request_dispatcher.dispatched != 1 || request_dispatcher.packets_read != 1)
        Fail("current-key expiry recreated a request for its synchronously retired socket");

    auto all_socket_a = Ingress::MakeSocket(io);
    auto all_socket_b = Ingress::MakeSocket(io);
    all_socket_a->open(acpp::udp::v4(), ec);
    all_socket_b->open(acpp::udp::v4(), ec);
    if (ec || !first.AttachSocket("all-a", all_socket_a) ||
        !first.AttachSocket("all-b", all_socket_b)) {
        Fail("failed to attach sockets for CloseAllSockets reentry test");
    }
    auto all_session = MakeSession(first, io, "all-a", Key(1), now, 0s);
    ReenterOnCancel all_reentry{.ingress = &first, .key = {}, .close_all = true};
    ReentryCancellation all_subscription(all_reentry);
    all_subscription.Resubscribe(all_session->Cancellation());
    first.CloseAllSockets();
    if (first.FindSocket("all-a") || first.FindSocket("all-b") ||
        !all_session->Closed() || all_reentry.calls != 1) {
        Fail("CloseAllSockets used an invalid borrowed key after reentry");
    }

    // Cursor-row retirement must unlink all hooks before their maps disappear.
    auto socket = Ingress::MakeSocket(io);
    socket->open(acpp::udp::v4(), ec);
    if (ec || !first.AttachSocket("retire", socket)) {
        Fail("failed to attach socket for reclaimer retirement test");
    }
    auto retire_a = MakeSession(first, io, "retire", Key(1), now, 0s);
    auto retire_b = MakeSession(first, io, "retire", Key(2), now, 0s);
    const size_t rows_before_retire = reclaimer.GetStats().rows;
    first.CloseSocket("retire");
    if (first.FindClientSession("retire", Key(1)) ||
        first.FindClientSession("retire", Key(2)) ||
        reclaimer.GetStats().rows + 2 != rows_before_retire) {
        Fail("socket retirement left a reclaimer hook linked");
    }
    retire_a.reset();
    retire_b.reset();

    Reclaimer cursor_reclaimer(scheduler, [](std::exception_ptr) { std::terminate(); });
    Ingress cursor_ingress("cursor", std::make_unique<DummyInbound>(), cursor_reclaimer, budget, io);
    auto cursor_socket = Ingress::MakeSocket(io);
    cursor_socket->open(acpp::udp::v4(), ec);
    if (ec || !cursor_ingress.AttachSocket("cursor-key", cursor_socket)) {
        Fail("failed to attach socket for cursor-row retirement test");
    }
    auto cursor_row = MakeSession(cursor_ingress, io, "cursor-key", Key(1), now, 0s);
    if (cursor_reclaimer.GetStats().rows != 1) Fail("cursor hook was not registered");
    cursor_ingress.CloseSocket("cursor-key");
    if (cursor_reclaimer.GetStats().rows != 0) {
        Fail("CloseSocket did not unlink the reclaimer cursor row");
    }
    RunFor(io, 120ms);
    if (cursor_reclaimer.GetStats().rows != 0 || cursor_ingress.GetResourceStats().associations) {
        Fail("retired reclaimer cursor row was visited after socket close");
    }
    cursor_row.reset();
    cursor_ingress.RequestStop();
    cursor_reclaimer.Stop();

    Reclaimer stopped_reclaimer(scheduler, [](std::exception_ptr) { std::terminate(); });
    Ingress stopped_ingress("stopped", std::make_unique<DummyInbound>(), stopped_reclaimer, budget, io);
    const auto scheduled_before_stop = scheduler.GetResourceStats().active_events;
    auto stopped_row = MakeSession(stopped_ingress, io, "stopped-key", Key(1), now, 0s);
    if (scheduler.GetResourceStats().active_events != scheduled_before_stop + 1) {
        Fail("live stopped-test row did not arm a scheduler event");
    }
    stopped_reclaimer.Stop();
    if (scheduler.GetResourceStats().active_events != scheduled_before_stop) {
        Fail("Stop did not cancel the pending association timer");
    }
    RunFor(io, 120ms);
    if (stopped_reclaimer.GetStats().rows != 1 ||
        stopped_reclaimer.GetStats().last_batch_checks != 0 || stopped_row->Closed()) {
        Fail("stopped reclaimer processed a pending live row");
    }
    stopped_ingress.RequestStop();
    RunFor(io, 120ms);
    if (stopped_reclaimer.GetStats().rows != 0) {
        Fail("unlink after Stop left a stale reclaimer hook");
    }
    stopped_row.reset();

    Reclaimer allocation_reclaimer(scheduler, [](std::exception_ptr) { std::terminate(); });
    Ingress allocation_ingress(
        "allocation", std::make_unique<DummyInbound>(), allocation_reclaimer, budget, io);
    const std::string long_socket_key(4096, 'k');
    const auto deallocated_before = pmr_scope.resource.deallocated_bytes;
    auto allocation_row = MakeSession(
        allocation_ingress, io, long_socket_key, Key(1),
        std::chrono::steady_clock::now() - 2s, 1s);
    std::weak_ptr<Ingress::ClientSession> allocation_weak = allocation_row;
    RunFor(io, 120ms);
    const auto deallocated_after = pmr_scope.resource.deallocated_bytes;
    if (allocation_reclaimer.GetStats().rows != 0 ||
        allocation_ingress.GetResourceStats().associations != 0 ||
        deallocated_after - deallocated_before < long_socket_key.size() ||
        allocation_weak.expired()) {
        Fail("empty association group did not release its long key independently of session lifetime");
    }
    allocation_row.reset();
    if (!allocation_weak.expired()) Fail("released empty-group session remained alive");
    allocation_ingress.RequestStop();
    allocation_reclaimer.Stop();

    RunFor(io, 20ms);
    request_ingress.RequestStop();
    request_socket->close(ec);
    prior.reset();
    replacement->Close();
    replacement.reset();
    uplink->Close();
    uplink.reset();
    RunFor(io, 120ms);
    first.RequestStop();
    second.RequestStop();
    if (reclaimer.GetStats().rows != 0) Fail("reclaimer retained rows after owner cleanup");
    reclaimer.Stop();
    return 0;
}
