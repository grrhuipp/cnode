#include "worker/udp_ingress.hpp"
#include "worker/udp_association_reclaimer.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "udp_receive_buffer.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <memory_resource>
#include <string_view>
#include <utility>
#include <vector>

namespace {

class DummyDatagramHandler final : public acpp::Inbound {
public:
    explicit DummyDatagramHandler(
        std::shared_ptr<int> adopted_state = {})
        : adopted_state_(std::move(adopted_state)) {}

    void AdoptWorkerStateFrom(
        acpp::Inbound& previous) noexcept override {
        const auto* old = dynamic_cast<const DummyDatagramHandler*>(&previous);
        if (!old) {
            return;
        }
        worker_state_ = old->worker_state_;
        if (adopted_state_) {
            *adopted_state_ = worker_state_;
        }
    }

    acpp::net::awaitable<acpp::RelayResult> Process(
        std::unique_ptr<acpp::AsyncStream>,
        acpp::routing::Dispatcher&,
        const acpp::proxyman::inbound::ReceiverSettings&,
        acpp::net::io_context&,
        acpp::session::Context&,
        const acpp::TimeoutsConfig&,
        uint32_t) override {
        co_return acpp::RelayResult{};
    }

    std::expected<
        acpp::InboundDatagramResult,
        acpp::ErrorCode> Process(
        const acpp::InboundDatagramRequest&) override {
        return std::unexpected(acpp::ErrorCode::PROTOCOL_AUTH_FAILED);
    }

private:
    std::shared_ptr<int> adopted_state_;
    int worker_state_ = 73;
};

class CountingThreadResource final : public std::pmr::memory_resource {
public:
    size_t allocations = 0;
    size_t deallocations = 0;
    size_t large_allocations = 0;
    size_t large_deallocations = 0;

private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        ++allocations;
        if (bytes >= 128) ++large_allocations;
        if (void* ptr = acpp::memory::AllocatePmr(bytes, alignment)) {
            return ptr;
        }
        throw std::bad_alloc();
    }
    void do_deallocate(void* ptr, size_t bytes, size_t alignment) override {
        ++deallocations;
        if (bytes >= 128) ++large_deallocations;
        acpp::memory::DeallocatePmr(ptr, bytes, alignment);
    }
    [[nodiscard]] bool do_is_equal(
        const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

class ThreadResourceScope final {
public:
    ThreadResourceScope()
        : previous_(std::pmr::set_default_resource(&resource)) {}
    ~ThreadResourceScope() {
        std::pmr::set_default_resource(previous_);
    }

    CountingThreadResource resource;

private:
    std::pmr::memory_resource* previous_;
};

class CountingUdpResponseContext final
    : public acpp::InboundDatagramResponse {
public:
    acpp::buf::MultiBuffer Encode(acpp::UDPPacketView packet) override {
        ++calls;
        last_size = packet.data.size();
        return {};
    }

    size_t calls = 0;
    size_t last_size = 0;
};

static_assert(noexcept(
    std::declval<acpp::worker_detail::UdpIngress&>().RequestStop()));
static_assert(noexcept(
    std::declval<acpp::worker_detail::UdpIngress&>().ReplaceHandler(
        std::declval<std::unique_ptr<acpp::Inbound>>())));
static_assert(noexcept(
    std::declval<acpp::worker_detail::UdpIngress&>().CleanupAllClientSessions()));
static_assert(noexcept(
    std::declval<acpp::worker_detail::UdpIngress&>().CloseSocket(
        std::declval<const std::string&>())));
static_assert(noexcept(
    std::declval<acpp::worker_detail::UdpIngress&>().CloseAllSockets()));

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

}  // namespace

int main() {
    ThreadResourceScope thread_resource;
    if (std::pmr::get_default_resource() != &thread_resource.resource) {
        Fail("UDP PMR test resource was not installed");
    }

    acpp::TargetAddress callback_source;
    callback_source.type = acpp::AddressType::IPv4;
    callback_source.resolved_addr = acpp::net::ip::address_v4::loopback();
    callback_source.port = 5353;
    std::array<uint8_t, 1> callback_payload{0x5a};
    acpp::UDPPacketView callback_packet{callback_source, callback_payload};
    const acpp::udp::endpoint callback_peer(acpp::net::ip::address_v4::loopback(), 5353);

    acpp::RoutedPacketCallback empty_callback;
    if (empty_callback(callback_packet, callback_peer)) {
        Fail("empty UDP callback reported successful delivery");
    }

    acpp::RoutedPacketCallback throwing_callback{
        [](acpp::UDPPacketView, const acpp::udp::endpoint&) { throw 7; }};
    if (throwing_callback(callback_packet, callback_peer)) {
        Fail("throwing UDP callback reported successful delivery");
    }

    bool callback_invoked = false;
    acpp::RoutedPacketCallback valid_callback{
        [&](acpp::UDPPacketView packet, const acpp::udp::endpoint& peer) {
            callback_invoked = packet.data.size() == 1 && packet.data[0] == 0x5a && peer == callback_peer;
        }};
    if (!valid_callback(callback_packet, callback_peer) || !callback_invoked) {
        Fail("valid UDP callback was not delivered");
    }

    acpp::RoutedPacketCallback rejecting_callback{
        [](acpp::UDPPacketView, const acpp::udp::endpoint&) { return false; }};
    if (rejecting_callback(callback_packet, callback_peer)) {
        Fail("UDP callback rejection was converted to delivery success");
    }

    acpp::net::io_context io_context;
    acpp::IoErrorCode ec;
    const acpp::udp::endpoint reply_endpoint_a(
        acpp::net::ip::address_v4::loopback(), 10001);
    const acpp::udp::endpoint reply_endpoint_b(
        acpp::net::ip::address_v4::loopback(), 10002);
    const acpp::InboundDatagramOwner default_owner;

    acpp::worker_detail::UdpIngress::ClientSession failing_reply_session(
        io_context,
        acpp::RoutedPacketCallback{
            [](acpp::UDPPacketView, const acpp::udp::endpoint&) { throw 9; }},
        reply_endpoint_a,
        default_owner);
    acpp::buf::BufferGuard reply_buffer{acpp::buf::Buffer::New()};
    if (!reply_buffer) Fail("failed to allocate UDP callback test buffer");
    reply_buffer->Tail()[0] = 0x33;
    reply_buffer->Produce(1);
    reply_buffer->SetUDP(callback_source);
    acpp::buf::MultiBuffer reply_payload{std::move(reply_buffer)};
    bool reply_failure_reported = false;
    acpp::net::co_spawn(
        io_context,
        failing_reply_session.WriteMultiBuffer(std::move(reply_payload)),
        [&](std::exception_ptr error) {
            reply_failure_reported = error != nullptr;
        });
    io_context.run();
    if (!reply_failure_reported) {
        Fail("UDP client reply callback failure was silently ignored");
    }
    io_context.restart();

    size_t raw_reply_callbacks = 0;
    acpp::worker_detail::UdpIngress::ClientSession raw_reply_session(
        io_context,
        acpp::RoutedPacketCallback{
            [&](acpp::UDPPacketView, const acpp::udp::endpoint&) {
                ++raw_reply_callbacks;
            }},
        reply_endpoint_a,
        default_owner);
    std::array<acpp::net::const_buffer, 1> raw_reply_buffers{
        acpp::net::buffer(callback_payload)};
    bool raw_reply_rejected = false;
    acpp::net::co_spawn(
        io_context,
        raw_reply_session.WriteBuffers(raw_reply_buffers),
        [&](std::exception_ptr error) {
            raw_reply_rejected = error != nullptr;
        });
    io_context.run();
    if (!raw_reply_rejected || raw_reply_callbacks != 0) {
        Fail("UDP raw scatter write was silently reported as delivered");
    }
    io_context.restart();

    std::vector<uint8_t> callback_large_payload(
        acpp::buf::Buffer::kSize + 257, 0x6d);
    acpp::buf::MultiBuffer callback_large_buffers;
    if (!acpp::buf::AppendSpanToMultiBuffer(
            callback_large_payload, callback_large_buffers)) {
        Fail("failed to allocate large UDP callback payload");
    }
    for (acpp::buf::Buffer* buffer : callback_large_buffers) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(callback_source);
        }
    }

    size_t large_callback_count = 0;
    bool large_callback_matches = false;
    acpp::udp::endpoint observed_reply_endpoint;
    acpp::worker_detail::UdpIngress::ClientSession large_reply_session(
        io_context,
        acpp::RoutedPacketCallback{[&](
            acpp::UDPPacketView packet,
            const acpp::udp::endpoint& reply_endpoint) {
            ++large_callback_count;
            observed_reply_endpoint = reply_endpoint;
            large_callback_matches =
                packet.data.size() == callback_large_payload.size() &&
                std::equal(packet.data.begin(), packet.data.end(),
                           callback_large_payload.begin());
        }},
        reply_endpoint_a,
        default_owner);
    bool large_reply_failed = false;
    acpp::net::co_spawn(
        io_context,
        large_reply_session.WriteMultiBuffer(std::move(callback_large_buffers)),
        [&](std::exception_ptr error) {
            large_reply_failed = error != nullptr;
        });
    io_context.run();
    if (large_reply_failed || large_callback_count != 1 ||
        !large_callback_matches || observed_reply_endpoint != reply_endpoint_a) {
        std::cerr << "large_reply_failed=" << large_reply_failed
                  << " callback_count=" << large_callback_count
                  << " callback_matches=" << large_callback_matches << '\n';
        Fail("multi-buffer UDP reply was split into multiple datagrams");
    }
    io_context.restart();

    acpp::buf::MultiBuffer migrated_reply_buffers;
    if (!acpp::buf::AppendSpanToMultiBuffer(
            callback_large_payload, migrated_reply_buffers)) {
        Fail("failed to allocate migrated UDP reply payload");
    }
    for (acpp::buf::Buffer* buffer : migrated_reply_buffers) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(callback_source);
        }
    }
    large_reply_session.UpdateReplyEndpoint(reply_endpoint_b);
    acpp::net::co_spawn(
        io_context,
        large_reply_session.WriteMultiBuffer(std::move(migrated_reply_buffers)),
        [&](std::exception_ptr error) {
            large_reply_failed = error != nullptr;
        });
    io_context.run();
    if (large_reply_failed || large_callback_count != 2 ||
        !large_callback_matches || observed_reply_endpoint != reply_endpoint_b) {
        Fail("UDP client session kept replying to its stale endpoint");
    }
    io_context.restart();

    acpp::worker_detail::UdpIngress::ClientSession bounded_input_session(
        io_context,
        acpp::RoutedPacketCallback{
            [](acpp::UDPPacketView, const acpp::udp::endpoint&) {}},
        reply_endpoint_a,
        default_owner);
    auto make_tiny_payload = [&]() {
        acpp::buf::BufferGuard buffer{acpp::buf::Buffer::New()};
        if (!buffer) Fail("failed to allocate bounded UDP queue payload");
        buffer->Tail()[0] = 0x7a;
        buffer->Produce(1);
        return acpp::buf::MultiBuffer{std::move(buffer)};
    };
    for (size_t i = 0; i < 256; ++i) {
        if (!bounded_input_session.Push(
                callback_source, make_tiny_payload())) {
            Fail("UDP input queue rejected a datagram below its bound");
        }
    }
    if (bounded_input_session.Push(callback_source, make_tiny_payload())) {
        Fail("UDP input queue accepted more than its datagram bound");
    }
    bounded_input_session.Close();

    auto first = acpp::worker_detail::UdpIngress::MakeSocket(io_context);
    first->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open first UDP socket");
    first->bind(acpp::udp::endpoint(acpp::net::ip::address_v4::loopback(), 0), ec);
    if (ec) Fail("failed to bind first UDP socket");
    const auto endpoint = first->local_endpoint(ec);
    if (ec || endpoint.port() == 0) Fail("failed to resolve first UDP endpoint");

    std::array<uint8_t, 1> receive_buffer{};
    acpp::udp::endpoint peer;
    bool receive_cancelled = false;
    first->async_receive_from(
        acpp::net::buffer(receive_buffer),
        peer,
        [&](acpp::IoErrorCode receive_ec, size_t) {
            receive_cancelled = receive_ec == acpp::io_error::operation_aborted;
        });
    first.reset();
    io_context.run();
    if (!receive_cancelled) {
        Fail("destroyed UDP socket did not cancel its pending receive");
    }
    io_context.restart();

    acpp::udp::socket large_receiver(io_context, acpp::udp::v4());
    large_receiver.bind(
        acpp::udp::endpoint(acpp::net::ip::address_v4::loopback(), 0), ec);
    if (ec) Fail("failed to bind large UDP receiver");
    acpp::udp::socket large_sender(io_context, acpp::udp::v4());
    const auto large_endpoint = large_receiver.local_endpoint(ec);
    if (ec) Fail("failed to query large UDP receiver endpoint");

    std::vector<uint8_t> large_payload(acpp::buf::Buffer::kSize + 257, 0x6d);
    bool large_received = false;
    acpp::net::co_spawn(
        io_context,
        [&]() -> acpp::net::awaitable<void> {
            auto [wait_ec] = co_await large_receiver.async_wait(
                acpp::udp::socket::wait_read,
                acpp::net::as_tuple(acpp::net::use_awaitable));
            if (wait_ec) co_return;

            acpp::IoErrorCode available_ec;
            const size_t available = large_receiver.available(available_ec);
            if (available_ec) co_return;
            acpp::detail::UdpReceiveBuffer receive_buffer;
            const auto storage = receive_buffer.Prepare(available);
            acpp::udp::endpoint sender_endpoint;
            auto [receive_ec, bytes] = co_await large_receiver.async_receive_from(
                storage,
                sender_endpoint,
                acpp::net::as_tuple(acpp::net::use_awaitable));
            if (receive_ec) co_return;
            const auto received = receive_buffer.Data(bytes);
            large_received = received.size() == large_payload.size() &&
                std::equal(received.begin(), received.end(), large_payload.begin());
        },
        acpp::net::detached);
    large_sender.send_to(acpp::net::buffer(large_payload), large_endpoint, 0, ec);
    if (ec) Fail("failed to send large UDP datagram");
    io_context.run();
    if (!large_received) {
        Fail("UDP receive path truncated a datagram larger than one Buffer");
    }
    io_context.restart();

    auto second = acpp::worker_detail::UdpIngress::MakeSocket(io_context);
    second->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open second UDP socket");
    second->bind(endpoint, ec);
    if (ec) Fail("owned UDP socket did not release its bound port");

    auto& udp_scheduler = acpp::TimeoutScheduler::ForIoContext(io_context);
    acpp::worker_detail::UdpAssociationReclaimer udp_reclaimer(udp_scheduler);
    acpp::worker_detail::UdpIngress worker(
        "test-inbound", std::make_unique<DummyDatagramHandler>(), udp_reclaimer,
        io_context);

    for (size_t i = 0; i < 512; ++i) {
        (void)worker.EnqueueReply(
            "bounded-replies", reply_endpoint_a, make_tiny_payload());
    }
    size_t drained_replies = 0;
    auto reply_stats = worker.GetResourceStats();
    if (reply_stats.reply_datagrams != 256 || reply_stats.reply_bytes != 256 ||
        reply_stats.active_reply_senders != 0) {
        Fail("UDP reply stats did not report queued resource occupancy");
    }
    auto first_bounded_reply = worker.BeginReplySend("bounded-replies");
    reply_stats = worker.GetResourceStats();
    if (!first_bounded_reply || reply_stats.reply_datagrams != 256 ||
        reply_stats.reply_bytes != 256 || reply_stats.active_reply_senders != 1) {
        Fail("UDP reply stats omitted the active sender");
    }
    ++drained_replies;
    if (!worker.CompleteReplySend("bounded-replies", *first_bounded_reply)) {
        Fail("UDP reply completion did not leave pending datagrams");
    }
    reply_stats = worker.GetResourceStats();
    if (reply_stats.reply_datagrams != 255 || reply_stats.reply_bytes != 255 ||
        reply_stats.active_reply_senders != 0) {
        Fail("UDP reply stats did not transition across completion");
    }
    while (auto reply = worker.BeginReplySend("bounded-replies")) {
        ++drained_replies;
        if (!worker.CompleteReplySend("bounded-replies", *reply)) {
            break;
        }
    }
    if (drained_replies != 256) {
        Fail("UDP reply queue exceeded or undershot its datagram bound");
    }
    worker.ClearReplyQueue("bounded-replies");
    reply_stats = worker.GetResourceStats();
    if (reply_stats.reply_datagrams != 0 || reply_stats.reply_bytes != 0 ||
        reply_stats.active_reply_senders != 0) {
        Fail("UDP reply cleanup retained resource stats");
    }

#ifdef CNODE_TEST_ALLOCATOR_FAULT
    auto make_tiny_guard = [&]() {
        acpp::buf::BufferGuard buffer{acpp::buf::Buffer::New()};
        if (!buffer) Fail("failed to allocate UDP reply OOM payload");
        buffer->Tail()[0] = 0x7a;
        buffer->Produce(1);
        return buffer;
    };
    auto exercise_reply_oom = [&](const std::string& socket_key,
                                  bool use_buffer_guard) {
        auto enqueue_one = [&]() {
            if (use_buffer_guard) {
                auto payload = make_tiny_guard();
                return worker.EnqueueReply(
                    socket_key, reply_endpoint_a, std::move(payload));
            }
            auto payload = make_tiny_payload();
            return worker.EnqueueReply(
                socket_key, reply_endpoint_a, std::move(payload));
        };
        auto enqueue_with_fault = [&]() {
            if (use_buffer_guard) {
                auto payload = make_tiny_guard();
                acpp::memory::reject_next_pmr_allocation = true;
                return worker.EnqueueReply(
                    socket_key, reply_endpoint_a, std::move(payload));
            }
            auto payload = make_tiny_payload();
            acpp::memory::reject_next_pmr_allocation = true;
            return worker.EnqueueReply(
                socket_key, reply_endpoint_a, std::move(payload));
        };
        if (enqueue_one() !=
            acpp::worker_detail::UdpIngress::ReplyEnqueueResult::StartSend) {
            Fail("failed to prime UDP reply OOM queue");
        }
        auto active = worker.BeginReplySend(socket_key);
        if (!active || enqueue_one() !=
                acpp::worker_detail::UdpIngress::ReplyEnqueueResult::Queued) {
            Fail("failed to retain pending and active UDP replies before OOM");
        }
        size_t pending_before_failure = 1;
        bool reply_oom_observed = false;
        for (size_t attempt = 0; attempt < 250; ++attempt) {
            try {
                if (enqueue_with_fault() !=
                    acpp::worker_detail::UdpIngress::ReplyEnqueueResult::Queued) {
                    Fail("UDP reply queue rejected before injected allocation failure");
                }
                if (!acpp::memory::reject_next_pmr_allocation) {
                    Fail("UDP reply queue consumed fault without throwing");
                }
                acpp::memory::reject_next_pmr_allocation = false;
                ++pending_before_failure;
            } catch (const std::bad_alloc&) {
                reply_oom_observed = !acpp::memory::reject_next_pmr_allocation;
                acpp::memory::reject_next_pmr_allocation = false;
                break;
            }
        }
        if (!reply_oom_observed) {
            Fail("UDP reply queue did not exercise deque allocation failure");
        }
        const auto before_recovery = worker.GetResourceStats();
        if (before_recovery.reply_datagrams != pending_before_failure + 1 ||
            before_recovery.reply_bytes != pending_before_failure + 1 ||
            before_recovery.active_reply_senders != 1) {
            Fail("UDP reply OOM changed pending or active queue accounting");
        }
        const auto active_buffers =
            acpp::worker_detail::UdpIngress::ReplySendBuffers(*active);
        if (active_buffers.empty() ||
            static_cast<const uint8_t*>(active_buffers.front().data())[0] != 0x7a ||
            acpp::worker_detail::UdpIngress::ReplyEndpoint(*active) != reply_endpoint_a) {
            Fail("UDP reply OOM changed the active datagram");
        }
        if (enqueue_one() !=
            acpp::worker_detail::UdpIngress::ReplyEnqueueResult::Queued) {
            Fail("UDP reply queue did not recover after injected OOM");
        }
        bool more = worker.CompleteReplySend(socket_key, *active);
        while (more) {
            auto reply = worker.BeginReplySend(socket_key);
            if (!reply) Fail("UDP reply queue lost a pending packet after OOM");
            more = worker.CompleteReplySend(socket_key, *reply);
        }
        active.reset();
        const auto drained_stats = worker.GetResourceStats();
        if (drained_stats.reply_datagrams != 0 || drained_stats.reply_bytes != 0 ||
            drained_stats.active_reply_senders != 0) {
            Fail("UDP reply OOM recovery did not drain to zero");
        }
        worker.ClearReplyQueue(socket_key);
    };
    exercise_reply_oom("oom-reply-multibuffer", false);
    exercise_reply_oom("oom-reply-buffer-guard", true);
#endif

    if (worker.EnqueueReply(
            "reply-generation", reply_endpoint_a, make_tiny_payload()) !=
        acpp::worker_detail::UdpIngress::ReplyEnqueueResult::StartSend) {
        Fail("failed to start the first UDP reply generation");
    }
    auto stale_reply = worker.BeginReplySend("reply-generation");
    if (!stale_reply) {
        Fail("failed to acquire the first UDP reply generation");
    }
    worker.ClearReplyQueue("reply-generation");

    if (worker.EnqueueReply(
            "reply-generation", reply_endpoint_a, make_tiny_payload()) !=
        acpp::worker_detail::UdpIngress::ReplyEnqueueResult::StartSend) {
        Fail("failed to start the replacement UDP reply generation");
    }
    auto active_reply = worker.BeginReplySend("reply-generation");
    if (!active_reply) {
        Fail("failed to acquire the replacement UDP reply generation");
    }
    if (worker.CompleteReplySend("reply-generation", *stale_reply)) {
        Fail("stale UDP reply completion matched a replacement queue");
    }
    if (worker.EnqueueReply(
            "reply-generation", reply_endpoint_a, make_tiny_payload()) !=
        acpp::worker_detail::UdpIngress::ReplyEnqueueResult::Queued) {
        Fail("stale UDP reply completion released a replacement queue");
    }
    if (!worker.CompleteReplySend("reply-generation", *active_reply)) {
        Fail("active UDP reply completion did not release its queue");
    }
    auto queued_reply = worker.BeginReplySend("reply-generation");
    if (!queued_reply) {
        Fail("replacement UDP reply queue lost its pending datagram");
    }
    if (worker.CompleteReplySend("reply-generation", *queued_reply)) {
        Fail("drained UDP reply queue still reported pending datagrams");
    }
    worker.ClearReplyQueue("reply-generation");

    acpp::InboundDatagramOwner owner_a;
    acpp::InboundDatagramOwner owner_b;
    std::array<uint8_t, 16> owner_a_bytes{};
    std::array<uint8_t, 16> owner_b_bytes{};
    owner_a_bytes.fill(0x11);
    owner_b_bytes.fill(0x22);
    if (!owner_a.Assign(owner_a_bytes) || !owner_b.Assign(owner_b_bytes)) {
        Fail("failed to initialize UDP session owners");
    }
    const std::string owner_a_session_key =
        owner_a.ScopeSessionKey("shared-session-id");
    const std::string owner_b_session_key =
        owner_b.ScopeSessionKey("shared-session-id");
    if (owner_a_session_key.empty() || owner_b_session_key.empty() ||
        owner_a_session_key == owner_b_session_key) {
        Fail("UDP protocol session key was not scoped by authenticated owner");
    }
    const auto owner_session = worker.CreateClientSession(
        "owner-socket",
        owner_a_session_key,
        io_context,
        acpp::RoutedPacketCallback{
            [](acpp::UDPPacketView, const acpp::udp::endpoint&) {}},
        reply_endpoint_a,
        owner_a,
        std::chrono::steady_clock::now(),
        std::chrono::seconds(60));
    auto make_owner_payload = [&]() {
        acpp::buf::BufferGuard buffer{acpp::buf::Buffer::New()};
        if (!buffer) Fail("failed to allocate UDP owner payload");
        buffer->Tail()[0] = 0x44;
        buffer->Produce(1);
        return acpp::buf::MultiBuffer{std::move(buffer)};
    };
    if (worker.PushClientPayload(
            "owner-socket",
            owner_a_session_key,
            callback_source,
            reply_endpoint_b,
            owner_b,
            make_owner_payload(),
            std::chrono::steady_clock::now())) {
        Fail("UDP session key collision crossed authenticated owners");
    }
    if (!worker.PushClientPayload(
            "owner-socket",
            owner_a_session_key,
            callback_source,
            reply_endpoint_b,
            owner_a,
            make_owner_payload(),
            std::chrono::steady_clock::now())) {
        Fail("UDP session rejected its authenticated owner");
    }
    auto input_stats = worker.GetResourceStats();
    if (input_stats.input_datagrams != 1 || input_stats.input_bytes != 1) {
        Fail("UDP input stats did not report queued payload occupancy");
    }
    const auto second_owner_session = worker.CreateClientSession(
        "owner-socket",
        owner_b_session_key,
        io_context,
        acpp::RoutedPacketCallback{
            [](acpp::UDPPacketView, const acpp::udp::endpoint&) {}},
        reply_endpoint_a,
        owner_b,
        std::chrono::steady_clock::now(),
        std::chrono::seconds(60));
    if (!second_owner_session || second_owner_session == owner_session ||
        !worker.PushClientPayload(
            "owner-socket",
            owner_b_session_key,
            callback_source,
            reply_endpoint_b,
            owner_b,
            make_owner_payload(),
            std::chrono::steady_clock::now())) {
        Fail("UDP session ID collision blocked a different authenticated owner");
    }
    input_stats = worker.GetResourceStats();
    if (input_stats.input_datagrams != 2 || input_stats.input_bytes != 2) {
        Fail("UDP input stats did not include both queued sessions");
    }
    bool input_read_ok = false;
    acpp::net::co_spawn(
        io_context,
        owner_session->ReadMultiBuffer(),
        [&](std::exception_ptr error, acpp::buf::MultiBuffer payload) {
            input_read_ok = !error && acpp::buf::TotalLen(payload) == 1;
        });
    io_context.poll(); // Complete the queued read, not the open association's idle budget.
    io_context.restart();
    input_stats = worker.GetResourceStats();
    if (!input_read_ok || input_stats.input_datagrams != 1 ||
        input_stats.input_bytes != 1) {
        Fail("UDP input stats did not drain after ReadMultiBuffer");
    }

#ifdef CNODE_TEST_ALLOCATOR_FAULT
    const auto input_baseline = worker.GetResourceStats();
    const std::string oom_input_socket = "oom-input-socket";
    auto oom_input_session = worker.CreateClientSession(
        oom_input_socket,
        "oom-input-client",
        io_context,
        acpp::RoutedPacketCallback{
            [](acpp::UDPPacketView, const acpp::udp::endpoint&) {}},
        reply_endpoint_a,
        default_owner,
        std::chrono::steady_clock::now(),
        std::chrono::seconds(60));
    if (!worker.PushClientPayload(
            oom_input_socket, "oom-input-client", callback_source,
            reply_endpoint_a, default_owner, make_owner_payload(),
            std::chrono::steady_clock::now())) {
        Fail("failed to prime UDP input OOM queue");
    }
    size_t input_oom_items = 1;
    bool input_oom_observed = false;
    for (; input_oom_items < 250; ++input_oom_items) {
        auto payload = make_owner_payload();
        acpp::memory::reject_next_pmr_allocation = true;
        try {
            if (!worker.PushClientPayload(
                    oom_input_socket, "oom-input-client", callback_source,
                    reply_endpoint_a, default_owner, std::move(payload),
                    std::chrono::steady_clock::now())) {
                Fail("UDP input queue rejected before injected allocation failure");
            }
            if (!acpp::memory::reject_next_pmr_allocation) {
                Fail("UDP input queue consumed fault without throwing");
            }
            acpp::memory::reject_next_pmr_allocation = false;
        } catch (const std::bad_alloc&) {
            input_oom_observed = !acpp::memory::reject_next_pmr_allocation;
            acpp::memory::reject_next_pmr_allocation = false;
            break;
        }
    }
    if (!input_oom_observed) {
        Fail("UDP input queue did not exercise deque allocation failure");
    }
    input_stats = worker.GetResourceStats();
    if (input_stats.input_datagrams != input_baseline.input_datagrams + input_oom_items ||
        input_stats.input_bytes != input_baseline.input_bytes + input_oom_items) {
        Fail("UDP input OOM changed queued occupancy accounting");
    }
    if (!worker.PushClientPayload(
            oom_input_socket, "oom-input-client", callback_source,
            reply_endpoint_a, default_owner, make_owner_payload(),
            std::chrono::steady_clock::now())) {
        Fail("UDP input queue did not recover after injected OOM");
    }
    ++input_oom_items;
    while (input_oom_items != 0) {
        bool read_ok = false;
        acpp::net::co_spawn(
            io_context,
            oom_input_session->ReadMultiBuffer(),
            [&](std::exception_ptr error, acpp::buf::MultiBuffer payload) {
                read_ok = !error && acpp::buf::TotalLen(payload) == 1;
            });
        io_context.poll();
        io_context.restart();
        if (!read_ok) Fail("UDP input queue failed to drain after OOM recovery");
        --input_oom_items;
    }
    oom_input_session->Close();
    worker.CleanupClientSessions(oom_input_socket);
    oom_input_session.reset();
    input_stats = worker.GetResourceStats();
    if (input_stats.input_datagrams != input_baseline.input_datagrams ||
        input_stats.input_bytes != input_baseline.input_bytes) {
        Fail("UDP input queue occupancy did not return to baseline");
    }
#endif

    acpp::worker_detail::UdpIngress::ClientSession overflow_session(
        io_context,
        acpp::RoutedPacketCallback{
            [](acpp::UDPPacketView, const acpp::udp::endpoint&) {}},
        reply_endpoint_a,
        owner_a);
    acpp::buf::MultiBuffer oversized_input;
    size_t oversized_bytes = 0;
    while (oversized_bytes <= 512 * 1024) {
        acpp::buf::BufferGuard buffer{acpp::buf::Buffer::New()};
        if (!buffer) Fail("failed to allocate oversized UDP input");
        const size_t n = buffer->Available();
        std::memset(buffer->Tail().data(), 0x5a, n);
        buffer->Produce(static_cast<uint32_t>(n));
        oversized_bytes += n;
        oversized_input.push_back(std::move(buffer));
    }
    if (overflow_session.Push(callback_source, std::move(oversized_input)) ||
        !overflow_session.Closed()) {
        Fail("oversized UDP input did not terminate its session");
    }
    bool overflow_reported = false;
    acpp::net::co_spawn(
        io_context,
        overflow_session.ReadMultiBuffer(),
        [&](std::exception_ptr error, acpp::buf::MultiBuffer) {
            try {
                if (error) std::rethrow_exception(error);
            } catch (const acpp::IoSystemError& e) {
                overflow_reported = e.code() == acpp::io_error::no_buffer_space;
            }
        });
    io_context.poll();
    if (!overflow_reported) {
        Fail("UDP input overflow was exposed as a clean EOF");
    }
    io_context.restart();

    auto attached = worker.AttachSocket("stable-socket", std::move(second));
    if (!attached || worker.FindSocket("stable-socket") != attached ||
        !worker.OwnsSocket("stable-socket", attached.get()) ||
        !attached->is_open()) {
        Fail("failed to attach initial UDP socket");
    }

    auto duplicate = acpp::worker_detail::UdpIngress::MakeSocket(io_context);
    duplicate->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open duplicate UDP socket");
    if (worker.AttachSocket("stable-socket", std::move(duplicate)) != nullptr) {
        Fail("duplicate UDP socket attachment was accepted");
    }
    if (worker.FindSocket("stable-socket") != attached || !attached->is_open()) {
        Fail("duplicate attachment replaced the live UDP socket");
    }

    auto response_context = std::make_shared<CountingUdpResponseContext>();
    acpp::worker_detail::UdpIngress::ClientSession snapshot_reply_session(
        io_context,
        acpp::RoutedPacketCallback{
            [response_context](
                acpp::UDPPacketView packet,
                const acpp::udp::endpoint&) {
                auto encoded = response_context->Encode(packet);
                encoded.clear();
            }},
        reply_endpoint_a,
        default_owner);
    auto adopted_worker_state = std::make_shared<int>(-1);
    if (!worker.ReplaceHandler(
            std::make_unique<DummyDatagramHandler>(adopted_worker_state))) {
        Fail("valid UDP handler replacement was rejected");
    }
    if (*adopted_worker_state != 73) {
        Fail("UDP handler replacement discarded Worker-local protocol state");
    }
    if (owner_session->Closed()) {
        Fail("UDP handler replacement closed a live client session");
    }
    acpp::buf::BufferGuard snapshot_reply{acpp::buf::Buffer::New()};
    if (!snapshot_reply) Fail("failed to allocate snapshot UDP reply");
    snapshot_reply->Tail()[0] = 0x55;
    snapshot_reply->Produce(1);
    snapshot_reply->SetUDP(callback_source);
    bool snapshot_reply_failed = false;
    acpp::net::co_spawn(
        io_context,
        snapshot_reply_session.WriteMultiBuffer(
            acpp::buf::MultiBuffer{std::move(snapshot_reply)}),
        [&](std::exception_ptr error) {
            snapshot_reply_failed = error != nullptr;
        });
    io_context.poll();
    if (snapshot_reply_failed || response_context->calls != 1 ||
        response_context->last_size != 1) {
        Fail("UDP handler replacement changed a live response context");
    }
    io_context.restart();
    if (worker.FindSocket("stable-socket") != attached || !attached->is_open()) {
        Fail("UDP handler replacement disturbed the live socket");
    }
    if (worker.ReplaceHandler(nullptr)) {
        Fail("null UDP handler replacement was accepted");
    }
    if (worker.FindSocket("stable-socket") != attached || !attached->is_open()) {
        Fail("rejected UDP handler replacement disturbed the live socket");
    }

    owner_session->Close();
    auto association_stats = worker.GetResourceStats();
    if (association_stats.associations != 2 ||
        association_stats.closed_associations != 1) {
        Fail("UDP association stats did not count live and closed sessions");
    }
    worker.CleanupClientSessions("owner-socket");
    association_stats = worker.GetResourceStats();
    if (association_stats.associations != 0) {
        Fail("UDP association cleanup retained resource stats");
    }

    const std::string long_socket_key(160, 's');
    const size_t pmr_allocations_before_cycles =
        thread_resource.resource.allocations;
    const size_t pmr_deallocations_before_cycles =
        thread_resource.resource.deallocations;
    for (size_t cycle = 0; cycle < 1000; ++cycle) {
        const size_t large_allocations_before =
            thread_resource.resource.large_allocations;
        const size_t large_deallocations_before =
            thread_resource.resource.large_deallocations;
        const std::string long_client_key =
            std::string(192, 'c') + std::to_string(cycle);
        auto cycle_session = worker.CreateClientSession(
            long_socket_key,
            long_client_key,
            io_context,
            acpp::RoutedPacketCallback{
                [](acpp::UDPPacketView, const acpp::udp::endpoint&) {}},
            reply_endpoint_a,
            default_owner,
            std::chrono::steady_clock::now(),
            std::chrono::seconds(60));
        if (!cycle_session || worker.FindClientSession(
                long_socket_key, long_client_key) != cycle_session) {
            Fail("long UDP keys failed heterogeneous session lookup");
        }
        if (thread_resource.resource.large_allocations <=
            large_allocations_before) {
            Fail("long UDP map keys did not allocate through PMR");
        }
#ifdef CNODE_TEST_ALLOCATOR_FAULT
        acpp::memory::reject_next_pmr_allocation = true;
        if (worker.FindClientSession(long_socket_key, long_client_key) !=
                cycle_session ||
            worker.GetResourceStats().associations == 0 ||
            !acpp::memory::reject_next_pmr_allocation) {
            Fail("UDP lookup or stats inspection allocated PMR memory");
        }
        acpp::memory::reject_next_pmr_allocation = false;
#endif
        if (worker.EnqueueReply(
                long_socket_key, reply_endpoint_a, make_tiny_payload()) !=
            acpp::worker_detail::UdpIngress::ReplyEnqueueResult::StartSend) {
            Fail("long UDP socket key failed reply queue insertion");
        }
        auto long_reply = worker.BeginReplySend(long_socket_key);
        if (!long_reply || worker.GetResourceStats().active_reply_senders != 1) {
            Fail("long UDP reply queue was absent from resource stats");
        }
        (void)worker.CompleteReplySend(long_socket_key, *long_reply);
        long_reply.reset();
        worker.ClearReplyQueue(long_socket_key);
        cycle_session->Close();
        worker.CleanupClientSessions(long_socket_key);
        cycle_session.reset();
        const auto cycle_stats = worker.GetResourceStats();
        if (cycle_stats.associations != 0 ||
            cycle_stats.input_datagrams != 0 || cycle_stats.input_bytes != 0 ||
            cycle_stats.reply_datagrams != 0 || cycle_stats.reply_bytes != 0 ||
            cycle_stats.active_reply_senders != 0 ||
            worker.FindClientSession(long_socket_key, long_client_key)) {
            Fail("UDP resource cycle retained map-owned state");
        }
        if (thread_resource.resource.large_deallocations <=
            large_deallocations_before) {
            Fail("long UDP map keys were not released through PMR");
        }
        if ((cycle + 1) % 50 == 0) {
            io_context.run_for(std::chrono::milliseconds(1));
            io_context.restart();
        }
    }
    if (thread_resource.resource.allocations <= pmr_allocations_before_cycles ||
        thread_resource.resource.deallocations <= pmr_deallocations_before_cycles) {
        Fail("long UDP keys did not allocate and release through the Worker PMR");
    }

    bool attached_wait_cancelled = false;
    attached->async_wait(
        acpp::udp::socket::wait_read,
        [&](acpp::IoErrorCode wait_ec) {
            attached_wait_cancelled =
                wait_ec == acpp::io_error::operation_aborted;
        });
    worker.CloseSocket("stable-socket");
    if (worker.FindSocket("stable-socket") != nullptr) {
        Fail("closed UDP socket remained registered");
    }
    if (!attached || attached->is_open() ||
        worker.OwnsSocket("stable-socket", attached.get())) {
        Fail("retired UDP socket lifetime handle did not observe closure");
    }
    io_context.run();
    if (!attached_wait_cancelled) {
        Fail("retired UDP socket did not deliver cancellation to its lifetime handle");
    }
    io_context.restart();

    const auto session_now = std::chrono::steady_clock::now();
    constexpr std::string_view idle_cleanup_socket = "idle-cleanup-socket";
    auto make_session = [&](std::string key, auto last_active,
                            std::chrono::seconds idle_timeout) {
        return worker.CreateClientSession(
            std::string(idle_cleanup_socket),
            key,
            io_context,
            acpp::RoutedPacketCallback{
                [](acpp::UDPPacketView, const acpp::udp::endpoint&) {}},
            reply_endpoint_a,
            default_owner,
            last_active,
            idle_timeout);
    };
    auto closed_disabled = make_session(
        "closed-disabled", session_now, std::chrono::seconds::zero());
    auto open_disabled = make_session(
        "open-disabled", session_now, std::chrono::seconds::zero());
    closed_disabled->Close();
    io_context.run_for(std::chrono::milliseconds(150));
    io_context.restart();
    if (worker.FindClientSession(std::string(idle_cleanup_socket), "closed-disabled") ||
        worker.FindClientSession(std::string(idle_cleanup_socket), "open-disabled") != open_disabled ||
        open_disabled->Closed()) {
        Fail("disabled idle cleanup retained a closed session or removed an open session");
    }

    auto closed_within_budget = make_session(
        "closed-within-budget", session_now, std::chrono::seconds(1));
    auto expired_open = make_session(
        "expired-open", session_now - std::chrono::seconds(2), std::chrono::seconds(1));
    auto fresh_open = make_session(
        "fresh-open", session_now, std::chrono::seconds(1));
    closed_within_budget->Close();
    io_context.run_for(std::chrono::milliseconds(150));
    io_context.restart();
    if (worker.FindClientSession(
            std::string(idle_cleanup_socket), "closed-within-budget") ||
        worker.FindClientSession(std::string(idle_cleanup_socket), "expired-open") ||
        !expired_open->Closed() ||
        worker.FindClientSession(std::string(idle_cleanup_socket), "fresh-open") != fresh_open ||
        fresh_open->Closed()) {
        Fail("positive idle cleanup did not independently remove closed and expired sessions");
    }

    constexpr size_t closed_session_count = 32;
    std::array<acpp::worker_detail::UdpIngress::ClientSessionPtr,
               closed_session_count> closed_sessions;
    std::array<std::string, closed_session_count> closed_keys;
    for (size_t i = 0; i < closed_session_count; ++i) {
        closed_keys[i] = "closed-distinct-" + std::to_string(i);
        closed_sessions[i] = make_session(
            closed_keys[i], session_now, std::chrono::seconds::zero());
        closed_sessions[i]->Close();
    }
    io_context.run_for(std::chrono::milliseconds(150));
    io_context.restart();
    for (size_t i = 0; i < closed_session_count; ++i) {
        if (worker.FindClientSession(std::string(idle_cleanup_socket), closed_keys[i])) {
            Fail("distinct closed UDP session key remained retained with idle timeout disabled");
        }
    }
    worker.CleanupClientSessions(idle_cleanup_socket);

    return 0;
}
