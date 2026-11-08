#include <stdexcept>
#include <gtest/gtest.h>

#include "worker/udp_ingress.hpp"
#include "worker/udp_association_reclaimer.hpp"
#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/stats.hpp"
#include "common/sharded_user_stats.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "transport/async_stream.hpp"
#include "udp_receive_buffer.hpp"

#include <asio/as_tuple.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <array>
#include <barrier>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <memory_resource>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

// Authenticated identity the test handler assigns to the next decoded datagram.
struct DatagramScript {
    ::InboundDatagramOwner owner;
    uint64_t session_id = 0;
    ::TargetAddress target;
    // One-shot: rejects the first PMR allocation after decoding completes, so
    // the fault lands in the ingress delivery path rather than the decoder.
    bool fail_next_allocation = false;
};

class DummyDatagramHandler final : public ::Inbound {
public:
    explicit DummyDatagramHandler(
        std::shared_ptr<int> adopted_state = {}, DatagramScript* script = nullptr)
        : adopted_state_(std::move(adopted_state)), script_(script) {}

    void AdoptWorkerStateFrom(
        ::Inbound& previous) noexcept override {
        const auto* old = dynamic_cast<const DummyDatagramHandler*>(&previous);
        if (!old) {
            return;
        }
        worker_state_ = old->worker_state_;
        if (adopted_state_) {
            *adopted_state_ = worker_state_;
        }
    }

    ::net::awaitable<::RelayResult> Process(
        std::unique_ptr<::AsyncStream>,
        ::routing::Dispatcher&,
        const ::proxyman::inbound::ReceiverSettings&,
        ::net::io_context&,
        ::session::Context&,
        const ::TimeoutsConfig&,
        uint32_t) override {
        co_return ::RelayResult{};
    }

    tl::expected<
        ::InboundDatagramResult,
        ::ErrorCode> Process(
        const ::InboundDatagramRequest& request) override {
        if (!script_) return tl::unexpected(::ErrorCode::PROTOCOL_AUTH_FAILED);
        ::InboundDatagramResult result;
        result.user = &profile_;
        result.tracker = tracker_;
        result.session_owner = script_->owner;
        result.session_id = script_->session_id;
        result.target = script_->target;
        if (!::buf::AppendSpanToMultiBuffer(request.payload, result.payload))
            return tl::unexpected(::ErrorCode::RESOURCE_EXHAUSTED);
#ifdef CNODE_TEST_ALLOCATOR_FAULT
        if (script_->fail_next_allocation) {
            script_->fail_next_allocation = false;
            ::memory::reject_next_pmr_allocation = true;
        }
#endif
        return result;
    }

private:
    std::shared_ptr<int> adopted_state_;
    DatagramScript* script_ = nullptr;
    int worker_state_ = 73;
    std::shared_ptr<::UserOnlineTracker> tracker_ = std::make_shared<::UserOnlineTracker>();
    ::UserProfile profile_;
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
        if (void* ptr = ::memory::AllocatePmr(bytes, alignment)) {
            return ptr;
        }
        throw std::bad_alloc();
    }
    void do_deallocate(void* ptr, size_t bytes, size_t alignment) override {
        ++deallocations;
        if (bytes >= 128) ++large_deallocations;
        ::memory::DeallocatePmr(ptr, bytes, alignment);
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
    : public ::InboundDatagramResponse {
public:
    ::buf::MultiBuffer Encode(::UDPPacketView packet) override {
        if (fail) throw 9;
        ++calls;
        last_size = packet.data.size();
        ::buf::MultiBuffer encoded;
        if (!::buf::AppendSpanToMultiBuffer(packet.data, encoded)) throw std::bad_alloc();
        return encoded;
    }

    size_t calls = 0;
    size_t last_size = 0;
    bool fail = false;
};

struct RecordingReplySink final : ::worker_detail::UdpReplySink {
    bool EnqueueUdpReply(std::string_view, ::udp::socket*, ::udp::endpoint peer,
                         ::buf::MultiBuffer payload, uint32_t,
                         std::shared_ptr<::worker_detail::UdpReplyFence> = {}) override {
        ++calls;
        endpoint = peer;
        bytes.clear();
        for (const auto* buffer : payload) {
            const auto part = buffer->Bytes();
            bytes.insert(bytes.end(), part.begin(), part.end());
        }
        return !reject;
    }
    size_t calls = 0;
    ::udp::endpoint endpoint;
    std::vector<uint8_t> bytes;
    bool reject = false;
};

// Uplink fixtures deliver only to pre-created rows; starting a job is a failure.
class NoDispatch final : public ::routing::Dispatcher {
public:
    ::net::awaitable<::RelayResult> Dispatch(
        ::net::io_context&, const ::routing::DispatchPolicy&,
        std::unique_ptr<::AsyncStream>, ::transport::Link,
        ::InitialPayload, ::session::Context&, ::StatsShard&,
        const ::TimeoutsConfig&) override {
        std::cerr << "uplink fixture started an unexpected native job\n";
        ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
    }
};


[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

void VerifyMigratedBudgetReservations() {
    using Budget = ::worker_detail::UdpResourceBudget;
    constexpr size_t kMigrating = 128;
    Budget source({
        .associations = kMigrating + 1, .datagrams = kMigrating + 1,
        .payload_capacity = (kMigrating + 1) * ::buf::Buffer::kSize});
    Budget target({
        .associations = 1, .datagrams = 1,
        .payload_capacity = ::buf::Buffer::kSize});
    ::buf::MultiBuffer payload;
    const std::array<uint8_t, 1> bytes{0x73};
    if (!::buf::AppendSpanToMultiBuffer(bytes, payload))
        Fail("failed to prepare migrated reservation payload");
    std::array<Budget::AssociationLease, kMigrating> associations;
    std::array<Budget::PayloadReservation, kMigrating> reservations;
    for (size_t i = 0; i < kMigrating; ++i) {
        associations[i] = source.AcquireAssociation();
        reservations[i] = source.ReservePayload(payload);
        if (!associations[i] || !reservations[i])
            Fail("failed to reserve migration source resources");
    }
    {
        auto last_association = source.AcquireAssociation();
        auto last_payload = source.ReservePayload(payload);
        if (!last_association || !last_payload ||
            source.AcquireAssociation() || source.ReservePayload(payload))
            Fail("migration source budget did not enforce its exact limits");
    }
    std::barrier start(2);
    std::thread receiver(
        [&, associations = std::move(associations),
         reservations = std::move(reservations)]() mutable {
            auto target_association = target.AcquireAssociation();
            auto target_payload = target.ReservePayload(payload);
            if (!target_association || !target_payload)
                Fail("failed to reserve receiving Worker resources");
            start.arrive_and_wait();
            // Only leases cross threads; the payload remains owned by this test.
            // Concurrent source admission must not race these migrated releases.
            for (size_t i = 0; i < kMigrating; ++i) {
                associations[i] = {};
                reservations[i] = {};
            }
            const auto usage = target.GetUsage();
            if (usage.associations != 1 || usage.datagrams != 1 ||
                usage.payload_capacity != ::buf::Buffer::kSize)
                Fail("migrated release was charged to the receiving Worker");
        });
    start.arrive_and_wait();
    for (size_t i = 0; i < 4096; ++i) {
        auto association = source.AcquireAssociation();
        auto reservation = source.ReservePayload(payload);
        if (!association || !reservation)
            Fail("migrated release lost source Worker admission capacity");
        const auto usage = source.GetUsage();
        if (usage.associations > kMigrating + 1 ||
            usage.datagrams > kMigrating + 1 ||
            usage.payload_capacity > (kMigrating + 1) * ::buf::Buffer::kSize)
            Fail("concurrent migrated release underflowed the source budget");
    }
    receiver.join();
    for (size_t i = 0; i < kMigrating; ++i) {
        if (associations[i] || reservations[i])
            Fail("moved migration reservation retained source ownership");
    }
    for (auto* budget : {&source, &target}) {
        const auto usage = budget->GetUsage();
        if (usage.associations || usage.datagrams || usage.payload_capacity)
            Fail("cross-Worker reservation destruction leaked resource accounting");
        auto association = budget->AcquireAssociation();
        auto reservation = budget->ReservePayload(payload);
        if (!association || !reservation)
            Fail("cross-Worker release did not restore admission");
    }
}

void VerifyWorkerBudget() {
    using Ingress = ::worker_detail::UdpIngress;
    using Result = Ingress::ReplyEnqueueResult;
    ::net::io_context io;
    auto& scheduler = ::TimeoutScheduler::ForIoContext(io);
    ::worker_detail::UdpAssociationReclaimer reclaimer(
        scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    ::worker_detail::UdpResourceBudget budget({
        .associations = 2, .datagrams = 3,
        .payload_capacity = 3 * ::buf::Buffer::kSize});
    Ingress first("first", std::make_unique<DummyDatagramHandler>(), reclaimer, budget, io);
    Ingress second("second", std::make_unique<DummyDatagramHandler>(), reclaimer, budget, io);
    ::InboundDatagramOwner owner;
    const std::array<uint8_t, 1> owner_bytes{0x53};
    if (!owner.Assign(owner_bytes)) Fail("failed to prepare budget test owner");
    const auto key = [&](uint64_t id) {
        return ::worker_detail::ClientSessionKey{owner, id};
    };
    const ::udp::endpoint endpoint(::net::ip::address_v4::loopback(), 12001);
    const ::worker_detail::ClientSessionKey endpoint_key{owner, std::nullopt, endpoint};
    const ::worker_detail::ClientSessionKey mapped_key{owner, std::nullopt,
        {::net::ip::make_address("::ffff:127.0.0.1"), endpoint.port()}};
    const ::worker_detail::ClientSessionKey moved_key{owner, std::nullopt,
        {endpoint.address(), static_cast<uint16_t>(endpoint.port() + 1)}};
    const ::worker_detail::ClientSessionKeyHash hash;
    if (!(endpoint_key == mapped_key) || hash(endpoint_key) != hash(mapped_key) ||
        endpoint_key == moved_key || endpoint_key == key(0) ||
        !(key(0) == ::worker_detail::ClientSessionKey{owner, 0, endpoint}))
        Fail("typed UDP identity lost normalization, endpoint port or zero-session distinction");
    const ::TargetAddress target(endpoint.address(), 53);
    const auto create = [&](Ingress& ingress, uint64_t id) {
        return ingress.CreateClientSession("socket", key(id), io,
            {}, endpoint, owner,
            std::chrono::steady_clock::now(), std::chrono::seconds::zero());
    };
    const auto payload = [](size_t blocks = 1) {
        ::buf::MultiBuffer result;
        for (size_t i = 0; i < blocks; ++i) {
            ::buf::BufferGuard buffer{::buf::Buffer::New()};
            if (!buffer) Fail("failed to prepare budget test payload");
            buffer->Tail()[0] = 0x55;
            buffer->Produce(1);
            result.push_back(std::move(buffer));
        }
        return result;
    };
#ifdef CNODE_TEST_ALLOCATOR_FAULT
    ::memory::reject_next_pmr_allocation = true;
    bool association_oom = false;
    try {
        (void)create(first, 1);
    } catch (const std::bad_alloc&) {
        association_oom = !::memory::reject_next_pmr_allocation;
    }
    ::memory::reject_next_pmr_allocation = false;
    if (!association_oom || budget.GetUsage().associations != 0 ||
        first.GetResourceStats().associations != 0)
        Fail("session construction failure leaked its association lease");
#endif
    auto one = create(first, 1);
    auto two = create(second, 2);
    if (!one || !two || create(first, 3) || budget.GetUsage().associations != 2)
        Fail("association admission was not shared across ingresses");
    first.CleanupClientSessions("socket");
    if (!one->Closed() || create(second, 3) || budget.GetUsage().associations != 2)
        Fail("map removal bypassed the live association budget");
    one.reset();
    auto three = create(first, 3);
    if (!three || budget.GetUsage().associations != 2 ||
        !two->Push(target, payload()))
        Fail("association release failed to restore admission or existing request");

    if (first.EnqueueReply("reply", endpoint, payload()) != Result::StartSend)
        Fail("failed to reserve a shared reply payload");
#ifdef CNODE_TEST_ALLOCATOR_FAULT
    ::memory::reject_next_pmr_allocation = true;
#endif
    auto active = first.BeginReplySend("reply");
#ifdef CNODE_TEST_ALLOCATOR_FAULT
    const bool allocated = !::memory::reject_next_pmr_allocation;
    ::memory::reject_next_pmr_allocation = false;
    if (allocated) Fail("ordinary UDP send handoff allocated a packet node");
#endif
    if (!active || budget.GetUsage().datagrams != 2 ||
        budget.GetUsage().payload_capacity != 2 * ::buf::Buffer::kSize ||
        second.EnqueueReply("reply", endpoint, payload(2)) != Result::Rejected)
        Fail("payload capacity did not include in-flight reply buffers");
    if (three->Push(target, payload(2)) || three->Closed() ||
        budget.GetUsage().datagrams != 2)
        Fail("shared payload rejection closed an existing association or leaked a reservation");
    if (second.EnqueueReply("reply", endpoint, payload()) != Result::StartSend ||
        three->Push(target, payload()) || three->Closed())
        Fail("global datagram saturation was not isolated to the incoming packet");
    first.ClearReplyQueue("reply");
    if (budget.GetUsage().datagrams != 3)
        Fail("clearing the reply map prematurely released an in-flight send");
    active.reset();
    if (budget.GetUsage().datagrams != 2 || !three->Push(target, payload()))
        Fail("in-flight completion failed to restore shared payload capacity");

    bool read = false;
    ::net::co_spawn(io, two->ReadMultiBuffer(),
        [&](std::exception_ptr error, ::buf::MultiBuffer buffers) {
            read = !error && buffers.byte_size() == 1;
            if (budget.GetUsage().datagrams != 2)
                Fail("relay-owned payload still consumed queue budget");
        });
    io.poll();
    io.restart();
    if (!read || two->Closed() || !two->Push(target, payload()))
        Fail("a saturated Worker stopped serving an existing association");
    second.ClearReplyQueue("reply");
    first.RequestStop();
    second.RequestStop();
    three.reset();
    two.reset();
    if (budget.GetUsage().associations != 0 || budget.GetUsage().datagrams != 0 ||
        budget.GetUsage().payload_capacity != 0)
        Fail("stop and destruction retained shared UDP resources");

    // The independent count limit is observable even with ample byte capacity.
    ::worker_detail::UdpResourceBudget count_budget({
        .associations = 1, .datagrams = 1, .payload_capacity = 1024 * 1024});
    Ingress counted("counted", std::make_unique<DummyDatagramHandler>(), reclaimer,
                    count_budget, io);
    if (counted.EnqueueReply("count", endpoint, payload()) != Result::StartSend ||
        counted.EnqueueReply("count", endpoint, payload()) != Result::Rejected ||
        count_budget.GetUsage().datagrams != 1)
        Fail("shared datagram count limit was not enforced independently");
    counted.RequestStop();
    if (count_budget.GetUsage().datagrams != 0 ||
        count_budget.GetUsage().payload_capacity != 0)
        Fail("reply queue destruction leaked its payload reservation");

    ::worker_detail::UdpResourceBudget empty_budget({
        .associations = 1, .datagrams = 2,
        .payload_capacity = 2 * ::buf::Buffer::kSize});
    Ingress empty_ingress("empty", std::make_unique<DummyDatagramHandler>(), reclaimer,
                          empty_budget, io);
    auto empty_session = create(empty_ingress, 1);
    if (!empty_session || !empty_session->Push(target, {}) ||
        !empty_session->Push(target, {}) || empty_session->Push(target, {}) ||
        empty_session->Closed() || empty_budget.GetUsage().datagrams != 2 ||
        empty_budget.GetUsage().payload_capacity != 2 * ::buf::Buffer::kSize)
        Fail("zero-length input bypassed datagram count or Buffer capacity admission");
    bool empty_read = false;
    ::net::co_spawn(io, empty_session->ReadMultiBuffer(),
        [&](std::exception_ptr error, ::buf::MultiBuffer packet) {
            const auto datagram = ::buf::InspectUdpDatagram(packet);
            empty_read = !error && datagram.Valid() && datagram.payload_size == 0 &&
                datagram.buffer_count == 1 && datagram.target->SameEndpoint(target);
        });
    io.poll();
    io.restart();
    if (!empty_read || empty_budget.GetUsage().datagrams != 1 ||
        empty_budget.GetUsage().payload_capacity != ::buf::Buffer::kSize ||
        !empty_session->Push(target, {}))
        Fail("reading zero-length input lost its boundary or failed to restore admission");
    empty_session->Close();
    if (empty_budget.GetUsage().datagrams != 0 ||
        empty_budget.GetUsage().payload_capacity != 0 || empty_session->Push(target, {}))
        Fail("closing zero-length input failed to release queue reservations");
    empty_ingress.RequestStop();
}

}  // namespace

TEST(UdpSocketOwner, Contract) {
    ThreadResourceScope thread_resource;
    VerifyWorkerBudget();
    VerifyMigratedBudgetReservations();
    if (std::pmr::get_default_resource() != &thread_resource.resource) {
        Fail("UDP PMR test resource was not installed");
    }

    ::TargetAddress callback_source;
    callback_source.type = ::AddressType::IPv4;
    callback_source.resolved_addr = ::net::ip::address_v4::loopback();
    callback_source.port = 5353;
    std::array<uint8_t, 1> callback_payload{0x5a};

    ::net::io_context io_context;
    ::worker_detail::UdpResourceBudget udp_budget;
    ::IoErrorCode ec;
    const ::udp::endpoint reply_endpoint_a(
        ::net::ip::address_v4::loopback(), 10001);
    const ::udp::endpoint reply_endpoint_b(
        ::net::ip::address_v4::loopback(), 10002);
    ::InboundDatagramOwner default_owner;
    const std::array<uint8_t, 1> default_owner_bytes{1};
    if (!default_owner.Assign(default_owner_bytes)) Fail("failed to prepare owner");
    RecordingReplySink failed_sink, raw_sink, large_sink, snapshot_sink;
    const auto failing_response = std::make_shared<CountingUdpResponseContext>();
    failing_response->fail = true;

    ::worker_detail::UdpIngress::ClientSession failing_reply_session(
        io_context,
        {.socket_key = {}, .socket = {}, .response = failing_response, .sink = &failed_sink, .worker_id = 0, .fence = {}},
        reply_endpoint_a,
        default_owner, udp_budget, udp_budget.AcquireAssociation());
    ::buf::BufferGuard reply_buffer{::buf::Buffer::New()};
    if (!reply_buffer) Fail("failed to allocate UDP callback test buffer");
    reply_buffer->Tail()[0] = 0x33;
    reply_buffer->Produce(1);
    reply_buffer->SetUDP(callback_source);
    ::buf::MultiBuffer reply_payload{std::move(reply_buffer)};
    bool reply_failure_reported = false;
    ::net::co_spawn(
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

    ::worker_detail::UdpIngress::ClientSession raw_reply_session(
        io_context,
        {.socket_key = {}, .socket = {}, .response = std::make_shared<CountingUdpResponseContext>(),
         .sink = &raw_sink, .worker_id = 0, .fence = {}},
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
    if (!raw_reply_rejected || raw_sink.calls != 0) {
        Fail("UDP raw scatter write was silently reported as delivered");
    }
    io_context.restart();

    std::vector<uint8_t> callback_large_payload(
        ::buf::Buffer::kSize + 257, 0x6d);
    ::buf::MultiBuffer callback_large_buffers;
    if (!::buf::AppendSpanToMultiBuffer(
            callback_large_payload, callback_large_buffers)) {
        Fail("failed to allocate large UDP callback payload");
    }
    for (::buf::Buffer* buffer : callback_large_buffers) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(callback_source);
        }
    }

    ::worker_detail::UdpIngress::ClientSession large_reply_session(
        io_context,
        {.socket_key = {}, .socket = {}, .response = std::make_shared<CountingUdpResponseContext>(),
         .sink = &large_sink, .worker_id = 0, .fence = {}},
        reply_endpoint_a,
        default_owner, udp_budget, udp_budget.AcquireAssociation());
    bool large_reply_failed = false;
    ::net::co_spawn(
        io_context,
        large_reply_session.WriteMultiBuffer(std::move(callback_large_buffers)),
        [&](std::exception_ptr error) {
            large_reply_failed = error != nullptr;
        });
    io_context.run();
    if (large_reply_failed || large_sink.calls != 1 ||
        large_sink.bytes != callback_large_payload || large_sink.endpoint != reply_endpoint_a) {
        Fail("multi-buffer UDP reply was split into multiple datagrams");
    }
    io_context.restart();

    ::buf::MultiBuffer migrated_reply_buffers;
    if (!::buf::AppendSpanToMultiBuffer(
            callback_large_payload, migrated_reply_buffers)) {
        Fail("failed to allocate migrated UDP reply payload");
    }
    for (::buf::Buffer* buffer : migrated_reply_buffers) {
        if (buffer && !buffer->IsEmpty()) {
            buffer->SetUDP(callback_source);
        }
    }
    large_reply_session.UpdateReplyEndpoint(reply_endpoint_b);
    ::net::co_spawn(
        io_context,
        large_reply_session.WriteMultiBuffer(std::move(migrated_reply_buffers)),
        [&](std::exception_ptr error) {
            large_reply_failed = error != nullptr;
        });
    io_context.run();
    if (large_reply_failed || large_sink.calls != 2 ||
        large_sink.bytes != callback_large_payload || large_sink.endpoint != reply_endpoint_b) {
        Fail("UDP client session kept replying to its stale endpoint");
    }
    io_context.restart();

    ::worker_detail::UdpIngress::ClientSession bounded_input_session(
        io_context,
        {},
        reply_endpoint_a,
        default_owner, udp_budget, udp_budget.AcquireAssociation());
    auto make_empty_payload = [&]() {
        return ::buf::MultiBuffer{};
    };
    const auto make_tiny_payload = [] {
        ::buf::MultiBuffer payload;
        const std::array<uint8_t, 1> bytes{0x7a};
        if (!::buf::AppendSpanToMultiBuffer(bytes, payload))
            Fail("failed to prepare UDP reply payload");
        return payload;
    };
    const auto before_empty_queue = udp_budget.GetUsage();
    for (size_t i = 0; i < 256; ++i) {
        if (!bounded_input_session.Push(
                callback_source, make_empty_payload())) {
            Fail("UDP input queue rejected a datagram below its bound");
        }
    }
    if (udp_budget.GetUsage().datagrams != before_empty_queue.datagrams + 256 ||
        udp_budget.GetUsage().payload_capacity !=
            before_empty_queue.payload_capacity + 256 * ::buf::Buffer::kSize)
        Fail("zero-length input queue did not charge one Buffer per datagram");
    if (bounded_input_session.Push(callback_source, make_empty_payload())) {
        Fail("UDP input queue accepted more than its datagram bound");
    }
    bounded_input_session.Close();
    if (udp_budget.GetUsage().datagrams != before_empty_queue.datagrams ||
        udp_budget.GetUsage().payload_capacity != before_empty_queue.payload_capacity)
        Fail("overflowed zero-length input queue retained reservations");

    auto first = ::worker_detail::UdpIngress::MakeSocket(io_context);
    first->open(::udp::v4(), ec);
    if (ec) Fail("failed to open first UDP socket");
    first->bind(::udp::endpoint(::net::ip::address_v4::loopback(), 0), ec);
    if (ec) Fail("failed to bind first UDP socket");
    const auto endpoint = first->local_endpoint(ec);
    if (ec || endpoint.port() == 0) Fail("failed to resolve first UDP endpoint");

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
    if (!receive_cancelled) {
        Fail("destroyed UDP socket did not cancel its pending receive");
    }
    io_context.restart();

    ::udp::socket large_receiver(io_context, ::udp::v4());
    large_receiver.bind(
        ::udp::endpoint(::net::ip::address_v4::loopback(), 0), ec);
    if (ec) Fail("failed to bind large UDP receiver");
    ::udp::socket large_sender(io_context, ::udp::v4());
    const auto large_endpoint = large_receiver.local_endpoint(ec);
    if (ec) Fail("failed to query large UDP receiver endpoint");

    std::vector<uint8_t> large_payload(::buf::Buffer::kSize + 257, 0x6d);
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
            ::detail::UdpReceiveBuffer receive_buffer;
            const auto storage = receive_buffer.Prepare(available);
            ::udp::endpoint sender_endpoint;
            auto [receive_ec, bytes] = co_await large_receiver.async_receive_from(
                storage,
                sender_endpoint,
                ::net::as_tuple(::net::use_awaitable));
            if (receive_ec) co_return;
            const auto received = receive_buffer.Data(bytes);
            large_received = received.size() == large_payload.size() &&
                std::equal(received.begin(), received.end(), large_payload.begin());
        },
        ::net::detached);
    large_sender.send_to(::net::buffer(large_payload), large_endpoint, 0, ec);
    if (ec) Fail("failed to send large UDP datagram");
    io_context.run();
    if (!large_received) {
        Fail("UDP receive path truncated a datagram larger than one Buffer");
    }
    io_context.restart();

    auto second = ::worker_detail::UdpIngress::MakeSocket(io_context);
    second->open(::udp::v4(), ec);
    if (ec) Fail("failed to open second UDP socket");
    second->bind(endpoint, ec);
    if (ec) Fail("owned UDP socket did not release its bound port");

    auto& udp_scheduler = ::TimeoutScheduler::ForIoContext(io_context);
    ::worker_detail::UdpAssociationReclaimer udp_reclaimer(
        udp_scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    DatagramScript uplink_script;
    uplink_script.target = callback_source;
    ::worker_detail::UdpIngress worker(
        "test-inbound", std::make_unique<DummyDatagramHandler>(nullptr, &uplink_script),
        udp_reclaimer, udp_budget, io_context);
    // Uplink payloads reach a row only through the authenticated datagram path.
    NoDispatch uplink_dispatcher;
    ::StatsShard uplink_stats;
    const ::TimeoutsConfig uplink_timeouts{};
    // Consulted only when a datagram starts an association, which never happens here.
    const ::proxyman::inbound::ReceiverSettings uplink_receiver{
        .inbound_tag = {},
        .inbound_tags = {},
        .protocol = {},
        .accounting_key = {},
        .stream_settings = {},
        .dispatch_policy = {
            .sniffing = {}, .outbound = ::routing::ForceOutbound{"direct"}},
        .proxy_protocol = ::ProxyProtocolMode::Auto,
        .has_route_inbound_tags = false};
    RecordingReplySink uplink_sink;
    const auto attach_uplink_socket = [&](std::string_view socket_key) {
        auto socket = worker.AttachSocket(
            socket_key, ::worker_detail::UdpIngress::MakeSocket(io_context));
        if (!socket) Fail("failed to attach UDP uplink test socket");
        return socket;
    };
    const auto deliver_uplink = [&](std::string_view socket_key,
                                    const ::worker_detail::UdpIngress::SocketPtr& socket,
                                    const ::InboundDatagramOwner& owner,
                                    uint64_t session_id, uint8_t marker) {
        uplink_script.owner = owner;
        uplink_script.session_id = session_id;
        const std::array<uint8_t, 1> datagram{marker};
        worker.ProcessDatagram(::worker_detail::UdpDatagramContext{
            .socket_key = socket_key,
            .sock = socket.get(),
            .client_endpoint = reply_endpoint_b,
            .payload = datagram,
            .receiver = &uplink_receiver,
            .io_context = io_context,
            .dispatcher = &uplink_dispatcher,
            .stats = uplink_stats,
            .timeouts = uplink_timeouts,
            .worker_id = 0,
            .reply_sink = uplink_sink,
            .environment = nullptr,
        });
    };
    const auto read_marker = [&](::worker_detail::UdpIngress::ClientSession& session) {
        int marker = -1;
        ::net::co_spawn(
            io_context,
            session.ReadMultiBuffer(),
            [&](std::exception_ptr error, ::buf::MultiBuffer payload) {
                if (error || payload.byte_size() != 1) return;
                for (const auto* buffer : payload) {
                    if (buffer && buffer->Len() == 1) marker = buffer->Bytes()[0];
                }
            });
        io_context.poll(); // Complete the queued read, not an open association's idle budget.
        io_context.restart();
        return marker;
    };

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
    auto bounded_reply = worker.CompleteReplySend("bounded-replies", first_bounded_reply->id);
    reply_stats = worker.GetResourceStats();
    if (!bounded_reply || reply_stats.reply_datagrams != 255 ||
        reply_stats.reply_bytes != 255 || reply_stats.active_reply_senders != 1) {
        Fail("UDP reply completion did not hand off the next pending datagram");
    }
    while (bounded_reply) {
        ++drained_replies;
        bounded_reply = worker.CompleteReplySend("bounded-replies", bounded_reply->id);
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
    auto exercise_reply_oom = [&](const std::string& socket_key) {
        const auto budget_before = udp_budget.GetUsage();
        auto enqueue_one = [&]() {
            return worker.EnqueueReply(
                socket_key, reply_endpoint_a, make_tiny_payload());
        };
        auto enqueue_with_fault = [&]() {
            auto payload = make_tiny_payload();
            ::memory::reject_next_pmr_allocation = true;
            return worker.EnqueueReply(
                socket_key, reply_endpoint_a, std::move(payload));
        };
        if (enqueue_one() !=
            ::worker_detail::UdpIngress::ReplyEnqueueResult::StartSend) {
            Fail("failed to prime UDP reply OOM queue");
        }
        auto active = worker.BeginReplySend(socket_key);
        if (!active || enqueue_one() !=
                ::worker_detail::UdpIngress::ReplyEnqueueResult::Queued) {
            Fail("failed to retain pending and active UDP replies before OOM");
        }
        size_t pending_before_failure = 1;
        bool reply_oom_observed = false;
        for (size_t attempt = 0; attempt < 250; ++attempt) {
            try {
                if (enqueue_with_fault() !=
                    ::worker_detail::UdpIngress::ReplyEnqueueResult::Queued) {
                    Fail("UDP reply queue rejected before injected allocation failure");
                }
                if (!::memory::reject_next_pmr_allocation) {
                    Fail("UDP reply queue consumed fault without throwing");
                }
                ::memory::reject_next_pmr_allocation = false;
                ++pending_before_failure;
            } catch (const std::bad_alloc&) {
                reply_oom_observed = !::memory::reject_next_pmr_allocation;
                ::memory::reject_next_pmr_allocation = false;
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
        if (udp_budget.GetUsage().datagrams != budget_before.datagrams + pending_before_failure + 1 ||
            udp_budget.GetUsage().payload_capacity != budget_before.payload_capacity +
                (pending_before_failure + 1) * ::buf::Buffer::kSize)
            Fail("reply deque allocation failure leaked a shared payload reservation");
        const auto active_buffers =
            active->SendBuffers();
        if (active_buffers.empty() ||
            static_cast<const uint8_t*>(active_buffers.front().data())[0] != 0x7a ||
            active->endpoint != reply_endpoint_a) {
            Fail("UDP reply OOM changed the active datagram");
        }
        if (enqueue_one() !=
            ::worker_detail::UdpIngress::ReplyEnqueueResult::Queued) {
            Fail("UDP reply queue did not recover after injected OOM");
        }
        size_t handed_off = 0;
        auto next = worker.CompleteReplySend(socket_key, active->id);
        while (next) {
            ++handed_off;
            next = worker.CompleteReplySend(socket_key, next->id);
        }
        if (handed_off != pending_before_failure + 1)
            Fail("UDP reply queue lost a pending packet after OOM");
        active.reset();
        const auto drained_stats = worker.GetResourceStats();
        if (drained_stats.reply_datagrams != 0 || drained_stats.reply_bytes != 0 ||
            drained_stats.active_reply_senders != 0) {
            Fail("UDP reply OOM recovery did not drain to zero");
        }
        worker.ClearReplyQueue(socket_key);
        if (udp_budget.GetUsage().datagrams != budget_before.datagrams ||
            udp_budget.GetUsage().payload_capacity != budget_before.payload_capacity)
            Fail("reply OOM recovery did not return its shared budget");
    };
    exercise_reply_oom("oom-reply");
#endif

    if (worker.EnqueueReply(
            "reply-generation", reply_endpoint_a, make_tiny_payload()) !=
        ::worker_detail::UdpIngress::ReplyEnqueueResult::StartSend) {
        Fail("failed to start the first UDP reply generation");
    }
    auto stale_reply = worker.BeginReplySend("reply-generation");
    if (!stale_reply) {
        Fail("failed to acquire the first UDP reply generation");
    }
    worker.ClearReplyQueue("reply-generation");

    if (worker.EnqueueReply(
            "reply-generation", reply_endpoint_a, make_tiny_payload()) !=
        ::worker_detail::UdpIngress::ReplyEnqueueResult::StartSend) {
        Fail("failed to start the replacement UDP reply generation");
    }
    auto active_reply = worker.BeginReplySend("reply-generation");
    if (!active_reply) {
        Fail("failed to acquire the replacement UDP reply generation");
    }
    if (worker.CompleteReplySend("reply-generation", stale_reply->id)) {
        Fail("stale UDP reply completion matched a replacement queue");
    }
    if (worker.EnqueueReply(
            "reply-generation", reply_endpoint_a, make_tiny_payload()) !=
        ::worker_detail::UdpIngress::ReplyEnqueueResult::Queued) {
        Fail("stale UDP reply completion released a replacement queue");
    }
    auto queued_reply = worker.CompleteReplySend("reply-generation", active_reply->id);
    if (!queued_reply) {
        Fail("replacement UDP reply queue lost its pending datagram");
    }
    if (worker.CompleteReplySend("reply-generation", queued_reply->id)) {
        Fail("drained UDP reply queue still reported pending datagrams");
    }
    worker.ClearReplyQueue("reply-generation");

    ::InboundDatagramOwner owner_a;
    ::InboundDatagramOwner owner_b;
    std::array<uint8_t, 16> owner_a_bytes{};
    std::array<uint8_t, 16> owner_b_bytes{};
    owner_a_bytes.fill(0x11);
    owner_b_bytes.fill(0x22);
    if (!owner_a.Assign(owner_a_bytes) || !owner_b.Assign(owner_b_bytes)) {
        Fail("failed to initialize UDP session owners");
    }
    const ::worker_detail::ClientSessionKey owner_a_session_key{owner_a, 0x1234};
    const ::worker_detail::ClientSessionKey owner_b_session_key{owner_b, 0x1234};
    if (owner_a_session_key == owner_b_session_key) {
        Fail("UDP protocol session key was not scoped by authenticated owner");
    }
    const auto owner_socket = attach_uplink_socket("owner-socket");
    const auto owner_session = worker.CreateClientSession(
        "owner-socket",
        owner_a_session_key,
        io_context,
        {},
        reply_endpoint_a,
        owner_a,
        std::chrono::steady_clock::now(),
        std::chrono::seconds(60));
    if (!owner_session) Fail("failed to create the first UDP owner session");
    // The same protocol session id authenticated as owner_b keys a different
    // row. None exists yet and this handler prepares no response, so the
    // datagram must be dropped rather than fed into owner_a's association.
    deliver_uplink("owner-socket", owner_socket, owner_b, 0x1234, 0xb0);
    auto input_stats = worker.GetResourceStats();
    if (input_stats.associations != 1 || input_stats.input_datagrams != 0 ||
        input_stats.native_dispatches != 0) {
        Fail("UDP session key collision crossed authenticated owners");
    }
    deliver_uplink("owner-socket", owner_socket, owner_a, 0x1234, 0xa1);
    input_stats = worker.GetResourceStats();
    if (input_stats.input_datagrams != 1 || input_stats.input_bytes != 1) {
        Fail("UDP session rejected its authenticated owner");
    }
    const auto second_owner_session = worker.CreateClientSession(
        "owner-socket",
        owner_b_session_key,
        io_context,
        {},
        reply_endpoint_a,
        owner_b,
        std::chrono::steady_clock::now(),
        std::chrono::seconds(60));
    if (!second_owner_session || second_owner_session == owner_session ||
        worker.GetResourceStats().associations != 2) {
        Fail("UDP session ID collision blocked a different authenticated owner");
    }
    deliver_uplink("owner-socket", owner_socket, owner_b, 0x1234, 0xb2);
    input_stats = worker.GetResourceStats();
    if (input_stats.input_datagrams != 2 || input_stats.input_bytes != 2) {
        Fail("UDP input stats did not include both queued sessions");
    }
    if (read_marker(*owner_session) != 0xa1) {
        Fail("UDP owner session did not receive exactly its own payload");
    }
    input_stats = worker.GetResourceStats();
    if (input_stats.input_datagrams != 1 || input_stats.input_bytes != 1) {
        Fail("UDP input stats did not drain after ReadMultiBuffer");
    }
    if (read_marker(*second_owner_session) != 0xb2) {
        Fail("UDP same-id session of another owner did not receive its own payload");
    }
    input_stats = worker.GetResourceStats();
    if (input_stats.input_datagrams != 0 || input_stats.input_bytes != 0) {
        Fail("UDP input stats did not drain both owner sessions");
    }

#ifdef CNODE_TEST_ALLOCATOR_FAULT
    const auto input_baseline = worker.GetResourceStats();
    const auto input_budget_baseline = udp_budget.GetUsage();
    const std::string oom_input_socket = "oom-input-socket";
    const auto oom_socket = attach_uplink_socket(oom_input_socket);
    auto oom_input_session = worker.CreateClientSession(
        oom_input_socket,
        ::worker_detail::ClientSessionKey{default_owner, 9},
        io_context,
        {},
        reply_endpoint_a,
        default_owner,
        std::chrono::steady_clock::now(),
        std::chrono::seconds(60));
    if (!oom_input_session) Fail("failed to create UDP input OOM session");
    const auto deliver_oom_input = [&]() {
        deliver_uplink(oom_input_socket, oom_socket, default_owner, 9, 0x44);
    };
    const auto queued_oom_inputs = [&]() {
        return worker.GetResourceStats().input_datagrams - input_baseline.input_datagrams;
    };
    deliver_oom_input();
    if (queued_oom_inputs() != 1) {
        Fail("failed to prime UDP input OOM queue");
    }
    size_t input_oom_items = 1;
    bool input_oom_observed = false;
    for (; input_oom_items < 250; ++input_oom_items) {
        // Decoding finishes first; the rejected allocation is the next one in
        // the delivery of an already admitted payload to the existing row.
        uplink_script.fail_next_allocation = true;
        try {
            deliver_oom_input();
            if (queued_oom_inputs() != input_oom_items + 1) {
                Fail("UDP input queue rejected before injected allocation failure");
            }
            if (!::memory::reject_next_pmr_allocation) {
                Fail("UDP input queue consumed fault without throwing");
            }
            ::memory::reject_next_pmr_allocation = false;
        } catch (const std::bad_alloc&) {
            input_oom_observed = !::memory::reject_next_pmr_allocation;
            ::memory::reject_next_pmr_allocation = false;
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
    if (udp_budget.GetUsage().datagrams != input_budget_baseline.datagrams + input_oom_items ||
        udp_budget.GetUsage().payload_capacity != input_budget_baseline.payload_capacity +
            input_oom_items * ::buf::Buffer::kSize)
        Fail("input deque allocation failure leaked a shared payload reservation");
    deliver_oom_input();
    if (queued_oom_inputs() != input_oom_items + 1) {
        Fail("UDP input queue did not recover after injected OOM");
    }
    ++input_oom_items;
    while (input_oom_items != 0) {
        bool read_ok = false;
        ::net::co_spawn(
            io_context,
            oom_input_session->ReadMultiBuffer(),
            [&](std::exception_ptr error, ::buf::MultiBuffer payload) {
                read_ok = !error && payload.byte_size() == 1;
            });
        io_context.poll();
        io_context.restart();
        if (!read_ok) Fail("UDP input queue failed to drain after OOM recovery");
        --input_oom_items;
    }
    oom_input_session->Close();
    worker.CloseSocket(oom_input_socket);
    oom_input_session.reset();
    input_stats = worker.GetResourceStats();
    if (input_stats.input_datagrams != input_baseline.input_datagrams ||
        input_stats.input_bytes != input_baseline.input_bytes) {
        Fail("UDP input queue occupancy did not return to baseline");
    }
    if (udp_budget.GetUsage().datagrams != input_budget_baseline.datagrams ||
        udp_budget.GetUsage().payload_capacity != input_budget_baseline.payload_capacity ||
        udp_budget.GetUsage().associations != input_budget_baseline.associations)
        Fail("input OOM cleanup did not return its shared resource budget");
#endif

    ::worker_detail::UdpIngress::ClientSession overflow_session(
        io_context,
        {},
        reply_endpoint_a,
        owner_a, udp_budget, udp_budget.AcquireAssociation());
    ::buf::MultiBuffer oversized_input;
    size_t oversized_bytes = 0;
    while (oversized_bytes <= 512 * 1024) {
        ::buf::BufferGuard buffer{::buf::Buffer::New()};
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
    ::net::co_spawn(
        io_context,
        overflow_session.ReadMultiBuffer(),
        [&](std::exception_ptr error, ::buf::MultiBuffer) {
            try {
                if (error) std::rethrow_exception(error);
            } catch (const ::IoSystemError& e) {
                overflow_reported = e.code() == ::io_error::no_buffer_space;
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

    auto duplicate = ::worker_detail::UdpIngress::MakeSocket(io_context);
    duplicate->open(::udp::v4(), ec);
    if (ec) Fail("failed to open duplicate UDP socket");
    if (worker.AttachSocket("stable-socket", std::move(duplicate)) != nullptr) {
        Fail("duplicate UDP socket attachment was accepted");
    }
    if (worker.FindSocket("stable-socket") != attached || !attached->is_open()) {
        Fail("duplicate attachment replaced the live UDP socket");
    }

    auto response_context = std::make_shared<CountingUdpResponseContext>();
    ::worker_detail::UdpIngress::ClientSession snapshot_reply_session(
        io_context,
        {.socket_key = {}, .socket = {}, .response = response_context, .sink = &snapshot_sink, .worker_id = 0, .fence = {}},
        reply_endpoint_a,
        default_owner, udp_budget, udp_budget.AcquireAssociation());
    auto adopted_worker_state = std::make_shared<int>(-1);
    if (!worker.ReplaceHandler(
            std::make_unique<DummyDatagramHandler>(adopted_worker_state, &uplink_script))) {
        Fail("valid UDP handler replacement was rejected");
    }
    if (*adopted_worker_state != 73) {
        Fail("UDP handler replacement discarded Worker-local protocol state");
    }
    if (owner_session->Closed()) {
        Fail("UDP handler replacement closed a live client session");
    }
    ::buf::BufferGuard snapshot_reply{::buf::Buffer::New()};
    if (!snapshot_reply) Fail("failed to allocate snapshot UDP reply");
    snapshot_reply->Tail()[0] = 0x55;
    snapshot_reply->Produce(1);
    snapshot_reply->SetUDP(callback_source);
    bool snapshot_reply_failed = false;
    ::net::co_spawn(
        io_context,
        snapshot_reply_session.WriteMultiBuffer(
            ::buf::MultiBuffer{std::move(snapshot_reply)}),
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
    worker.CloseSocket("owner-socket");
    association_stats = worker.GetResourceStats();
    if (association_stats.associations != 0) {
        Fail("UDP association cleanup retained resource stats");
    }

    const std::string long_socket_key(160, 's');
    const auto long_socket = attach_uplink_socket(long_socket_key);
    const size_t pmr_allocations_before_cycles =
        thread_resource.resource.allocations;
    const size_t pmr_deallocations_before_cycles =
        thread_resource.resource.deallocations;
    for (size_t cycle = 0; cycle < 1000; ++cycle) {
        const size_t large_allocations_before =
            thread_resource.resource.large_allocations;
        const size_t large_deallocations_before =
            thread_resource.resource.large_deallocations;
        const ::worker_detail::ClientSessionKey long_client_key{default_owner, cycle};
        auto cycle_session = worker.CreateClientSession(
            long_socket_key,
            long_client_key,
            io_context,
            {},
            reply_endpoint_a,
            default_owner,
            std::chrono::steady_clock::now(),
            std::chrono::seconds(60));
        if (!cycle_session) {
            Fail("failed to create a long-key UDP session");
        }
        if (thread_resource.resource.large_allocations <=
            large_allocations_before) {
            Fail("long UDP map keys did not allocate through PMR");
        }
#ifdef CNODE_TEST_ALLOCATOR_FAULT
        ::memory::reject_next_pmr_allocation = true;
        if (worker.GetResourceStats().associations != 1 ||
            !::memory::reject_next_pmr_allocation) {
            Fail("UDP stats inspection allocated PMR memory");
        }
        ::memory::reject_next_pmr_allocation = false;
#endif
        // Reaching the pre-created row proves the borrowed long-key lookup.
        deliver_uplink(long_socket_key, long_socket, default_owner, cycle, 0x6c);
        if (worker.GetResourceStats().input_datagrams != 1) {
            Fail("long UDP keys failed heterogeneous session lookup");
        }
        if (worker.EnqueueReply(
                long_socket_key, reply_endpoint_a, make_tiny_payload()) !=
            ::worker_detail::UdpIngress::ReplyEnqueueResult::StartSend) {
            Fail("long UDP socket key failed reply queue insertion");
        }
        auto long_reply = worker.BeginReplySend(long_socket_key);
        if (!long_reply || worker.GetResourceStats().active_reply_senders != 1) {
            Fail("long UDP reply queue was absent from resource stats");
        }
        (void)worker.CompleteReplySend(long_socket_key, long_reply->id);
        long_reply.reset();
        worker.ClearReplyQueue(long_socket_key);
        cycle_session->Close();
        worker.CleanupClientSessions(long_socket_key);
        cycle_session.reset();
        const auto cycle_stats = worker.GetResourceStats();
        if (cycle_stats.associations != 0 ||
            cycle_stats.input_datagrams != 0 || cycle_stats.input_bytes != 0 ||
            cycle_stats.reply_datagrams != 0 || cycle_stats.reply_bytes != 0 ||
            cycle_stats.active_reply_senders != 0) {
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
    worker.CloseSocket(long_socket_key);
    if (thread_resource.resource.allocations <= pmr_allocations_before_cycles ||
        thread_resource.resource.deallocations <= pmr_deallocations_before_cycles) {
        Fail("long UDP keys did not allocate and release through the Worker PMR");
    }

    bool attached_wait_cancelled = false;
    attached->async_wait(
        ::udp::socket::wait_read,
        [&](::IoErrorCode wait_ec) {
            attached_wait_cancelled =
                wait_ec == ::io_error::operation_aborted;
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

    if (worker.GetResourceStats().associations != 0) {
        Fail("idle cleanup fixture started with retained associations");
    }
    const auto session_now = std::chrono::steady_clock::now();
    constexpr std::string_view idle_cleanup_socket = "idle-cleanup-socket";
    const auto typed_key = [&](uint64_t id) {
        return ::worker_detail::ClientSessionKey{default_owner, id};
    };
    auto make_session = [&](uint64_t id, auto last_active,
                            std::chrono::seconds idle_timeout) {
        return worker.CreateClientSession(
            std::string(idle_cleanup_socket),
            typed_key(id),
            io_context,
            {},
            reply_endpoint_a,
            default_owner,
            last_active,
            idle_timeout);
    };
    auto closed_disabled = make_session(
        1, session_now, std::chrono::seconds::zero());
    auto open_disabled = make_session(
        2, session_now, std::chrono::seconds::zero());
    closed_disabled->Close();
    io_context.run_for(std::chrono::milliseconds(150));
    io_context.restart();
    auto idle_stats = worker.GetResourceStats();
    if (idle_stats.associations != 1 || idle_stats.closed_associations != 0 ||
        open_disabled->Closed()) {
        Fail("disabled idle cleanup retained a closed session or removed an open session");
    }

    auto closed_within_budget = make_session(
        3, session_now, std::chrono::seconds(1));
    auto expired_open = make_session(
        4, session_now - std::chrono::seconds(2), std::chrono::seconds(1));
    auto fresh_open = make_session(
        5, session_now, std::chrono::seconds(1));
    closed_within_budget->Close();
    io_context.run_for(std::chrono::milliseconds(150));
    io_context.restart();
    idle_stats = worker.GetResourceStats();
    // Rows 2 and 5 are the only open sessions; any surviving row 3 or 4 would
    // be counted as closed.
    if (idle_stats.associations != 2 || idle_stats.closed_associations != 0 ||
        !expired_open->Closed() || open_disabled->Closed() ||
        fresh_open->Closed()) {
        Fail("positive idle cleanup did not independently remove closed and expired sessions");
    }

    constexpr size_t closed_session_count = 32;
    std::array<::worker_detail::UdpIngress::ClientSessionPtr,
               closed_session_count> closed_sessions;
    for (size_t i = 0; i < closed_session_count; ++i) {
        closed_sessions[i] = make_session(
            100 + i, session_now, std::chrono::seconds::zero());
        closed_sessions[i]->Close();
    }
    io_context.run_for(std::chrono::milliseconds(150));
    io_context.restart();
    idle_stats = worker.GetResourceStats();
    if (idle_stats.associations != 2 || idle_stats.closed_associations != 0) {
        Fail("distinct closed UDP session key remained retained with idle timeout disabled");
    }
    worker.CleanupClientSessions(idle_cleanup_socket);

}
