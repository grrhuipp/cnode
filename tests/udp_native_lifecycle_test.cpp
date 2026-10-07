#include "async_allocation_fault.hpp"
#include "udp_native_lifecycle_allocation.hpp"
#include "worker/udp_association_reclaimer.hpp"
#include "worker/udp_ingress.hpp"

#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/stats.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/features/routing/dispatcher.hpp"
#include "acppnode/infra/config_types.hpp"
#include "acppnode/proxy/inbound.hpp"
#include "acppnode/proxy/inbound_datagram.hpp"
#include "acppnode/transport/async_stream.hpp"

#include <asio/as_tuple.hpp>
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/steady_timer.hpp>
#include <asio/use_awaitable.hpp>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
#include <memory_resource>
#include <new>
#include <string_view>

namespace {
using namespace std::chrono_literals;
using Ingress = acpp::worker_detail::UdpIngress;
using Reclaimer = acpp::worker_detail::UdpAssociationReclaimer;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

class Response final : public acpp::InboundDatagramResponse {
public:
    acpp::buf::MultiBuffer Encode(acpp::UDPPacketView) override { return {}; }
};

class LongMetadataFaultResource final : public std::pmr::memory_resource {
public:
    bool armed = false;
    size_t failures = 0;

private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (armed && bytes >= 2048) {
            armed = false;
            ++failures;
            throw std::bad_alloc();
        }
        if (void* memory = acpp::memory::AllocatePmr(bytes, alignment)) return memory;
        throw std::bad_alloc();
    }
    void do_deallocate(void* pointer, size_t bytes, size_t alignment) override {
        acpp::memory::DeallocatePmr(pointer, bytes, alignment);
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

class NativeInbound final : public acpp::Inbound {
public:
    explicit NativeInbound(LongMetadataFaultResource* fault = nullptr)
        : fault_(fault) {}

    acpp::net::awaitable<acpp::RelayResult> Process(
        std::unique_ptr<acpp::AsyncStream>, acpp::routing::Dispatcher&,
        const acpp::proxyman::inbound::ReceiverSettings&, acpp::net::io_context&,
        acpp::session::Context&, const acpp::TimeoutsConfig&, uint32_t) override {
        co_return acpp::RelayResult{};
    }

    std::expected<acpp::InboundDatagramResult, acpp::ErrorCode> Process(
        const acpp::InboundDatagramRequest& request) override {
        acpp::InboundDatagramResult result;
        constexpr std::array<uint8_t, 1> owner{0x47};
        if (!result.session_owner.Assign(owner))
            return std::unexpected(acpp::ErrorCode::RESOURCE_EXHAUSTED);
        result.session_key = request.payload.front() == 0x63
            ? "client-b" : "client-a";
        result.response = acpp::memory::AllocateShared<Response>();
        result.target = acpp::TargetAddress(
            acpp::net::ip::address_v4::loopback(), 53);
        auto buffer = acpp::buf::BufferGuard{acpp::buf::Buffer::New()};
        if (!buffer) return std::unexpected(acpp::ErrorCode::RESOURCE_EXHAUSTED);
        buffer->Tail()[0] = request.payload.front();
        buffer->Produce(1);
        result.payload.push_back(std::move(buffer));
        if (fault_ && !fault_injected_) {
            fault_injected_ = true;
            fault_->armed = true;
        }
        return result;
    }

private:
    LongMetadataFaultResource* fault_ = nullptr;
    bool fault_injected_ = false;
};

class GateDispatcher final : public acpp::routing::Dispatcher {
public:
    explicit GateDispatcher(acpp::net::io_context& io) : gate(io) {
        gate.expires_after(10s);
    }

    acpp::net::awaitable<acpp::RelayResult> Dispatch(
        acpp::net::io_context&, const acpp::routing::DispatchPolicy& policy,
        std::unique_ptr<acpp::AsyncStream>, acpp::transport::Link link,
        acpp::InitialPayload, acpp::session::Context& context, acpp::StatsShard&,
        const acpp::TimeoutsConfig&) override {
        const auto* forced = std::get_if<acpp::routing::ForceOutbound>(
            &policy.outbound);
        if (!forced || forced->outbound_tag != "loopback")
            Fail("native job did not retain its narrow dispatch policy snapshot");
        if (context.inbound.tag != "receiver-tag" ||
            context.inbound.protocol != "native-test" ||
            context.inbound.security != "tls" ||
            context.inbound.tags.size() != 1 ||
            context.inbound.tags.front() != "route-tag")
            Fail("native request retained borrowed receiver metadata");
        ++dispatches;
        auto payload = co_await link.reader->ReadMultiBuffer();
        if (payload.byte_size() != 1) Fail("first native UDP payload was not delivered");
        uint8_t first_byte = 0;
        for (const auto* buffer : payload) {
            if (!buffer || buffer->Len() != 1 ||
                (buffer->Bytes()[0] != 0x62 && buffer->Bytes()[0] != 0x63))
                Fail("native UDP dispatcher received the wrong payload");
            first_byte = buffer->Bytes()[0];
        }
        ++packets_read;
        acpp::transport::CancellationSubscription cancellation(
            link.reader->Cancellation(), &OnCancel, this);
        auto [ec] = co_await gate.async_wait(
            acpp::net::as_tuple(acpp::net::use_awaitable));
        (void)ec;
        (void)first_byte;
        co_return acpp::RelayResult{};
    }

    static void OnCancel(void* owner, acpp::transport::Cancellation) noexcept {
        auto& self = *static_cast<GateDispatcher*>(owner);
        ++self.cancellations;
        if (self.reenter_stop && !self.stop_reentered) {
            self.stop_reentered = true;
            self.ingress->RequestStop();
        }
    }

    acpp::net::steady_timer gate;
    Ingress* ingress = nullptr;
    size_t dispatches = 0;
    size_t packets_read = 0;
    size_t cancellations = 0;
    bool reenter_stop = false;
    bool stop_reentered = false;
};

class ReplySink final : public acpp::worker_detail::UdpReplySink {
public:
    bool EnqueueUdpReply(const std::string&, acpp::udp::socket*,
                         acpp::udp::endpoint, acpp::buf::MultiBuffer,
                         uint32_t) override { return true; }
};

acpp::net::awaitable<void> ObserveJoin(Ingress& ingress, bool& returned) {
    co_await ingress.AsyncJoin();
    returned = true;
}

acpp::net::awaitable<void> VerifyJoinFrameAllocationFailure(
    Ingress& ingress, bool& verified) {
    const auto jobs_before = ingress.GetResourceStats().native_dispatches;
    const auto injections_before =
        udp_native_lifecycle_fault::StandardNewFailures();
    udp_native_lifecycle_fault::ArmStandardNew(0);
    bool allocation_failed = false;
    try {
        co_await ingress.AsyncJoin();
    } catch (const std::bad_alloc&) {
        allocation_failed = true;
    }
    udp_native_lifecycle_fault::Disarm();
    if (!allocation_failed ||
        udp_native_lifecycle_fault::StandardNewFailures() != injections_before + 1 ||
        jobs_before == 0 || ingress.GetResourceStats().native_dispatches != jobs_before)
        Fail("join-frame allocation failure lost its still-running native jobs");
    verified = true;
}

acpp::net::awaitable<void> ObserveCancelledJoin(
    Ingress& ingress, bool& returned, bool& parent_cancelled,
    bool& throw_setting, acpp::net::cancellation_signal& parent_signal) {
    co_await acpp::net::this_coro::throw_if_cancelled(false);
    // Cancel after the child starts, but before joining. Cancelling co_spawn
    // before entry would prevent this coroutine from ever calling AsyncJoin.
    parent_signal.emit(acpp::net::cancellation_type::terminal);
    co_await ingress.AsyncJoin();
    const auto cancellation_state =
        co_await acpp::net::this_coro::cancellation_state;
    parent_cancelled = cancellation_state.cancelled() !=
        acpp::net::cancellation_type::none;
    throw_setting = co_await acpp::net::this_coro::throw_if_cancelled();
    returned = true;
}

acpp::proxyman::inbound::ReceiverSettings MakeReceiver() {
    return acpp::proxyman::inbound::ReceiverSettings{
        .inbound_tag = "receiver-tag",
        .inbound_tags = {"route-tag"},
        .protocol = "native-test",
        .stream_settings = {.security = "tls"},
        .dispatch_policy = {
            .outbound = acpp::routing::ForceOutbound{"loopback"}},
        .has_route_inbound_tags = true};
}

void VerifyPreparationOom(acpp::net::io_context& io, Reclaimer& reclaimer) {
    io.restart();
    LongMetadataFaultResource fault_resource;
    struct PmrDefaultScope {
        explicit PmrDefaultScope(std::pmr::memory_resource* resource)
            : previous(std::pmr::set_default_resource(resource)) {}
        ~PmrDefaultScope() { std::pmr::set_default_resource(previous); }
        std::pmr::memory_resource* previous;
    } pmr_scope(&fault_resource);

    Ingress ingress("native-oom", std::make_unique<NativeInbound>(&fault_resource),
                    reclaimer, io);
    auto socket = Ingress::MakeSocket(io);
    acpp::IoErrorCode ec;
    socket->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open native OOM test socket");
    socket->bind({acpp::net::ip::address_v4::loopback(), 0}, ec);
    if (ec || !ingress.AttachSocket("oom-socket", socket))
        Fail("failed to attach native OOM test socket");
    GateDispatcher dispatcher(io);
    acpp::StatsShard stats;
    acpp::TimeoutsConfig timeouts;
    timeouts.idle = 0;
    ReplySink reply_sink;
    auto receiver = MakeReceiver();
    receiver.inbound_tag.assign(4096, 'm');
    constexpr std::array<uint8_t, 1> packet{0x62};
    bool allocation_failed = false;
    try {
        ingress.ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
            .socket_key = "oom-socket",
            .sock = socket.get(),
            .client_endpoint = {acpp::net::ip::address_v4::loopback(), 46123},
            .payload = packet,
            .receiver = &receiver,
            .io_context = io,
            .dispatcher = dispatcher,
            .stats = stats,
            .timeouts = timeouts,
            .worker_id = 5,
            .reply_sink = reply_sink,
        });
    } catch (const std::bad_alloc&) {
        allocation_failed = true;
    }
    auto failed_stats = ingress.GetResourceStats();
    if (!allocation_failed || fault_resource.failures != 1 ||
        failed_stats.associations != 1 || failed_stats.closed_associations != 1 ||
        failed_stats.native_dispatches != 0)
        Fail("native metadata PMR failure left an open ghost association or job");
    io.run_for(160ms);
    io.restart();
    if (ingress.GetResourceStats().associations != 0)
        Fail("closed zero-idle native association was not reclaimed naturally");

    receiver.inbound_tag = "receiver-tag";
    acpp::InboundDatagramOwner maintenance_owner;
    constexpr std::array<uint8_t, 1> maintenance_owner_bytes{0x48};
    if (!maintenance_owner.Assign(maintenance_owner_bytes))
        Fail("failed to prepare maintenance-only session owner");
    auto maintenance_session = ingress.CreateClientSession(
        "maintenance-socket", "held-open", io,
        [](acpp::UDPPacketView, const acpp::udp::endpoint&) {},
        {acpp::net::ip::address_v4::loopback(), 48123},
        maintenance_owner, std::chrono::steady_clock::now(), 0s);
    if (!maintenance_session)
        Fail("failed to prime the association maintenance timer");
    auto expect_spawn_failure = [&](
        udp_native_lifecycle_fault::DispatchStageFault fault, int budget,
        uint16_t client_port) {
        const auto standard_before =
            udp_native_lifecycle_fault::StandardNewFailures();
        const auto aligned_before =
            udp_native_lifecycle_fault::AsioAlignedNewFailures();
        udp_native_lifecycle_fault::ArmAtDispatchStage(fault, budget);
        bool spawn_failed = false;
        try {
            ingress.ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
                .socket_key = "oom-socket",
                .sock = socket.get(),
                .client_endpoint = {
                    acpp::net::ip::address_v4::loopback(), client_port},
                .payload = packet,
                .receiver = &receiver,
                .io_context = io,
                .dispatcher = dispatcher,
                .stats = stats,
                .timeouts = timeouts,
                .worker_id = 5,
                .reply_sink = reply_sink,
            });
        } catch (const std::bad_alloc&) {
            spawn_failed = true;
        }
        udp_native_lifecycle_fault::Disarm();
        const auto injections = fault ==
                udp_native_lifecycle_fault::DispatchStageFault::StandardNew
            ? udp_native_lifecycle_fault::StandardNewFailures() - standard_before
            : udp_native_lifecycle_fault::AsioAlignedNewFailures() - aligned_before;
        auto spawn_failure_stats = ingress.GetResourceStats();
        if (!spawn_failed || injections != 1 ||
            spawn_failure_stats.associations != 2 ||
            spawn_failure_stats.closed_associations != 1 ||
            spawn_failure_stats.native_dispatches != 0)
            Fail("injected native spawn allocation failure left a ghost association or job");
        io.run_for(160ms);
        io.restart();
        if (ingress.GetResourceStats().associations != 1 ||
            ingress.FindClientSession("maintenance-socket", "held-open") !=
                maintenance_session)
            Fail("spawn-failed native association did not reach natural GC");
    };

    // These are global C++ coroutine-frame allocations: budget 0 rejects
    // RunNativeDispatch's frame, budget 1 rejects co_spawn's entry frame.
    for (int allocation_index = 0; allocation_index != 2; ++allocation_index)
        expect_spawn_failure(
            udp_native_lifecycle_fault::DispatchStageFault::StandardNew,
            allocation_index, static_cast<uint16_t>(46124 + allocation_index));
    // Keep the previous aligned_new fault as a separate real co_spawn
    // operation-allocation check; it is not evidence of coroutine-frame OOM.
    expect_spawn_failure(
        udp_native_lifecycle_fault::DispatchStageFault::AsioAlignedNew, 0, 46126);
    ingress.CleanupClientSessions("maintenance-socket");
    maintenance_session.reset();

    ingress.ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
        .socket_key = "oom-socket",
        .sock = socket.get(),
        .client_endpoint = {acpp::net::ip::address_v4::loopback(), 46123},
        .payload = packet,
        .receiver = &receiver,
        .io_context = io,
        .dispatcher = dispatcher,
        .stats = stats,
        .timeouts = timeouts,
        .worker_id = 5,
        .reply_sink = reply_sink,
    });
    io.poll();
    io.restart();
    if (dispatcher.dispatches != 1 || dispatcher.packets_read != 1 ||
        ingress.GetResourceStats().native_dispatches != 1)
        Fail("native ingress did not recover and deliver the first packet after PMR OOM");
    ingress.RequestStop();
    bool joined = false;
    acpp::net::co_spawn(io, ObserveJoin(ingress, joined), acpp::net::detached);
    dispatcher.gate.cancel();
    io.run();
    if (!joined || ingress.GetResourceStats().native_dispatches != 0)
        Fail("native job did not join after metadata OOM recovery");
}

void VerifySocketIdentityRecycle(
    acpp::net::io_context& io, Reclaimer& reclaimer) {
    io.restart();
    Ingress ingress("native-reuse", std::make_unique<NativeInbound>(), reclaimer, io);
    auto old_socket = Ingress::MakeSocket(io);
    acpp::IoErrorCode ec;
    old_socket->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open old socket identity test socket");
    old_socket->bind({acpp::net::ip::address_v4::loopback(), 0}, ec);
    if (ec || !ingress.AttachSocket("identity-socket", old_socket))
        Fail("failed to attach old socket identity");
    GateDispatcher dispatcher(io);
    acpp::StatsShard stats;
    acpp::TimeoutsConfig timeouts;
    ReplySink reply_sink;
    auto receiver = MakeReceiver();
    constexpr std::array<uint8_t, 1> packet{0x62};
    auto process = [&](const Ingress::SocketPtr& current) {
        ingress.ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
            .socket_key = "identity-socket",
            .sock = current.get(),
            .client_endpoint = {acpp::net::ip::address_v4::loopback(), 47123},
            .payload = packet,
            .receiver = &receiver,
            .io_context = io,
            .dispatcher = dispatcher,
            .stats = stats,
            .timeouts = timeouts,
            .worker_id = 6,
            .reply_sink = reply_sink,
        });
    };
    process(old_socket);
    io.poll();
    io.restart();
    if (dispatcher.dispatches != 1 || dispatcher.packets_read != 1)
        Fail("old socket identity did not start its native dispatch");
    acpp::InboundDatagramOwner owner;
    constexpr std::array<uint8_t, 1> owner_bytes{0x47};
    if (!owner.Assign(owner_bytes)) Fail("failed to create socket identity owner");
    const auto client_key = owner.ScopeSessionKey("client-a");
    auto old_session = ingress.FindClientSession("identity-socket", client_key);
    if (!old_session) Fail("old socket session was not created");
    ingress.CloseSocket("identity-socket");

    auto replacement_socket = Ingress::MakeSocket(io);
    replacement_socket->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open replacement socket identity");
    replacement_socket->bind({acpp::net::ip::address_v4::loopback(), 0}, ec);
    if (ec || !ingress.AttachSocket("identity-socket", replacement_socket))
        Fail("failed to attach replacement socket identity");
    process(old_socket);
    if (ingress.GetResourceStats().associations != 0 ||
        ingress.GetResourceStats().native_dispatches != 1 ||
        !ingress.OwnsSocket("identity-socket", replacement_socket.get()))
        Fail("stale socket datagram crossed into its replacement identity");
    process(replacement_socket);
    io.poll();
    io.restart();
    auto replacement_session = ingress.FindClientSession("identity-socket", client_key);
    if (!replacement_session || replacement_session == old_session ||
        dispatcher.dispatches != 2 || dispatcher.packets_read != 2 ||
        ingress.GetResourceStats().native_dispatches != 2)
        Fail("replacement socket did not create an independent native job");

    replacement_session->Close();
    bool joined = false;
    acpp::net::co_spawn(io, ObserveJoin(ingress, joined), acpp::net::detached);
    dispatcher.gate.cancel();
    io.run();
    if (!joined || ingress.GetResourceStats().native_dispatches != 0 ||
        !ingress.OwnsSocket("identity-socket", replacement_socket.get()) ||
        !replacement_socket->is_open())
        Fail("old job completion damaged the replacement socket identity");
    ingress.RequestStop();
}

void VerifyUplinkRefresh(acpp::net::io_context& io, Reclaimer& reclaimer) {
    io.restart();
    Ingress ingress("native-refresh", std::make_unique<NativeInbound>(), reclaimer, io);
    auto socket = Ingress::MakeSocket(io);
    acpp::IoErrorCode ec;
    socket->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open UDP refresh test socket");
    socket->bind({acpp::net::ip::address_v4::loopback(), 0}, ec);
    if (ec || !ingress.AttachSocket("refresh-socket", socket))
        Fail("failed to attach UDP refresh test socket");

    GateDispatcher dispatcher(io);
    acpp::StatsShard stats;
    acpp::TimeoutsConfig timeouts;
    timeouts.idle = 1;
    ReplySink reply_sink;
    auto receiver = MakeReceiver();
    constexpr std::array<uint8_t, 1> packet{0x62};
    auto process_packet = [&]() {
        ingress.ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
            .socket_key = "refresh-socket",
            .sock = socket.get(),
            .client_endpoint = {acpp::net::ip::address_v4::loopback(), 45123},
            .payload = packet,
            .receiver = &receiver,
            .io_context = io,
            .dispatcher = dispatcher,
            .stats = stats,
            .timeouts = timeouts,
            .worker_id = 4,
            .reply_sink = reply_sink,
        });
    };
    process_packet();
    io.poll();
    io.restart();
    if (dispatcher.dispatches != 1 || dispatcher.packets_read != 1)
        Fail("UDP refresh test did not start its native session");
    acpp::InboundDatagramOwner owner;
    constexpr std::array<uint8_t, 1> owner_bytes{0x47};
    if (!owner.Assign(owner_bytes)) Fail("failed to create refresh session owner");
    const auto client_key = owner.ScopeSessionKey("client-a");
    auto session = ingress.FindClientSession("refresh-socket", client_key);
    if (!session) Fail("UDP refresh session row is missing");

    acpp::net::steady_timer refresh(io);
    refresh.expires_after(650ms);
    refresh.async_wait([&](acpp::IoErrorCode timer_ec) {
        if (!timer_ec) process_packet();
    });
    io.run_for(1250ms);
    io.restart();
    if (ingress.FindClientSession("refresh-socket", client_key) != session ||
        session->Closed())
        Fail("native uplink failed to refresh its association idle timestamp");

    io.run_for(1100ms);
    io.restart();
    if (ingress.FindClientSession("refresh-socket", client_key) || !session->Closed())
        Fail("refreshed native association did not expire naturally after idleness");
    ingress.RequestStop();
    bool joined = false;
    acpp::net::co_spawn(io, ObserveJoin(ingress, joined), acpp::net::detached);
    dispatcher.gate.cancel();
    io.run();
    if (!joined || ingress.GetResourceStats().native_dispatches != 0)
        Fail("idle-expired native dispatch did not join at actual completion");
}

} // namespace

int main() {
    std::set_terminate([] {
        try {
            if (const auto error = std::current_exception()) std::rethrow_exception(error);
        } catch (const std::exception& error) {
            std::fprintf(stderr, "native UDP fixture terminated: %s\n", error.what());
        } catch (...) {
            std::fprintf(stderr, "native UDP fixture terminated: unknown exception\n");
        }
        std::fflush(stderr);
        std::_Exit(99);
    });
    acpp::memory::ThreadPoolFacade owner_resource;
    struct RestoreDefaultResource {
        std::pmr::memory_resource* previous;
        ~RestoreDefaultResource() { std::pmr::set_default_resource(previous); }
    } resource_scope{std::pmr::set_default_resource(&owner_resource)};
    acpp::net::io_context io;
    auto& scheduler = acpp::TimeoutScheduler::ForIoContext(io);
    Reclaimer reclaimer(scheduler);
    Ingress ingress("native-test", std::make_unique<NativeInbound>(), reclaimer, io);
    auto socket = Ingress::MakeSocket(io);
    acpp::IoErrorCode ec;
    socket->open(acpp::udp::v4(), ec);
    if (ec) Fail("failed to open native UDP test socket");
    socket->bind({acpp::net::ip::address_v4::loopback(), 0}, ec);
    if (ec || !ingress.AttachSocket("native-socket", socket))
        Fail("failed to attach native UDP test socket");

    GateDispatcher dispatcher(io);
    dispatcher.ingress = &ingress;
    dispatcher.reenter_stop = true;
    acpp::StatsShard stats;
    acpp::TimeoutsConfig timeouts;
    ReplySink reply_sink;
    auto receiver = MakeReceiver();
    constexpr std::array<uint8_t, 1> datagram{0x62};
    ingress.ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
        .socket_key = "native-socket",
        .sock = socket.get(),
        .client_endpoint = {acpp::net::ip::address_v4::loopback(), 43123},
        .payload = datagram,
        .receiver = &receiver,
        .io_context = io,
        .dispatcher = dispatcher,
        .stats = stats,
        .timeouts = timeouts,
        .worker_id = 3,
        .reply_sink = reply_sink,
    });
    constexpr std::array<uint8_t, 1> second_datagram{0x63};
    ingress.ProcessDatagram(acpp::worker_detail::UdpDatagramContext{
        .socket_key = "native-socket",
        .sock = socket.get(),
        .client_endpoint = {acpp::net::ip::address_v4::loopback(), 43124},
        .payload = second_datagram,
        .receiver = &receiver,
        .io_context = io,
        .dispatcher = dispatcher,
        .stats = stats,
        .timeouts = timeouts,
        .worker_id = 3,
        .reply_sink = reply_sink,
    });
    receiver.inbound_tag.assign(256, 'x');
    receiver.inbound_tags.front().assign(256, 'y');
    receiver.protocol.assign(256, 'z');
    receiver.stream_settings.security.assign(256, 'q');
    std::get<acpp::routing::ForceOutbound>(receiver.dispatch_policy.outbound)
        .outbound_tag.assign(256, 'r');

    acpp::InboundDatagramOwner owner;
    constexpr std::array<uint8_t, 1> owner_bytes{0x47};
    if (!owner.Assign(owner_bytes)) Fail("failed to prepare test owner");
    auto session_a = ingress.FindClientSession(
        "native-socket", owner.ScopeSessionKey("client-a"));
    auto session_b = ingress.FindClientSession(
        "native-socket", owner.ScopeSessionKey("client-b"));
    if (!session_a || !session_b)
        Fail("native UDP associations were not installed");
    if (!ingress.ReplaceHandler(std::make_unique<NativeInbound>()) ||
        ingress.FindClientSession("native-socket", owner.ScopeSessionKey("client-a")) != session_a ||
        ingress.FindClientSession("native-socket", owner.ScopeSessionKey("client-b")) != session_b ||
        ingress.GetResourceStats().native_dispatches != 2)
        Fail("same-socket handler replacement disturbed active native jobs");

    io.poll();
    io.restart();
    if (dispatcher.dispatches != 2 || dispatcher.packets_read != 2)
        Fail("native UDP requests did not dispatch their first packets exactly once");

    ingress.CloseSocket("native-socket");
    auto stats_after_close = ingress.GetResourceStats();
    if (dispatcher.cancellations != 2 || stats_after_close.associations != 0 ||
        stats_after_close.native_dispatches != 2)
        Fail("socket batch reentry confused row removal with native job completion");

    bool join_fault_verified = false;
    acpp::net::co_spawn(io, VerifyJoinFrameAllocationFailure(ingress, join_fault_verified),
                       acpp::net::detached);
    io.run_for(10ms);
    io.restart();
    if (!join_fault_verified)
        Fail("join-frame allocation fault was not exercised before normal join recovery");

    bool joined = false;
    bool parent_cancelled = false;
    bool join_throw_setting = true;
    acpp::net::cancellation_signal parent_signal;
    acpp::net::co_spawn(
        io, ObserveCancelledJoin(ingress, joined, parent_cancelled,
                                 join_throw_setting, parent_signal),
        acpp::net::bind_cancellation_slot(
            parent_signal.slot(), acpp::net::detached));
    io.run_for(20ms);
    io.restart();
    if (joined || ingress.GetResourceStats().native_dispatches != 2)
        Fail("native join returned before actual dispatcher completion");
    ingress.RequestStop();
    ingress.RequestStop();
    if (ingress.GetResourceStats().native_dispatches != 2)
        Fail("native stop treated cancellation as actual job completion");
    dispatcher.gate.cancel();
    io.run();
    if (!joined || !parent_cancelled || join_throw_setting ||
        ingress.GetResourceStats().native_dispatches != 0)
        Fail("native join lost parent cancellation state before drain completion");

    VerifyPreparationOom(io, reclaimer);
    VerifySocketIdentityRecycle(io, reclaimer);
    VerifyUplinkRefresh(io, reclaimer);
    return 0;
}
