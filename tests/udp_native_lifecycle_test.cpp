#include <stdexcept>
#include <gtest/gtest.h>

#include "worker/udp_association_reclaimer.hpp"
#include "worker/udp_ingress.hpp"
#include "worker/udp_handoff_directory.hpp"
#include "ss_udp.hpp"
#include "inbound/ss_inbound.hpp"

#include "app/proxyman/inbound/receiver_settings.hpp"
#include "app/stats.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/user_profile.hpp"
#include "common/session.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
#include "proxy/inbound_datagram.hpp"
#include "transport/async_stream.hpp"

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
#include <span>
#include <string_view>
#include <vector>

namespace {
using namespace std::chrono_literals;
using Ingress = ::worker_detail::UdpIngress;
using Reclaimer = ::worker_detail::UdpAssociationReclaimer;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

class Response final : public ::InboundDatagramResponse {
public:
    ::buf::MultiBuffer Encode(::UDPPacketView) override { return {}; }
};


class NativeInbound final : public ::Inbound {
public:

    ::net::awaitable<::RelayResult> Process(
        std::unique_ptr<::AsyncStream>, ::routing::Dispatcher&,
        const ::proxyman::inbound::ReceiverSettings&, ::net::io_context&,
        ::session::Context&, const ::TimeoutsConfig&, uint32_t) override {
        co_return ::RelayResult{};
    }

    tl::expected<::InboundDatagramResult, ::ErrorCode> Process(
        const ::InboundDatagramRequest& request) override {
        ::InboundDatagramResult result;
        result.user = &profile_;
        result.tracker = tracker_;
        constexpr std::array<uint8_t, 1> owner{0x47};
        if (!result.session_owner.Assign(owner))
            return tl::unexpected(::ErrorCode::RESOURCE_EXHAUSTED);
        result.session_id = request.payload.front() == 0x63 ? 2 : 1;
        result.target = ::TargetAddress(
            ::net::ip::address_v4::loopback(), 53);
        auto buffer = ::buf::BufferGuard{::buf::Buffer::New()};
        if (!buffer) return tl::unexpected(::ErrorCode::RESOURCE_EXHAUSTED);
        buffer->Tail()[0] = request.payload.front();
        buffer->Produce(1);
        result.payload.push_back(std::move(buffer));
        return result;
    }
    tl::expected<std::shared_ptr<::InboundDatagramResponse>, ::ErrorCode>
    CreateDatagramResponse(const ::InboundDatagramResult&) override {
        return ::memory::AllocateShared<Response>();
    }

private:
    std::shared_ptr<::UserOnlineTracker> tracker_ = std::make_shared<::UserOnlineTracker>();
    ::UserProfile profile_;
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

    ::net::awaitable<::RelayResult> Dispatch(
        ::net::io_context&, const ::routing::DispatchPolicy& policy,
        std::unique_ptr<::AsyncStream>, ::transport::Link link,
        ::InitialPayload, ::session::Context& context, ::StatsShard&,
        const ::TimeoutsConfig&) override {
        const auto* forced = std::get_if<::routing::ForceOutbound>(
            &policy.outbound);
        if (!forced || forced->outbound_tag != "loopback")
            Fail("native job did not retain its narrow dispatch policy snapshot");
        if (context.inbound.tag != "receiver-tag" ||
            context.inbound.tags.size() != 1 ||
            context.inbound.tags.front() != "route-tag")
            Fail("native request retained borrowed receiver metadata");
        if (dispatches == sessions.size())
            Fail("native dispatcher started more jobs than the fixture records");
        // The native link reader is the association's own ClientSession.
        sessions[dispatches] = static_cast<Ingress::ClientSession*>(link.reader);
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
        RequestCancellation cancellation(*this);
        cancellation.Resubscribe(link.reader->Cancellation());
        auto [ec] = co_await gate.async_wait(
            ::net::as_tuple(::net::use_awaitable));
        (void)ec;
        (void)first_byte;
        co_return ::RelayResult{};
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

class ReplySink final : public ::worker_detail::UdpReplySink {
public:
    bool EnqueueUdpReply(std::string_view, ::udp::socket*,
                         ::udp::endpoint, ::buf::MultiBuffer,
                         uint32_t,
                         std::shared_ptr<::worker_detail::UdpReplyFence> = {}) override {
        return true;
    }
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

::proxyman::inbound::ReceiverSettings MakeReceiver() {
    auto receiver = ::proxyman::inbound::ReceiverSettings{
        .inbound_tag = "receiver-tag",
        .inbound_tags = {"route-tag"},
        .protocol = "native-test",
        .stream_settings = {},
        .dispatch_policy = {
            .sniffing = {},
            .outbound = ::routing::ForceOutbound{"loopback"}},
        .has_route_inbound_tags = true};
    receiver.stream_settings.security = "tls";
    return receiver;
}


void VerifySocketIdentityRecycle(
    ::net::io_context& io, Reclaimer& reclaimer) {
    io.restart();
    ::worker_detail::UdpResourceBudget budget({
        .associations = 2, .datagrams = 8, .payload_capacity = 64 * 1024});
    Ingress ingress("native-reuse", std::make_unique<NativeInbound>(), reclaimer, budget, io);
    Ingress other("native-other", std::make_unique<NativeInbound>(), reclaimer, budget, io);
    auto old_socket = Ingress::MakeSocket(io);
    ::IoErrorCode ec;
    old_socket->open(::udp::v4(), ec);
    if (ec) Fail("failed to open old socket identity test socket");
    old_socket->bind({::net::ip::address_v4::loopback(), 0}, ec);
    if (ec || !ingress.AttachSocket("identity-socket", old_socket))
        Fail("failed to attach old socket identity");
    GateDispatcher dispatcher(io);
    ::StatsShard stats;
    ::TimeoutsConfig timeouts;
    ReplySink reply_sink;
    auto receiver = MakeReceiver();
    constexpr std::array<uint8_t, 1> packet{0x62};
    auto process = [&](const Ingress::SocketPtr& current) {
        ingress.ProcessDatagram(::worker_detail::UdpDatagramContext{
            .socket_key = "identity-socket",
            .sock = current.get(),
            .client_endpoint = {::net::ip::address_v4::loopback(), 47123},
            .payload = packet,
            .receiver = &receiver,
            .io_context = io,
            .dispatcher = &dispatcher,
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
    ::InboundDatagramOwner owner;
    constexpr std::array<uint8_t, 1> owner_bytes{0x47};
    if (!owner.Assign(owner_bytes)) Fail("failed to create socket identity owner");
    const ::worker_detail::ClientSessionKey client_key{owner, 1};
    auto* const old_session = dispatcher.sessions[0];
    if (!old_session || ingress.GetResourceStats().associations != 1)
        Fail("old socket session was not created");
    ingress.CloseSocket("identity-socket");

    auto replacement_socket = Ingress::MakeSocket(io);
    replacement_socket->open(::udp::v4(), ec);
    if (ec) Fail("failed to open replacement socket identity");
    replacement_socket->bind({::net::ip::address_v4::loopback(), 0}, ec);
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
    auto* const replacement_session = dispatcher.sessions[1];
    if (!replacement_session || replacement_session == old_session ||
        ingress.GetResourceStats().associations != 1 ||
        dispatcher.dispatches != 2 || dispatcher.packets_read != 2 ||
        ingress.GetResourceStats().native_dispatches != 2)
        Fail("replacement socket did not create an independent native job");
    const auto create_other = [&] {
        return other.CreateClientSession("other-socket", client_key, io,
            {},
            {::net::ip::address_v4::loopback(), 47124}, owner,
            std::chrono::steady_clock::now(), 0s);
    };
    if (budget.GetUsage().associations != 2 || create_other())
        Fail("retired dispatcher ownership bypassed the shared association limit");

    replacement_session->Close();
    bool joined = false;
    ::net::co_spawn(io, ObserveJoin(ingress, joined), ::net::detached);
    dispatcher.gate.cancel();
    io.run();
    if (!joined || ingress.GetResourceStats().native_dispatches != 0 ||
        !ingress.OwnsSocket("identity-socket", replacement_socket.get()) ||
        !replacement_socket->is_open())
        Fail("old job completion damaged the replacement socket identity");
    auto recovered = create_other();
    // Both native jobs completed and released their rows: only `recovered`
    // holds a lease now.
    if (!recovered || budget.GetUsage().associations != 1)
        Fail("dispatcher completion did not return its association lease");
    other.RequestStop();
    ingress.RequestStop();
}

void VerifyUplinkRefresh(::net::io_context& io, Reclaimer& reclaimer) {
    io.restart();
    ::worker_detail::UdpResourceBudget budget;
    Ingress ingress("native-refresh", std::make_unique<NativeInbound>(), reclaimer, budget, io);
    auto socket = Ingress::MakeSocket(io);
    ::IoErrorCode ec;
    socket->open(::udp::v4(), ec);
    if (ec) Fail("failed to open UDP refresh test socket");
    socket->bind({::net::ip::address_v4::loopback(), 0}, ec);
    if (ec || !ingress.AttachSocket("refresh-socket", socket))
        Fail("failed to attach UDP refresh test socket");

    GateDispatcher dispatcher(io);
    ::StatsShard stats;
    ::TimeoutsConfig timeouts;
    timeouts.idle = 1;
    ReplySink reply_sink;
    auto receiver = MakeReceiver();
    constexpr std::array<uint8_t, 1> packet{0x62};
    auto process_packet = [&]() {
        ingress.ProcessDatagram(::worker_detail::UdpDatagramContext{
            .socket_key = "refresh-socket",
            .sock = socket.get(),
            .client_endpoint = {::net::ip::address_v4::loopback(), 45123},
            .payload = packet,
            .receiver = &receiver,
            .io_context = io,
            .dispatcher = &dispatcher,
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
    auto* const session = dispatcher.sessions[0];
    if (!session || ingress.GetResourceStats().associations != 1)
        Fail("UDP refresh session row is missing");

    ::net::steady_timer refresh(io);
    refresh.expires_after(650ms);
    refresh.async_wait([&](::IoErrorCode timer_ec) {
        if (!timer_ec) process_packet();
    });
    io.run_for(1250ms);
    io.restart();
    if (ingress.GetResourceStats().associations != 1 || session->Closed())
        Fail("native uplink failed to refresh its association idle timestamp");

    io.run_for(1100ms);
    io.restart();
    if (ingress.GetResourceStats().associations != 0 || !session->Closed())
        Fail("refreshed native association did not expire naturally after idleness");
    ingress.RequestStop();
    bool joined = false;
    ::net::co_spawn(io, ObserveJoin(ingress, joined), ::net::detached);
    dispatcher.gate.cancel();
    io.run();
    if (!joined || ingress.GetResourceStats().native_dispatches != 0)
        Fail("idle-expired native dispatch did not join at actual completion");
}

void VerifyProtocolLocalAssociation() {
    using namespace ::proxyman::inbound;
    auto previous_view = UserStore::CaptureWorkerView();
    UserOnlineTracker tracker;
    StatsShard stats{};
    const ProtocolSettings configuration{};
    const ProtocolSettings other_configuration{};
    const udp::endpoint first{net::ip::address_v4::loopback(), 48234};
    const udp::endpoint second{net::ip::address_v4::loopback(), 48235};
    const TargetAddress target("127.0.0.1", 53);
    constexpr std::array<uint8_t, 3> payload{1, 2, 3};
    for (auto method : {"2022-blake3-aes-128-gcm", "2022-blake3-chacha20-poly1305"}) {
        const auto cipher = ss::ParseCipherMethod(method);
        if (!cipher) Fail("protocol association fixture cipher is unavailable");
        ss::KeyBytes key;
        std::array<uint8_t, 32> credential{0x61, 0x72};
        if (!key.assign(std::span(credential).first(cipher->key_size)))
            Fail("failed to prepare protocol association credential");
        PreparedShadowsocksUser user;
        if (!user.derived_key.assign(key.span())) Fail("failed to prepare local protocol user");
        user.key_size = cipher->key_size;
        user.salt_size = cipher->salt_size;
        user.profile.user_id = 41;
        UserSet users = PreparedShadowsocksUsers{std::move(user)};
        UserStore::InstallWorkerView(UserStore::PrepareWorkerView(
            UserStore::PrepareUsers("protocol-association", users)));
        proxy::shadowsocks::inbound::Handler handler(tracker, stats, nullptr, *cipher);
        ss::Ss2022UdpSessionState encoder;
        if (!ss::Init2022UdpSessionState(encoder, *cipher, key))
            Fail("failed to initialize protocol association encoder");
        const auto encode = [&](uint64_t packet_id) {
            encoder.next_packet_id = packet_id;
            const auto size = ss::Encode2022UdpRequestPacketTo(
                target, payload.data(), payload.size(), encoder, {}, nullptr, 0);
            std::vector<uint8_t> packet(size);
            if (size == 0 || ss::Encode2022UdpRequestPacketTo(
                    target, payload.data(), payload.size(), encoder, {},
                    packet.data(), packet.size()) != size)
                Fail("failed to encode protocol association packet");
            return packet;
        };
        InboundDatagramAssociationIndex index;
        InboundDatagramRequest request{
            .tag = "protocol-association", .payload = {}, .associations = &index,
            .configuration = &configuration, .worker_id = 0, .client_endpoint = first};
        auto initial = encode(0);
        request.payload = initial;
        auto decoded = handler.Process(request);
        if (!decoded || !decoded->association_policy || decoded->committed_association ||
            !decoded->session_id || !decoded->packet_id)
            Fail("authenticated first packet did not request cold association resolution");
        auto association = decoded->association_policy->create();
        if (!association->Check(*decoded->packet_id, 0, first, InboundDatagramCheck::Commit))
            Fail("failed to commit authenticated first packet");
        index.emplace(InboundDatagramAssociationKey{
            decoded->session_owner, *decoded->session_id, &configuration}, association.get());
        association->claimed.store(false, std::memory_order_release);
        if (handler.Process(request)) Fail("local protocol reopened the cold replay window");

        auto newer = encode(2);
        request.payload = newer;
        auto accepted = handler.Process(request);
        if (!accepted || accepted->committed_association != association.get() ||
            !accepted->target.SameEndpoint(target) || accepted->payload.byte_size() != payload.size())
            Fail("normal protocol entry did not commit local authenticated payload");
        if (handler.Process(request)) Fail("normal protocol entry accepted a local replay");
        auto reordered = encode(1);
        request.payload = reordered;
        request.client_endpoint = second;
        if (handler.Process(request)) Fail("old path packet stole the local response endpoint");
        request.client_endpoint = first;
        if (!handler.Process(request)) Fail("current path reordering was not accepted");

        auto claimed = encode(3);
        request.payload = claimed;
        association->claimed.store(true, std::memory_order_release);
        auto pending = handler.Process(request);
        if (!pending || pending->committed_association ||
            !association->Check(3, 0, first, InboundDatagramCheck::Commit))
            Fail("claimed local state was mutated before exclusive control commit");
        association->claimed.store(false, std::memory_order_release);
        if (handler.Process(request)) Fail("control commit did not reach the local replay authority");

        auto scoped = encode(4);
        request.payload = scoped;
        request.configuration = &other_configuration;
        auto other = handler.Process(request);
        if (!other || other->committed_association)
            Fail("local protocol state crossed configuration namespaces");
        request.configuration = &configuration;
        scoped.back() ^= 1;
        if (handler.Process(request)) Fail("invalid ciphertext reached local association commit");
        scoped.back() ^= 1;
        if (!handler.Process(request)) Fail("invalid ciphertext poisoned local replay state");
    }
    UserStore::InstallWorkerView(std::move(previous_view));
}

void VerifyHandoffDirectoryNamespaces() {
    using namespace ::worker_detail;
    ::net::io_context coordinator;
    auto& directory = ::net::use_service<UdpHandoffDirectory>(coordinator);
    const auto& policy = ::ss::Ss2022UdpAssociation::Policy();
    auto configuration = std::make_shared<const ::proxyman::inbound::ProtocolSettings>();
    auto other_configuration = std::make_shared<const ::proxyman::inbound::ProtocolSettings>();
    ::InboundDatagramOwner owner;
    std::array<uint8_t, 32> credential{};
    for (size_t i = 0; i < credential.size(); ++i)
        credential[i] = static_cast<uint8_t>(i + 1);
    if (!owner.Assign(credential)) Fail("failed to prepare directory credential");
    UdpHandoffIdentity key{
        .listener = "listener", .tag = "inbound", .configuration = configuration.get(),
        .client = ClientSessionKey{owner, 0x00123456789abcdeULL}};
    const ::udp::endpoint endpoint{::net::ip::address_v4::loopback(), 48234};
    auto record = directory.Claim(key, configuration, policy);
    if (!record || !record->association->claimed.load(std::memory_order_acquire) ||
        directory.Claim(key, configuration, policy) || !record->association->Check(7, 0, endpoint, ::InboundDatagramCheck::Commit))
        Fail("directory allowed duplicate ownership claims");
    record->association->claimed.store(false, std::memory_order_release);
    auto reclaimed = directory.Claim(key, configuration, policy);
    if (reclaimed != record || reclaimed->association->Check(7, 0, endpoint, ::InboundDatagramCheck::Commit) ||
        directory.Claim(key, configuration, policy))
        Fail("directory claim lost unique ownership or committed replay");
    record->association->claimed.store(false, std::memory_order_release);

    const auto expect_isolated = [&](
        const UdpHandoffIdentity& identity,
        std::shared_ptr<const ::proxyman::inbound::ProtocolSettings> snapshot) {
        auto isolated = directory.Claim(identity, snapshot, policy);
        if (!isolated || isolated == record || !isolated->association->Check(7, 1, endpoint, ::InboundDatagramCheck::Commit) ||
            directory.Claim(identity, snapshot, policy))
            Fail("directory merged distinct authenticated namespaces");
        isolated->association->claimed.store(false, std::memory_order_release);
        auto repeated = directory.Claim(identity, snapshot, policy);
        if (repeated != isolated || repeated->association->Check(7, 1, endpoint, ::InboundDatagramCheck::Commit) ||
            !repeated->association->Check(6, 1, endpoint, ::InboundDatagramCheck::Commit) || repeated->association->Check(5, 0, endpoint, ::InboundDatagramCheck::Commit))
            Fail("directory failed to retain isolated namespace replay");
        repeated->association->claimed.store(false, std::memory_order_release);
    };
    for (size_t i = 0; i < credential.size(); ++i) {
        auto distinct = key;
        distinct.client.owner.bytes[i] ^= 0x80;
        expect_isolated(distinct, configuration);
    }
    auto shorter = key;
    shorter.client.owner.size = 16;
    expect_isolated(shorter, configuration);
    auto session = key;
    session.client.session_id = *key.client.session_id + 1;
    expect_isolated(session, configuration);
    auto listener = key;
    listener.listener += "-other";
    expect_isolated(listener, configuration);
    auto tag = key;
    tag.tag += "-other";
    expect_isolated(tag, configuration);
    auto settings = key;
    settings.configuration = other_configuration.get();
    expect_isolated(settings, other_configuration);
}

void VerifyHandoffDirectoryTombstone(::net::io_context& io, Reclaimer& reclaimer) {
    using namespace ::worker_detail;
    ::net::io_context coordinator;
    auto& directory = ::net::use_service<UdpHandoffDirectory>(coordinator);
    const auto& policy = ::ss::Ss2022UdpAssociation::Policy();
    auto configuration = std::make_shared<const ::proxyman::inbound::ProtocolSettings>();
    std::weak_ptr<const ::proxyman::inbound::ProtocolSettings> configuration_lifetime = configuration;
    ::InboundDatagramOwner owner;
    constexpr std::array<uint8_t, 32> credential{0x71};
    if (!owner.Assign(credential)) Fail("failed to prepare tombstone credential");
    UdpHandoffIdentity key{
        .listener = "closed-listener", .tag = "closed-inbound",
        .configuration = configuration.get(), .client = ClientSessionKey{owner, 9}};
    UdpResourceBudget budget;
    const ::udp::endpoint endpoint{::net::ip::address_v4::loopback(), 48234};
    Ingress ingress("directory-tombstone", std::make_unique<NativeInbound>(),
                    reclaimer, budget, io);
    auto session = ingress.CreateClientSession(
        key.listener, key.client, io, {},
        {::net::ip::address_v4::loopback(), 48234},
        owner, std::chrono::steady_clock::now(), 0s);
    auto record = directory.Claim(key, configuration, policy);
    if (!session || !record || !record->association->Check(31, 0, endpoint, ::InboundDatagramCheck::Commit))
        Fail("failed to prepare live directory association");
    record->session = session;
    record->association->claimed.store(false, std::memory_order_release);
    ingress.CleanupClientSessions(key.listener);
    if (!session->Closed() || record->session.expired())
        Fail("closed association did not retain its outstanding session owner");
    session.reset();
    if (!record->session.expired() || budget.GetUsage().associations != 0)
        Fail("directory kept a closed association alive");
    const std::weak_ptr<UdpHandoffRecord> tombstone = record;
    record.reset();
    configuration.reset();
    if (tombstone.expired() || configuration_lifetime.expired())
        Fail("directory discarded its replay tombstone or settings snapshot");
    auto resumed = directory.Claim(key, configuration_lifetime.lock(), policy);
    if (!resumed || resumed != tombstone.lock() || resumed->association->Check(31, 0, endpoint, ::InboundDatagramCheck::Commit) ||
        resumed->association->Check(30, 1, endpoint, ::InboundDatagramCheck::Commit) || !resumed->association->Check(32, 1, endpoint, ::InboundDatagramCheck::Commit) ||
        resumed->association->Check(30, 0, endpoint, ::InboundDatagramCheck::Commit) || !resumed->association->Check(30, 1, endpoint, ::InboundDatagramCheck::Commit))
        Fail("association closure reopened a protected replay window");
    resumed->association->claimed.store(false, std::memory_order_release);
    ingress.RequestStop();
}

void VerifyHandoffDirectoryCapacity() {
    using namespace ::worker_detail;
    ::net::io_context coordinator;
    auto& directory = ::net::use_service<UdpHandoffDirectory>(coordinator);
    const auto& policy = ::ss::Ss2022UdpAssociation::Policy();
    auto configuration = std::make_shared<const ::proxyman::inbound::ProtocolSettings>();
    ::InboundDatagramOwner owner;
    constexpr std::array<uint8_t, 32> credential{0x63};
    if (!owner.Assign(credential)) Fail("failed to prepare capacity credential");
    UdpHandoffIdentity key{
        .listener = "capacity-listener", .tag = "capacity-inbound",
        .configuration = configuration.get(), .client = ClientSessionKey{owner, 0}};
    const ::udp::endpoint endpoint{::net::ip::address_v4::loopback(), 48234};
    std::shared_ptr<UdpHandoffRecord> first;
    for (size_t i = 0; i < ::ss::Ss2022UdpReplayCache::kMaxSessions; ++i) {
        key.client.session_id = i;
        auto record = directory.Claim(key, configuration, policy);
        if (!record || !record->association->Check(11, 0, endpoint, ::InboundDatagramCheck::Commit))
            Fail("directory rejected a session before reaching capacity");
        record->association->claimed.store(false, std::memory_order_release);
        if (i == 0) first = std::move(record);
    }
    key.client.session_id = ::ss::Ss2022UdpReplayCache::kMaxSessions;
    if (directory.Claim(key, configuration, policy))
        Fail("full directory evicted an unexpired closed-session replay tombstone");
    auto protected_key = key;
    protected_key.client.session_id = 0;
    auto protected_record = directory.Claim(protected_key, configuration, policy);
    if (protected_record != first || protected_record->association->Check(11, 0, endpoint, ::InboundDatagramCheck::Commit))
        Fail("capacity rejection lost an existing session or its replay history");
    const auto expired = std::chrono::steady_clock::now() -
        ::ss::Ss2022UdpReplayCache::kRetention - 1s;
    if (!first->association->Check(12, 0, endpoint, ::InboundDatagramCheck::Commit, expired))
        Fail("failed to commit an expired protocol retention deadline");
    if (directory.Claim(key, configuration, policy))
        Fail("directory reclaimed a still-claimed expired tombstone");
    first->association->claimed.store(false, std::memory_order_release);
    auto replacement = directory.Claim(key, configuration, policy);
    if (!replacement || replacement == first || !replacement->association->Check(11, 0, endpoint, ::InboundDatagramCheck::Commit))
        Fail("directory did not reclaim an expired unclaimed tombstone");
    replacement->association->claimed.store(false, std::memory_order_release);
    if (directory.Claim(protected_key, configuration, policy))
        Fail("directory exceeded capacity after reclaiming one expired tombstone");
}

void VerifyAssociationReplyDrain() {
    ::net::io_context io;
    auto fence = std::make_shared<::worker_detail::UdpReplyFence>(io);
    auto unrelated = std::make_shared<::worker_detail::UdpReplyFence>(io);
    ::worker_detail::UdpReplyFence::Lease queued(fence);
    ::worker_detail::UdpReplyFence::Lease active(fence);
    ::worker_detail::UdpReplyFence::Lease other_active(unrelated);
    bool drained = false;
    ::net::co_spawn(io, fence->AsyncDrain(),
        [&](std::exception_ptr failure) {
            if (failure) Fail("association reply fence failed");
            drained = true;
        });
    io.poll();
    io.restart();
    if (drained) Fail("reply drain ignored queued and active sends");
    queued = {};
    io.poll();
    io.restart();
    if (drained) Fail("reply drain returned before active sender completion");
    auto sender_lease = std::move(active);
    active = {};
    io.poll();
    io.restart();
    if (drained) Fail("moving a reply lease released the active send");
    sender_lease = {};
    io.poll();
    io.restart();
    if (!drained) Fail("reply drain waited on another association's sender");
    other_active = {};
}

} // namespace

TEST(UdpNativeLifecycle, Contract) {
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
    ::memory::ThreadMemoryResource owner_resource;
    struct RestoreDefaultResource {
        std::pmr::memory_resource* previous;
        ~RestoreDefaultResource() { std::pmr::set_default_resource(previous); }
    } resource_scope{std::pmr::set_default_resource(&owner_resource)};
    VerifyAssociationReplyDrain();
    ::net::io_context io;
    auto& scheduler = ::TimeoutScheduler::ForIoContext(io);
    Reclaimer reclaimer(scheduler, nullptr, [](void*, std::exception_ptr) { std::terminate(); });
    VerifyHandoffDirectoryNamespaces();
    VerifyProtocolLocalAssociation();
    VerifyHandoffDirectoryTombstone(io, reclaimer);
    VerifyHandoffDirectoryCapacity();
    ::worker_detail::UdpResourceBudget budget;
    Ingress ingress("native-test", std::make_unique<NativeInbound>(), reclaimer, budget, io);
    auto socket = Ingress::MakeSocket(io);
    ::IoErrorCode ec;
    socket->open(::udp::v4(), ec);
    if (ec) Fail("failed to open native UDP test socket");
    socket->bind({::net::ip::address_v4::loopback(), 0}, ec);
    if (ec || !ingress.AttachSocket("native-socket", socket))
        Fail("failed to attach native UDP test socket");

    GateDispatcher dispatcher(io);
    dispatcher.ingress = &ingress;
    dispatcher.reenter_stop = true;
    ::StatsShard stats;
    ::TimeoutsConfig timeouts;
    ReplySink reply_sink;
    auto receiver = MakeReceiver();
    constexpr std::array<uint8_t, 1> datagram{0x62};
    ingress.ProcessDatagram(::worker_detail::UdpDatagramContext{
        .socket_key = "native-socket",
        .sock = socket.get(),
        .client_endpoint = {::net::ip::address_v4::loopback(), 43123},
        .payload = datagram,
        .receiver = &receiver,
        .io_context = io,
        .dispatcher = &dispatcher,
        .stats = stats,
        .timeouts = timeouts,
        .worker_id = 3,
        .reply_sink = reply_sink,
    });
    constexpr std::array<uint8_t, 1> second_datagram{0x63};
    ingress.ProcessDatagram(::worker_detail::UdpDatagramContext{
        .socket_key = "native-socket",
        .sock = socket.get(),
        .client_endpoint = {::net::ip::address_v4::loopback(), 43124},
        .payload = second_datagram,
        .receiver = &receiver,
        .io_context = io,
        .dispatcher = &dispatcher,
        .stats = stats,
        .timeouts = timeouts,
        .worker_id = 3,
        .reply_sink = reply_sink,
    });
    receiver.inbound_tag.assign(256, 'x');
    receiver.inbound_tags.front().assign(256, 'y');
    receiver.protocol.assign(256, 'z');
    receiver.stream_settings.security.assign(256, 'q');
    std::get<::routing::ForceOutbound>(receiver.dispatch_policy.outbound)
        .outbound_tag.assign(256, 'r');

    const auto installed = ingress.GetResourceStats();
    if (installed.associations != 2 || installed.closed_associations != 0 ||
        installed.native_dispatches != 2)
        Fail("native UDP associations were not installed");
    if (!ingress.ReplaceHandler(std::make_unique<NativeInbound>()))
        Fail("same-socket handler replacement was rejected");

    io.poll();
    io.restart();
    if (dispatcher.dispatches != 2 || dispatcher.packets_read != 2)
        Fail("native UDP requests did not dispatch their first packets exactly once");
    auto* const session_a = dispatcher.sessions[0];
    auto* const session_b = dispatcher.sessions[1];
    // A datagram decoded by the replacement handler must reach the existing
    // row's queue instead of starting a new job.
    ingress.ProcessDatagram(::worker_detail::UdpDatagramContext{
        .socket_key = "native-socket",
        .sock = socket.get(),
        .client_endpoint = {::net::ip::address_v4::loopback(), 43123},
        .payload = datagram,
        .receiver = &receiver,
        .io_context = io,
        .dispatcher = &dispatcher,
        .stats = stats,
        .timeouts = timeouts,
        .worker_id = 3,
        .reply_sink = reply_sink,
    });
    const auto replaced = ingress.GetResourceStats();
    if (!session_a || !session_b || session_a == session_b ||
        session_a->Closed() || session_b->Closed() ||
        replaced.associations != 2 || replaced.closed_associations != 0 ||
        replaced.native_dispatches != 2 || replaced.input_datagrams != 1 ||
        dispatcher.dispatches != 2)
        Fail("same-socket handler replacement disturbed active native jobs");

    ingress.CloseSocket("native-socket");
    auto stats_after_close = ingress.GetResourceStats();
    if (dispatcher.cancellations != 2 || stats_after_close.associations != 0 ||
        stats_after_close.native_dispatches != 2)
        Fail("socket batch reentry confused row removal with native job completion");


    bool joined = false;
    bool parent_cancelled = false;
    bool join_throw_setting = true;
    ::net::cancellation_signal parent_signal;
    ::net::co_spawn(
        io, ObserveCancelledJoin(ingress, joined, parent_cancelled,
                                 join_throw_setting, parent_signal),
        ::net::bind_cancellation_slot(
            parent_signal.slot(), ::net::detached));
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

    VerifySocketIdentityRecycle(io, reclaimer);
    VerifyUplinkRefresh(io, reclaimer);
}
