#include <gtest/gtest.h>

#include "transport/internet/datagram_socket.hpp"

#include "common/buf/multi_buffer.hpp"
#include "transport/link_error.hpp"
#include "app/session_group_executor.hpp"
#include <optional>
#include <thread>

#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/use_future.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cstdio>
#include <future>
#include <memory>
#include <span>
#include <vector>

namespace {
using namespace std::chrono_literals;
using ::transport::internet::DatagramSocket;
using ::transport::internet::ReceivedDatagram;

::buf::MultiBuffer MakePayload(std::span<const uint8_t> bytes) {
    ::buf::MultiBuffer payload;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        ::buf::BufferGuard buffer{::buf::Buffer::New()};
        if (!buffer) throw std::bad_alloc();
        const auto count = std::min<std::size_t>(buffer->Available(), bytes.size() - offset);
        std::memcpy(buffer->Tail().data(), bytes.data() + offset, count);
        buffer->Produce(static_cast<uint32_t>(count));
        payload.push_back(std::move(buffer));
        offset += count;
    }
    return payload;
}

::net::awaitable<void> SendPayload(
    DatagramSocket& socket, ::udp::endpoint destination, ::buf::MultiBuffer payload) {
    auto operation = socket.StartWrite();
    co_await operation.SendTo(std::move(destination), std::move(payload));
}

::net::awaitable<void> SendBuffers(
    DatagramSocket& socket, ::udp::endpoint destination,
    std::span<const ::net::const_buffer> buffers) {
    auto operation = socket.StartWrite();
    co_await operation.SendTo(std::move(destination), buffers);
}

::net::awaitable<void> ParentRead(DatagramSocket& socket) {
    auto operation = socket.StartRead();
    (void)co_await operation.Receive();
}

::net::awaitable<void> SendEmptyRaw(
    ::net::io_context& io, ::udp::endpoint destination) {
    ::udp::socket sender(io, ::udp::v4());
    const std::array<::net::const_buffer, 1> empty{::net::const_buffer{}};
    (void)co_await sender.async_send_to(empty, destination, ::net::use_awaitable);
}

bool TestIndependentBindingsAndLargeScatter() {
    ::net::io_context io;
    DatagramSocket receiver(io, ::net::ip::address_v4::loopback());
    DatagramSocket sender(io, ::net::ip::address_v4::loopback());
    const auto target = receiver.LocalEndpoint();
    if (target.port() == sender.LocalEndpoint().port() || DatagramSocket::ActiveCount() < 2)
        return false;

    std::vector<uint8_t> bytes(60000);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<uint8_t>(i * 31u);
    auto read = receiver.StartRead();
    auto receiving = ::net::co_spawn(io, read.Receive(), ::net::use_future);
    auto sending = ::net::co_spawn(io,
        SendPayload(sender, target, MakePayload(bytes)), ::net::use_future);
    io.run();
    sending.get();
    ReceivedDatagram packet = receiving.get();
    if (packet.payload.byte_size() != bytes.size() || packet.source.port() != sender.LocalEndpoint().port())
        return false;
    std::size_t offset = 0;
    for (const auto* buffer : packet.payload) {
        for (const auto byte : buffer->Bytes()) {
            if (byte != bytes[offset++]) return false;
        }
    }
    if (offset != bytes.size()) return false;

    ::buf::MultiBuffer fragmented;
    for (uint8_t i = 0; i < 100; ++i) {
        ::buf::BufferGuard buffer{::buf::Buffer::New()};
        if (!buffer) return false;
        buffer->Tail()[0] = i;
        buffer->Produce(1);
        fragmented.push_back(std::move(buffer));
    }
    io.restart();
    auto fragmented_receive = ::net::co_spawn(io, read.Receive(), ::net::use_future);
    auto fragmented_send = ::net::co_spawn(io,
        SendPayload(sender, target, std::move(fragmented)), ::net::use_future);
    io.run();
    fragmented_send.get();
    const auto fragments = fragmented_receive.get();
    if (fragments.payload.byte_size() != 100) return false;
    std::size_t index = 0;
    for (const auto* buffer : fragments.payload) {
        for (const auto byte : buffer->Bytes())
            if (byte != index++) return false;
    }
    if (index != 100) return false;

    std::array<uint8_t, 100> raw{};
    std::array<::net::const_buffer, 100> scatter{};
    for (std::size_t i = 0; i < raw.size(); ++i) {
        raw[i] = static_cast<uint8_t>(i);
        scatter[i] = ::net::buffer(&raw[i], 1);
    }
    io.restart();
    auto raw_receive = ::net::co_spawn(io, read.Receive(), ::net::use_future);
    auto raw_send = ::net::co_spawn(io, SendBuffers(sender, target, scatter), ::net::use_future);
    io.run();
    raw_send.get();
    const auto raw_packet = raw_receive.get();
    if (raw_packet.payload.byte_size() != raw.size()) return false;
    index = 0;
    for (const auto* buffer : raw_packet.payload)
        for (const auto byte : buffer->Bytes())
            if (byte != raw[index++]) return false;
    return index == raw.size();
}

bool TestZeroLengthAndCancellationIsolation() {
    ::net::io_context io;
    DatagramSocket first(io, ::net::ip::address_v4::loopback());
    DatagramSocket second(io, ::net::ip::address_v4::loopback());
    const auto count = DatagramSocket::ActiveCount();

    auto cancelled_read = first.StartRead();
    auto cancelled_future = ::net::co_spawn(io, cancelled_read.Receive(), ::net::use_future);
    auto live_read = second.StartRead();
    auto live_future = ::net::co_spawn(io, live_read.Receive(), ::net::use_future);
    io.poll();
    first.Cancel();
    auto empty_send = ::net::co_spawn(io,
        SendEmptyRaw(io, second.LocalEndpoint()), ::net::use_future);
    io.restart();
    io.run();
    empty_send.get();

    bool cancelled = false;
    try { (void)cancelled_future.get(); }
    catch (const ::transport::LinkError& error) {
        cancelled = error.code() == ::ErrorCode::CANCELLED;
    }
    const auto packet = live_future.get();
    if (!cancelled || packet.payload.empty() || packet.payload.byte_size() != 0 ||
        packet.source.address().is_v6() ||
        DatagramSocket::ActiveCount() != count || first.IsIPv6() || second.IsIPv6())
        return false;
    first.Close();
    return DatagramSocket::ActiveCount() == count - 1 && second.LocalEndpoint().port() != 0;
}

bool TestParentCancellationPropagation() {
    ::net::io_context io;
    DatagramSocket socket(io, ::net::ip::address_v4::loopback());
    ::net::cancellation_signal parent_cancel;
    auto future = ::net::co_spawn(io, ParentRead(socket),
        ::net::bind_cancellation_slot(parent_cancel.slot(), ::net::use_future));
    io.poll();
    parent_cancel.emit(::net::cancellation_type::terminal);
    io.restart();
    io.run_for(100ms);
    const bool completed_without_socket_cancel =
        future.wait_for(0ms) == std::future_status::ready && socket.LocalEndpoint().port() != 0;
    if (!completed_without_socket_cancel) {
        socket.Cancel();
        io.restart();
        io.run_for(100ms);
    }
    bool aborted = false;
    try { future.get(); }
    catch (const std::system_error& error) {
        aborted = error.code() == ::io_error::operation_aborted;
    }
    return completed_without_socket_cancel && aborted;
}

bool TestIPv6MaximumAndFamilyValidation() {
    ::net::io_context io;
    DatagramSocket receiver(io, ::net::ip::address_v6::loopback());
    DatagramSocket sender(io, ::net::ip::address_v6::loopback());
    DatagramSocket v4(io, ::net::ip::address_v4::loopback());
    std::vector<uint8_t> bytes(65527, 0xA5);
    auto read = receiver.StartRead();
    auto receiving = ::net::co_spawn(io, read.Receive(), ::net::use_future);
    auto sending = ::net::co_spawn(io,
        SendPayload(sender, receiver.LocalEndpoint(), MakePayload(bytes)), ::net::use_future);
    io.run();
    sending.get();
    const auto packet = receiving.get();
    if (packet.payload.byte_size() != bytes.size() || !packet.source.address().is_v6()) return false;

    bool family_rejected = false;
    {
        auto invalid_family = sender.StartWrite();
        auto family_future = ::net::co_spawn(io,
            invalid_family.SendTo(v4.LocalEndpoint(), MakePayload(std::span<const uint8_t>{})),
            ::net::use_future);
        io.restart();
        io.run();
        try { family_future.get(); }
        catch (const ::transport::LinkError& error) {
            family_rejected = error.code() == ::ErrorCode::INVALID_ARGUMENT;
        }
    }

    std::vector<uint8_t> too_large(65528, 0x5A);
    auto invalid_size = sender.StartWrite();
    auto size_future = ::net::co_spawn(io,
        invalid_size.SendTo(receiver.LocalEndpoint(), MakePayload(too_large)),
        ::net::use_future);
    io.restart();
    io.run();
    bool size_rejected = false;
    try { size_future.get(); }
    catch (const ::transport::LinkError& error) {
        size_rejected = error.code() == ::ErrorCode::INVALID_ARGUMENT;
    }
    return family_rejected && size_rejected;
}

bool TestCloseAndReadScopeTimeout() {
    const auto baseline = DatagramSocket::ActiveCount();
    ::net::io_context io;
    DatagramSocket receiver(io, ::net::ip::address_v4::loopback());
    DatagramSocket sender(io, ::net::ip::address_v4::loopback());
    receiver.SetReadTimeout(1s);
    auto operation = receiver.StartRead();
    auto first = ::net::co_spawn(io, operation.Receive(), ::net::use_future);
    const std::array<uint8_t, 1> one_byte{7};
    auto send_one = ::net::co_spawn(io,
        SendPayload(sender, receiver.LocalEndpoint(), MakePayload(one_byte)),
        ::net::use_future);
    io.run_for(100ms);
    send_one.get();
    if (first.wait_for(0ms) != std::future_status::ready || first.get().payload.byte_size() != 1)
        return false;

    // The same scope keeps its original read deadline across repeated receives.
    auto second = ::net::co_spawn(io, operation.Receive(), ::net::use_future);
    io.restart();
    io.run_for(1100ms);
    if (second.wait_for(0ms) != std::future_status::ready) return false;
    bool timed_out = false;
    try { (void)second.get(); }
    catch (const ::transport::LinkError&) { timed_out = true; }
    if (!timed_out || !receiver.ConsumeReadTimeout()) return false;

    DatagramSocket closed(io, ::net::ip::address_v4::loopback());
    auto pending = closed.StartRead();
    auto pending_future = ::net::co_spawn(io, pending.Receive(), ::net::use_future);
    io.restart();
    io.poll();
    closed.Close();
    io.restart();
    io.run();
    bool closed_error = false;
    try { (void)pending_future.get(); }
    catch (const ::transport::LinkError&) { closed_error = true; }
    return closed_error && DatagramSocket::ActiveCount() == baseline + 1;
}
bool TestSocketLimitAndReclamation() {
    constexpr std::size_t limit = 4096;
    const auto baseline = DatagramSocket::ActiveCount();
    if (baseline >= limit) return false;
    ::net::io_context io;
    std::vector<std::unique_ptr<DatagramSocket>> sockets;
    sockets.reserve(limit - baseline);
    for (std::size_t i = baseline; i < limit; ++i)
        sockets.push_back(std::make_unique<DatagramSocket>(io, ::net::ip::address_v4::loopback()));
    bool rejected = false;
    try { DatagramSocket extra(io, ::net::ip::address_v4::loopback()); }
    catch (const ::transport::LinkError& error) {
        rejected = error.code() == ::ErrorCode::RESOURCE_EXHAUSTED;
    }
    if (!rejected || DatagramSocket::ActiveCount() != limit) return false;
    sockets.pop_back();
    {
        DatagramSocket replacement(io, ::net::ip::address_v4::loopback());
        if (DatagramSocket::ActiveCount() != limit) return false;
    }
    sockets.clear();
    return DatagramSocket::ActiveCount() == baseline;
}
bool TestZeroLengthNativeSends() {
    ::net::io_context io;
    DatagramSocket sender(io, ::net::ip::address_v4::loopback());
    DatagramSocket receiver(io, ::net::ip::address_v4::loopback());
    for (bool owned : {false, true}) {
        auto operation = receiver.StartRead();
        auto receiving = ::net::co_spawn(io, operation.Receive(), ::net::use_future);
        auto sending = ::net::co_spawn(io,
            owned ? SendPayload(sender, receiver.LocalEndpoint(), {})
                  : SendBuffers(sender, receiver.LocalEndpoint(), {}),
            ::net::use_future);
        io.run_for(1s);
        if (sending.wait_for(0s) != std::future_status::ready ||
            receiving.wait_for(0s) != std::future_status::ready) {
            sender.Close();
            receiver.Close();
            io.restart();
            io.run();
            return false;
        }
        sending.get();
        const auto packet = receiving.get();
        if (packet.payload.empty() || packet.payload.byte_size() != 0 ||
            packet.source != sender.LocalEndpoint()) return false;
        io.restart();
    }
    return true;
}

bool TestAdmissionBucketSurvivesDomainMigration() {
    struct Hooks final : ::ExecutionDomain::Hooks {
        ::memory::AllocationDomain allocation;
        std::optional<::memory::ScopedAllocationDomain> lease;
        std::exception_ptr failure;
        void Enter() noexcept override { lease.emplace(allocation); }
        void Leave() noexcept override { lease.reset(); }
        void OnFailure(std::exception_ptr error) noexcept override { failure = error; }
    };
    ::net::io_context io;
    auto coordinator = std::make_shared<::GroupCoordinator>(io);
    coordinator->RegisterWorker(0, io, io.get_executor());
    auto hooks = std::make_shared<Hooks>();
    auto domain = ::ExecutionDomain::Create(io, 0, io.get_executor(), hooks, coordinator);
    hooks->allocation.SetLeaseGroup(domain->LeaseIdentity(), ::ExecutionDomain::SharesLeaseIdentity);
    const auto baseline = DatagramSocket::ActiveCount();
    std::unique_ptr<DatagramSocket> socket;
    domain->Execute([&] {
        socket = std::make_unique<DatagramSocket>(io, ::net::ip::address_v4::loopback());
    });
    io.poll();
    if (!socket || DatagramSocket::ActiveCount() != baseline + 1) return false;
    bool remote_clean = false;
    domain->Execute([&] {
        socket.reset();
        remote_clean = DatagramSocket::ActiveCount() == 0;
    });
    // The same stable domain is now executed on another native thread.
    std::thread migrated([&] { io.poll(); });
    migrated.join();
    const bool passed = remote_clean && !hooks->failure &&
        DatagramSocket::ActiveCount() == baseline;
    domain.reset();
    bool finalized = false;
    auto finalize = [](std::shared_ptr<::GroupCoordinator> owner)
        -> ::net::awaitable<void> {
        owner->CloseAdmission();
        co_await owner->AsyncJoin();
        owner->ReleaseServices();
        co_await owner->Finalize();
    };
    ::net::co_spawn(io, finalize(coordinator),
        [&](std::exception_ptr error) { finalized = !error; });
    io.restart();
    io.run_for(1s);
    return passed && finalized;
}

}  // namespace

TEST(DatagramSocket, Contract) {
    try {
        const bool bindings = TestIndependentBindingsAndLargeScatter();
        const bool cancel = TestZeroLengthAndCancellationIsolation();
        const bool parent_cancel = TestParentCancellationPropagation();
        const bool ipv6 = TestIPv6MaximumAndFamilyValidation();
        const bool timeout_close = TestCloseAndReadScopeTimeout();
        const bool limit = TestSocketLimitAndReclamation();
        const bool empty = TestZeroLengthNativeSends();
        const bool migrated = TestAdmissionBucketSurvivesDomainMigration();
        const bool reclaimed = DatagramSocket::ActiveCount() == 0;
        std::printf("datagram socket: bindings=%d cancel=%d parent_cancel=%d ipv6=%d timeout_close=%d limit=%d empty=%d migrated=%d reclaimed=%d\n",
                    bindings, cancel, parent_cancel, ipv6, timeout_close, limit, empty, migrated, reclaimed);
        { ASSERT_TRUE(bindings && cancel && parent_cancel && ipv6 && timeout_close && limit &&
            empty && migrated && reclaimed); return; }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "datagram socket test exception: %s\n", error.what());
        FAIL() << error.what();
    }
}

TEST(DatagramSocket, CancelledWriteDoesNotSend) {
    for (const bool owned : {false, true}) {
        SCOPED_TRACE(owned);
        ::net::io_context io;
        DatagramSocket sender(io, ::net::ip::address_v4::loopback());
        ::udp::socket peer(io, {::net::ip::address_v4::loopback(), 0});
        peer.non_blocking(true);
        ::net::cancellation_signal cancellation;
        const std::array<uint8_t, 1> payload{42};
        const std::array<::net::const_buffer, 1> buffers{::net::buffer(payload)};
        auto send = [&]() -> ::net::awaitable<void> {
            // Disabling implicit throws does not authorize sending after
            // cancellation; the operation must observe the sticky state.
            co_await ::net::this_coro::throw_if_cancelled(false);
            auto operation = sender.StartWrite();
            cancellation.emit(::net::cancellation_type::terminal);
            if (owned) co_await operation.SendTo(peer.local_endpoint(), MakePayload(payload));
            else co_await operation.SendTo(peer.local_endpoint(), buffers);
        };
        auto result = ::net::co_spawn(io, send(),
            ::net::bind_cancellation_slot(cancellation.slot(), ::net::use_future));
        io.run();
        bool aborted = false;
        try { result.get(); }
        catch (const std::system_error& error) {
            aborted = error.code() == ::io_error::operation_aborted;
        }
        EXPECT_TRUE(aborted);
        std::array<uint8_t, 1> received{};
        ::udp::endpoint source;
        ::IoErrorCode error;
        (void)peer.receive_from(::net::buffer(received), source, 0, error);
        EXPECT_TRUE(error == ::io_error::would_block || error == ::io_error::try_again);
    }
}
