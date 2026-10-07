#include "acppnode/transport/internet/datagram_socket.hpp"

#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/transport/link_error.hpp"

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
using acpp::transport::internet::DatagramSocket;
using acpp::transport::internet::ReceivedDatagram;

acpp::buf::MultiBuffer MakePayload(std::span<const uint8_t> bytes) {
    acpp::buf::MultiBuffer payload;
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        acpp::buf::BufferGuard buffer{acpp::buf::Buffer::New()};
        if (!buffer) throw std::bad_alloc();
        const auto count = std::min<std::size_t>(buffer->Available(), bytes.size() - offset);
        std::memcpy(buffer->Tail().data(), bytes.data() + offset, count);
        buffer->Produce(static_cast<uint32_t>(count));
        payload.push_back(std::move(buffer));
        offset += count;
    }
    return payload;
}

acpp::net::awaitable<void> SendPayload(
    DatagramSocket& socket, acpp::udp::endpoint destination, acpp::buf::MultiBuffer payload) {
    auto operation = socket.StartWrite();
    co_await operation.SendTo(std::move(destination), std::move(payload));
}

acpp::net::awaitable<void> SendBuffers(
    DatagramSocket& socket, acpp::udp::endpoint destination,
    std::span<const acpp::net::const_buffer> buffers) {
    auto operation = socket.StartWrite();
    co_await operation.SendTo(std::move(destination), buffers);
}

acpp::net::awaitable<void> ParentRead(DatagramSocket& socket) {
    auto operation = socket.StartRead();
    (void)co_await operation.Receive();
}

acpp::net::awaitable<void> SendEmptyRaw(
    acpp::net::io_context& io, acpp::udp::endpoint destination) {
    acpp::udp::socket sender(io, acpp::udp::v4());
    const std::array<acpp::net::const_buffer, 1> empty{acpp::net::const_buffer{}};
    (void)co_await sender.async_send_to(empty, destination, acpp::net::use_awaitable);
}

bool TestIndependentBindingsAndLargeScatter() {
    acpp::net::io_context io;
    DatagramSocket receiver(io, acpp::net::ip::address_v4::loopback());
    DatagramSocket sender(io, acpp::net::ip::address_v4::loopback());
    const auto target = receiver.LocalEndpoint();
    if (target.port() == sender.LocalEndpoint().port() || DatagramSocket::ActiveCount() < 2)
        return false;

    std::vector<uint8_t> bytes(60000);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<uint8_t>(i * 31u);
    auto read = receiver.StartRead();
    auto receiving = acpp::net::co_spawn(io, read.Receive(), acpp::net::use_future);
    auto sending = acpp::net::co_spawn(io,
        SendPayload(sender, target, MakePayload(bytes)), acpp::net::use_future);
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

    acpp::buf::MultiBuffer fragmented;
    for (uint8_t i = 0; i < 100; ++i) {
        acpp::buf::BufferGuard buffer{acpp::buf::Buffer::New()};
        if (!buffer) return false;
        buffer->Tail()[0] = i;
        buffer->Produce(1);
        fragmented.push_back(std::move(buffer));
    }
    io.restart();
    auto fragmented_receive = acpp::net::co_spawn(io, read.Receive(), acpp::net::use_future);
    auto fragmented_send = acpp::net::co_spawn(io,
        SendPayload(sender, target, std::move(fragmented)), acpp::net::use_future);
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
    std::array<acpp::net::const_buffer, 100> scatter{};
    for (std::size_t i = 0; i < raw.size(); ++i) {
        raw[i] = static_cast<uint8_t>(i);
        scatter[i] = acpp::net::buffer(&raw[i], 1);
    }
    io.restart();
    auto raw_receive = acpp::net::co_spawn(io, read.Receive(), acpp::net::use_future);
    auto raw_send = acpp::net::co_spawn(io, SendBuffers(sender, target, scatter), acpp::net::use_future);
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
    acpp::net::io_context io;
    DatagramSocket first(io, acpp::net::ip::address_v4::loopback());
    DatagramSocket second(io, acpp::net::ip::address_v4::loopback());
    const auto count = DatagramSocket::ActiveCount();

    auto cancelled_read = first.StartRead();
    auto cancelled_future = acpp::net::co_spawn(io, cancelled_read.Receive(), acpp::net::use_future);
    auto live_read = second.StartRead();
    auto live_future = acpp::net::co_spawn(io, live_read.Receive(), acpp::net::use_future);
    io.poll();
    first.Cancel();
    auto empty_send = acpp::net::co_spawn(io,
        SendEmptyRaw(io, second.LocalEndpoint()), acpp::net::use_future);
    io.restart();
    io.run();
    empty_send.get();

    bool cancelled = false;
    try { (void)cancelled_future.get(); }
    catch (const acpp::transport::LinkError& error) {
        cancelled = error.code() == acpp::ErrorCode::CANCELLED;
    }
    const auto packet = live_future.get();
    if (!cancelled || !packet.payload.empty() || packet.source.address().is_v6() ||
        DatagramSocket::ActiveCount() != count || first.IsIPv6() || second.IsIPv6())
        return false;
    first.Close();
    return DatagramSocket::ActiveCount() == count - 1 && second.LocalEndpoint().port() != 0;
}

bool TestParentCancellationPropagation() {
    acpp::net::io_context io;
    DatagramSocket socket(io, acpp::net::ip::address_v4::loopback());
    acpp::net::cancellation_signal parent_cancel;
    auto future = acpp::net::co_spawn(io, ParentRead(socket),
        acpp::net::bind_cancellation_slot(parent_cancel.slot(), acpp::net::use_future));
    io.poll();
    parent_cancel.emit(acpp::net::cancellation_type::terminal);
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
        aborted = error.code() == acpp::io_error::operation_aborted;
    }
    return completed_without_socket_cancel && aborted;
}

bool TestIPv6MaximumAndFamilyValidation() {
    acpp::net::io_context io;
    DatagramSocket receiver(io, acpp::net::ip::address_v6::loopback());
    DatagramSocket sender(io, acpp::net::ip::address_v6::loopback());
    DatagramSocket v4(io, acpp::net::ip::address_v4::loopback());
    std::vector<uint8_t> bytes(65527, 0xA5);
    auto read = receiver.StartRead();
    auto receiving = acpp::net::co_spawn(io, read.Receive(), acpp::net::use_future);
    auto sending = acpp::net::co_spawn(io,
        SendPayload(sender, receiver.LocalEndpoint(), MakePayload(bytes)), acpp::net::use_future);
    io.run();
    sending.get();
    const auto packet = receiving.get();
    if (packet.payload.byte_size() != bytes.size() || !packet.source.address().is_v6()) return false;

    bool family_rejected = false;
    {
        auto invalid_family = sender.StartWrite();
        auto family_future = acpp::net::co_spawn(io,
            invalid_family.SendTo(v4.LocalEndpoint(), MakePayload(std::span<const uint8_t>{})),
            acpp::net::use_future);
        io.restart();
        io.run();
        try { family_future.get(); }
        catch (const acpp::transport::LinkError& error) {
            family_rejected = error.code() == acpp::ErrorCode::INVALID_ARGUMENT;
        }
    }

    std::vector<uint8_t> too_large(65528, 0x5A);
    auto invalid_size = sender.StartWrite();
    auto size_future = acpp::net::co_spawn(io,
        invalid_size.SendTo(receiver.LocalEndpoint(), MakePayload(too_large)),
        acpp::net::use_future);
    io.restart();
    io.run();
    bool size_rejected = false;
    try { size_future.get(); }
    catch (const acpp::transport::LinkError& error) {
        size_rejected = error.code() == acpp::ErrorCode::INVALID_ARGUMENT;
    }
    return family_rejected && size_rejected;
}

bool TestCloseAndReadScopeTimeout() {
    const auto baseline = DatagramSocket::ActiveCount();
    acpp::net::io_context io;
    DatagramSocket receiver(io, acpp::net::ip::address_v4::loopback());
    DatagramSocket sender(io, acpp::net::ip::address_v4::loopback());
    receiver.SetReadTimeout(1s);
    auto operation = receiver.StartRead();
    auto first = acpp::net::co_spawn(io, operation.Receive(), acpp::net::use_future);
    const std::array<uint8_t, 1> one_byte{7};
    auto send_one = acpp::net::co_spawn(io,
        SendPayload(sender, receiver.LocalEndpoint(), MakePayload(one_byte)),
        acpp::net::use_future);
    io.run_for(100ms);
    send_one.get();
    if (first.wait_for(0ms) != std::future_status::ready || first.get().payload.byte_size() != 1)
        return false;

    // The same scope keeps its original read deadline across repeated receives.
    auto second = acpp::net::co_spawn(io, operation.Receive(), acpp::net::use_future);
    io.restart();
    io.run_for(1100ms);
    if (second.wait_for(0ms) != std::future_status::ready) return false;
    bool timed_out = false;
    try { (void)second.get(); }
    catch (const acpp::transport::LinkError&) { timed_out = true; }
    if (!timed_out || !receiver.ConsumeReadTimeout()) return false;

    DatagramSocket closed(io, acpp::net::ip::address_v4::loopback());
    auto pending = closed.StartRead();
    auto pending_future = acpp::net::co_spawn(io, pending.Receive(), acpp::net::use_future);
    io.restart();
    io.poll();
    closed.Close();
    io.restart();
    io.run();
    bool closed_error = false;
    try { (void)pending_future.get(); }
    catch (const acpp::transport::LinkError&) { closed_error = true; }
    return closed_error && DatagramSocket::ActiveCount() == baseline + 1;
}
bool TestSocketLimitAndReclamation() {
    constexpr std::size_t limit = 4096;
    const auto baseline = DatagramSocket::ActiveCount();
    if (baseline >= limit) return false;
    acpp::net::io_context io;
    std::vector<std::unique_ptr<DatagramSocket>> sockets;
    sockets.reserve(limit - baseline);
    for (std::size_t i = baseline; i < limit; ++i)
        sockets.push_back(std::make_unique<DatagramSocket>(io, acpp::net::ip::address_v4::loopback()));
    bool rejected = false;
    try { DatagramSocket extra(io, acpp::net::ip::address_v4::loopback()); }
    catch (const acpp::transport::LinkError& error) {
        rejected = error.code() == acpp::ErrorCode::RESOURCE_EXHAUSTED;
    }
    if (!rejected || DatagramSocket::ActiveCount() != limit) return false;
    sockets.pop_back();
    {
        DatagramSocket replacement(io, acpp::net::ip::address_v4::loopback());
        if (DatagramSocket::ActiveCount() != limit) return false;
    }
    sockets.clear();
    return DatagramSocket::ActiveCount() == baseline;
}
}  // namespace

int main() {
    try {
        const bool bindings = TestIndependentBindingsAndLargeScatter();
        const bool cancel = TestZeroLengthAndCancellationIsolation();
        const bool parent_cancel = TestParentCancellationPropagation();
        const bool ipv6 = TestIPv6MaximumAndFamilyValidation();
        const bool timeout_close = TestCloseAndReadScopeTimeout();
        const bool limit = TestSocketLimitAndReclamation();
        const bool reclaimed = DatagramSocket::ActiveCount() == 0;
        std::printf("datagram socket: bindings=%d cancel=%d parent_cancel=%d ipv6=%d timeout_close=%d limit=%d reclaimed=%d\n",
                    bindings, cancel, parent_cancel, ipv6, timeout_close, limit, reclaimed);
        return bindings && cancel && parent_cancel && ipv6 && timeout_close && limit && reclaimed ? 0 : 1;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "datagram socket test exception: %s\n", error.what());
        return 1;
    }
}
