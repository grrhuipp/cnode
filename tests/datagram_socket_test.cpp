#include <gtest/gtest.h>

#include "transport/internet/datagram_socket.hpp"

#include "common/buf/multi_buffer.hpp"
#include "transport/link.hpp"
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

enum class SendShape { LargeOwnedPayload, FragmentedOwnedPayload, BorrowedScatter };
class DatagramSocketPayload : public testing::TestWithParam<SendShape> {};
TEST_P(DatagramSocketPayload, PreservesPayloadAndSourceWithIndependentBindings) {
    ::net::io_context io;
    DatagramSocket receiver(io, ::net::ip::address_v4::loopback());
    DatagramSocket sender(io, ::net::ip::address_v4::loopback());
    EXPECT_NE(receiver.LocalEndpoint().port(), sender.LocalEndpoint().port());
    std::vector<uint8_t> bytes(GetParam() == SendShape::LargeOwnedPayload ? 60000 : 100);
    for (std::size_t i = 0; i < bytes.size(); ++i)
        bytes[i] = static_cast<uint8_t>(GetParam() == SendShape::LargeOwnedPayload ? i * 31u : i);
    ::buf::MultiBuffer payload;
    std::vector<::net::const_buffer> scatter;
    if (GetParam() == SendShape::LargeOwnedPayload) {
        payload = MakePayload(bytes);
    } else if (GetParam() == SendShape::FragmentedOwnedPayload) {
        for (const auto byte : bytes) {
            ::buf::BufferGuard buffer{::buf::Buffer::New()};
            ASSERT_TRUE(buffer);
            buffer->Tail()[0] = byte;
            buffer->Produce(1);
            payload.push_back(std::move(buffer));
        }
    } else {
        for (const auto& byte : bytes) scatter.push_back(::net::buffer(&byte, 1));
    }
    auto read = receiver.StartRead();
    auto receiving = ::net::co_spawn(io, read.Receive(), ::net::use_future);
    auto sending = ::net::co_spawn(io,
        GetParam() == SendShape::BorrowedScatter
            ? SendBuffers(sender, receiver.LocalEndpoint(), scatter)
            : SendPayload(sender, receiver.LocalEndpoint(), std::move(payload)),
        ::net::use_future);
    io.run();
    sending.get();
    const auto packet = receiving.get();
    EXPECT_EQ(packet.source, sender.LocalEndpoint());
    std::vector<uint8_t> received;
    for (const auto* buffer : packet.payload)
        received.insert(received.end(), buffer->Bytes().begin(), buffer->Bytes().end());
    EXPECT_EQ(received, bytes);
}
INSTANTIATE_TEST_SUITE_P(SendShapes, DatagramSocketPayload,
    testing::Values(SendShape::LargeOwnedPayload, SendShape::FragmentedOwnedPayload, SendShape::BorrowedScatter),
    [](const testing::TestParamInfo<SendShape>& info) {
        switch (info.param) {
        case SendShape::LargeOwnedPayload: return "LargeOwned";
        case SendShape::FragmentedOwnedPayload: return "FragmentedOwned";
        case SendShape::BorrowedScatter: return "BorrowedScatter";
        }
        return "Unknown";
    });

TEST(DatagramSocket, ZeroLengthAndCancellationIsolation) {
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
    EXPECT_TRUE(cancelled);
    EXPECT_FALSE(packet.payload.empty());
    EXPECT_EQ(packet.payload.byte_size(), 0u);
    EXPECT_FALSE(packet.source.address().is_v6());
    EXPECT_EQ(DatagramSocket::ActiveCount(), count);
    EXPECT_FALSE(first.IsIPv6());
    EXPECT_FALSE(second.IsIPv6());
    first.Close();
    EXPECT_EQ(DatagramSocket::ActiveCount(), count - 1);
    EXPECT_NE(second.LocalEndpoint().port(), 0);
}

TEST(DatagramSocket, ParentCancellationPropagation) {
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
    EXPECT_TRUE(completed_without_socket_cancel);
    EXPECT_TRUE(aborted);
}

TEST(DatagramSocket, IPv6MaximumAndFamilyValidation) {
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
    EXPECT_EQ(packet.payload.byte_size(), bytes.size());
    EXPECT_TRUE(packet.source.address().is_v6());

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
    EXPECT_TRUE(family_rejected);
    EXPECT_TRUE(size_rejected);
}

TEST(DatagramSocket, CloseAndReadScopeTimeout) {
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
    if (first.wait_for(0ms) != std::future_status::ready) {
        receiver.Close();
        io.restart();
        io.run();
        FAIL() << "initial datagram receive did not complete";
    }
    EXPECT_EQ(first.get().payload.byte_size(), 1u);

    // The same scope keeps its original read deadline across repeated receives.
    auto second = ::net::co_spawn(io, operation.Receive(), ::net::use_future);
    io.restart();
    io.run_for(1100ms);
    if (second.wait_for(0ms) != std::future_status::ready) {
        receiver.Close();
        io.restart();
        io.run();
        ADD_FAILURE() << "read scope deadline did not complete the receive";
    }
    bool timed_out = false;
    try { (void)second.get(); }
    catch (const ::transport::LinkError&) { timed_out = true; }
    EXPECT_TRUE(timed_out);
    EXPECT_TRUE(receiver.ConsumeReadTimeout());

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
    EXPECT_TRUE(closed_error);
    EXPECT_EQ(DatagramSocket::ActiveCount(), baseline + 1);
}
TEST(DatagramSocket, SocketLimitAndReclamation) {
    constexpr std::size_t limit = 4096;
    const auto baseline = DatagramSocket::ActiveCount();
    ASSERT_LT(baseline, limit);
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
    EXPECT_TRUE(rejected);
    EXPECT_EQ(DatagramSocket::ActiveCount(), limit);
    sockets.pop_back();
    {
        DatagramSocket replacement(io, ::net::ip::address_v4::loopback());
        EXPECT_EQ(DatagramSocket::ActiveCount(), limit);
    }
    sockets.clear();
    EXPECT_EQ(DatagramSocket::ActiveCount(), baseline);
}
class DatagramSocketWrite : public testing::TestWithParam<bool> {};
TEST_P(DatagramSocketWrite, ZeroLengthNativeSends) {
    ::net::io_context io;
    DatagramSocket sender(io, ::net::ip::address_v4::loopback());
    DatagramSocket receiver(io, ::net::ip::address_v4::loopback());
    const bool owned = GetParam();
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
        FAIL() << "zero-length send or receive did not complete";
    }
    sending.get();
    const auto packet = receiving.get();
    EXPECT_FALSE(packet.payload.empty());
    EXPECT_EQ(packet.payload.byte_size(), 0u);
    EXPECT_EQ(packet.source, sender.LocalEndpoint());
}

}  // namespace


TEST_P(DatagramSocketWrite, CancelledWriteDoesNotSend) {
    const bool owned = GetParam();
    ::net::io_context io;
    DatagramSocket sender(io, ::net::ip::address_v4::loopback());
    ::udp::socket peer(io, {::net::ip::address_v4::loopback(), 0});
    peer.non_blocking(true);
    ::net::cancellation_signal cancellation;
    const std::array<uint8_t, 1> payload{42};
    const std::array<::net::const_buffer, 1> buffers{::net::buffer(payload)};
    auto send = [&]() -> ::net::awaitable<void> {
        // 显式关闭隐式取消异常后，操作仍须在发送前检查粘滞取消状态。
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
INSTANTIATE_TEST_SUITE_P(PayloadOwnership, DatagramSocketWrite, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "Owned" : "Borrowed";
    });

TEST(DatagramSocket, PeekDatagramSizeReportsHeadWithoutConsuming) {
    ::net::io_context io;
    ::udp::socket receiver(io, {::net::ip::address_v4::loopback(), 0});
    ::udp::socket sender(io, ::udp::v4());
    receiver.non_blocking(true);
    ::IoErrorCode error;
    EXPECT_EQ(::transport::internet::PeekDatagramSize(receiver, error), 0u);
    // The empty-queue code must match the asio enum receive paths compare with.
    EXPECT_TRUE(error == ::io_error::would_block || error == ::io_error::try_again);

    const std::vector<uint8_t> large(19999, 0x5a);
    sender.send_to(::net::buffer(large), receiver.local_endpoint());
    sender.send_to(::net::const_buffer{}, receiver.local_endpoint());
    std::vector<uint8_t> received(65536);
    ::udp::endpoint source;
    EXPECT_EQ(::transport::internet::PeekDatagramSize(receiver, error), large.size());
    EXPECT_FALSE(error);
    EXPECT_EQ(::transport::internet::PeekDatagramSize(receiver, error), large.size());
    EXPECT_EQ(receiver.receive_from(::net::buffer(received), source), large.size());
    // A zero-length datagram is a real datagram, not an empty queue.
    EXPECT_EQ(::transport::internet::PeekDatagramSize(receiver, error), 0u);
    EXPECT_FALSE(error);
    EXPECT_EQ(receiver.receive_from(::net::buffer(received), source), 0u);
    (void)::transport::internet::PeekDatagramSize(receiver, error);
    EXPECT_TRUE(error == ::io_error::would_block || error == ::io_error::try_again);
}
