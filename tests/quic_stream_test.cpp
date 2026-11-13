#include <gtest/gtest.h>

#include "transport/hysteria_ingress.hpp"
#include <asio/bind_cancellation_slot.hpp>
#include <asio/cancellation_signal.hpp>
#include <asio/co_spawn.hpp>
#include <asio/post.hpp>
#include <algorithm>
#include <array>
#include <chrono>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace {
using namespace std::chrono_literals;
using transport::UdpSessionStream;
using transport::QuicStreamState;


template <class Scenario>
void RunInDomain(Scenario scenario) {
    net::io_context io;
    std::exception_ptr failure;
    bool completed = false;
    auto run = [&]() -> net::awaitable<void> {
        try {
            co_await scenario(io);
        } catch (...) { failure = std::current_exception(); }
        completed = true;
    };
    net::co_spawn(io, run(), [&](std::exception_ptr error) { if (error) failure = error; });
    io.run_for(3s);
    EXPECT_TRUE(completed) << "UDP scenario did not complete";
    if (failure) std::rethrow_exception(failure);
}

class QuicUdpCancellation : public testing::TestWithParam<bool> {};

TEST_P(QuicUdpCancellation, ReturnsUnreadBuffersBeforeNotifyingSubscribers) {
    const bool destroy_host = GetParam();
    RunInDomain([destroy_host](net::io_context& io) -> net::awaitable<void> {
        const auto baseline = common::test_buffers_live;
        const common::TargetAddress target("127.0.0.1", 12345);
        auto stream = std::make_unique<UdpSessionStream>(io, 7,
            std::weak_ptr<transport::HysteriaConnection>{});
        constexpr std::array<std::string_view, 3> input{
            "delivered-first", "discard-second", "discard-third"};
        for (const auto bytes : input) {
            const bool admitted = stream->Push(target,
                {reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()});
            EXPECT_TRUE(admitted);
            if (!admitted) co_return;
        }
        auto delivered = co_await stream->ReadMultiBuffer();
        EXPECT_FALSE(delivered.empty());
        EXPECT_EQ(delivered.byte_size(), input[0].size());
        if (delivered.empty() || delivered.byte_size() != input[0].size()) co_return;
        EXPECT_EQ(common::test_buffers_live, baseline + input.size());
        struct Observer final : transport::CancellationSubscription {
            std::unique_ptr<UdpSessionStream>& host;
            bool destroy;
            bool notified = false;
            uint64_t buffers_at_notification = 0;
            common::ErrorCode reason = common::ErrorCode::OK;
            Observer(std::unique_ptr<UdpSessionStream>& host, bool destroy)
                : host(host), destroy(destroy) {}
            void OnCancellation(transport::Cancellation cancellation) noexcept override {
                notified = true;
                reason = cancellation.reason;
                buffers_at_notification = common::test_buffers_live;
                if (destroy) host.reset();
            }
        } observer(stream, destroy_host);
        observer.Resubscribe(stream->Cancellation());
        const auto rejected = common::rejected_process_allocations;
        common::reject_next_process_allocation = true;
        stream->Cancel();
        common::reject_next_process_allocation = false;
        EXPECT_EQ(common::rejected_process_allocations, rejected);
        EXPECT_TRUE(observer.notified);
        EXPECT_EQ(observer.reason, common::ErrorCode::CANCELLED);
        EXPECT_EQ(observer.buffers_at_notification, baseline + 1u)
            << "unread input was still owned during cancellation delivery";
        EXPECT_EQ(common::test_buffers_live, baseline + 1u)
            << "cancelled UDP host retained unreachable input";
        if (stream) stream->Cancel();
        {
            const auto* buffer = delivered.FrontBuffer();
            const auto bytes = buffer->Bytes();
            EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()), input[0]);
            EXPECT_TRUE(buffer->UDP().SameEndpoint(target));
        }
        delivered.clear();
        EXPECT_EQ(common::test_buffers_live, baseline);
        stream.reset();
    });
}

TEST(QuicUdpQueue, BoundsBufferCapacityAndReturnsAdmissionOnRead) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        const auto baseline = common::test_buffers_live;
        const common::TargetAddress target("127.0.0.1", 12345);
        UdpSessionStream stream(io, 9, {});
        constexpr size_t limit = UdpSessionStream::kMaxQueuedBytes / common::Buffer::kSize;
        size_t accepted = 0;
        for (size_t index = 0; index < 2 * limit; ++index) {
            const uint8_t byte = static_cast<uint8_t>(index % 251);
            if (stream.Push(target, {&byte, 1})) ++accepted;
        }
        EXPECT_EQ(accepted, limit);
        if (accepted != limit) co_return;
        EXPECT_EQ(common::test_buffers_live, baseline + limit);
        const uint8_t replacement = 0xee;
        const auto rejected = common::rejected_process_allocations;
        common::reject_next_process_allocation = true;
        const bool admitted_when_full = stream.Push(target, {&replacement, 1});
        common::reject_next_process_allocation = false;
        EXPECT_FALSE(admitted_when_full);
        EXPECT_EQ(common::rejected_process_allocations, rejected)
            << "full UDP queue attempted allocation before rejecting input";

        auto first = co_await stream.ReadMultiBuffer();
        EXPECT_FALSE(first.empty());
        EXPECT_EQ(first.byte_size(), 1u);
        if (first.empty() || first.byte_size() != 1) co_return;
        EXPECT_EQ(first.FrontSpan().front(), 0);
        std::vector<uint8_t> two_blocks(common::Buffer::kSize + 1, 0x6c);
        two_blocks.front() = 0x12;
        two_blocks.back() = 0x91;
        const auto rejected_with_one_slot = common::rejected_process_allocations;
        common::reject_next_process_allocation = true;
        const bool admitted_with_one_slot = stream.Push(target, two_blocks);
        common::reject_next_process_allocation = false;
        EXPECT_FALSE(admitted_with_one_slot);
        EXPECT_EQ(common::rejected_process_allocations, rejected_with_one_slot)
            << "two-block input allocated with only one queued block available";
        auto second = co_await stream.ReadMultiBuffer();
        EXPECT_FALSE(second.empty());
        EXPECT_EQ(second.byte_size(), 1u);
        if (second.empty() || second.byte_size() != 1) co_return;
        EXPECT_EQ(second.FrontSpan().front(), 1);
        const bool admitted = stream.Push(target, two_blocks);
        EXPECT_TRUE(admitted);
        if (!admitted) co_return;
        EXPECT_TRUE(first.FrontBuffer()->UDP().SameEndpoint(target));
        first.clear();
        second.clear();
        for (size_t index = 2; index < accepted; ++index) {
            auto packet = co_await stream.ReadMultiBuffer();
            EXPECT_FALSE(packet.empty());
            EXPECT_EQ(packet.byte_size(), 1u);
            if (packet.empty() || packet.byte_size() != 1) co_return;
            EXPECT_EQ(packet.FrontSpan().front(), static_cast<uint8_t>(index % 251));
            EXPECT_TRUE(packet.FrontBuffer()->UDP().SameEndpoint(target));
        }
        auto tail = co_await stream.ReadMultiBuffer();
        EXPECT_EQ(tail.byte_size(), two_blocks.size());
        if (tail.byte_size() != two_blocks.size()) co_return;
        const auto bytes = tail.FrontSpan();
        EXPECT_EQ(bytes.size(), two_blocks.size());
        if (bytes.size() != two_blocks.size()) co_return;
        EXPECT_TRUE(std::equal(bytes.begin(), bytes.end(), two_blocks.begin()));
        EXPECT_TRUE(tail.FrontBuffer()->UDP().SameEndpoint(target));
        tail.clear();
        EXPECT_EQ(common::test_buffers_live, baseline);

    });
}

TEST(QuicUdpQueue, OversizedDatagramIsRejectedBeforeAllocation) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        const auto baseline = common::test_buffers_live;
        const common::TargetAddress target("127.0.0.1", 12345);
        UdpSessionStream stream(io, 11, {});
        const std::vector<uint8_t> oversized(UdpSessionStream::kMaxQueuedBytes + 1, 0x7a);
        const auto rejected_before_oversized = common::rejected_process_allocations;
        common::reject_next_process_allocation = true;
        const bool oversized_admitted = stream.Push(target, oversized);
        common::reject_next_process_allocation = false;
        EXPECT_FALSE(oversized_admitted);
        EXPECT_EQ(common::rejected_process_allocations, rejected_before_oversized)
            << "oversized UDP input underflowed its budget check";
        EXPECT_EQ(common::test_buffers_live, baseline);
        co_return;
    });
}

TEST(QuicUdpQueue, EmptyMessagesConsumeBufferAdmissionAndRemainReadable) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        const auto baseline = common::test_buffers_live;
        const common::TargetAddress target("127.0.0.1", 12345);
        UdpSessionStream stream(io, 10, {});
        constexpr size_t limit = UdpSessionStream::kMaxQueuedBytes / common::Buffer::kSize;
        size_t admitted = 0;
        for (size_t index = 0; index <= limit; ++index)
            admitted += stream.Push(target, {});
        EXPECT_EQ(admitted, limit);
        if (admitted != limit) co_return;
        EXPECT_EQ(common::test_buffers_live, baseline + limit);
        const auto rejected = common::rejected_process_allocations;
        common::reject_next_process_allocation = true;
        const bool overflow = stream.Push(target, {});
        common::reject_next_process_allocation = false;
        EXPECT_FALSE(overflow);
        EXPECT_EQ(common::rejected_process_allocations, rejected);

        auto packet = co_await stream.ReadMultiBuffer();
        {
            const auto datagram = common::InspectUdpDatagram(packet);
            EXPECT_TRUE(datagram.Valid());
            EXPECT_NE(datagram.target, nullptr);
            if (!datagram.Valid() || !datagram.target) co_return;
            EXPECT_EQ(datagram.payload_size, 0u);
            EXPECT_TRUE(datagram.target->SameEndpoint(target));
        }
        const uint8_t later = 0x7a;
        EXPECT_TRUE(stream.Push(target, {&later, 1}));
        stream.Cancel();
        EXPECT_EQ(common::test_buffers_live, baseline + 1);
        EXPECT_EQ(common::InspectUdpDatagram(packet).status, common::UdpDatagramStatus::Valid);
        packet.clear();
        EXPECT_EQ(common::test_buffers_live, baseline);
    });
}

struct StreamCancellation final : transport::CancellationSubscription {
    bool notified = false;
    common::ErrorCode reason = common::ErrorCode::OK;
    bool terminal = false;

    void OnCancellation(transport::Cancellation cancellation) noexcept override {
        notified = true;
        reason = cancellation.reason;
        terminal = cancellation.terminal;
    }
};

TEST(QuicStreamClose, CompletedDuplexLeavesTransportAliveUntilNativeRetirement) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        auto state = std::make_shared<QuicStreamState>(io, 4, std::weak_ptr<transport::HysteriaConnection>{});
        StreamCancellation cancellation;
        cancellation.Resubscribe(state->Cancellation());
        {
            transport::QuicStream stream(state);
            const std::array<uint8_t, 3> input{0x12, 0x34, 0x56};
            const bool admitted = state->PushInput(input, true);
            EXPECT_TRUE(admitted);
            if (!admitted) co_return;
            std::array<uint8_t, 3> received{};
            EXPECT_EQ(co_await stream.AsyncRead(net::buffer(received)), input.size());
            EXPECT_EQ(received, input);
            EXPECT_TRUE((co_await stream.ReadMultiBuffer()).empty());
            stream.ShutdownWrite();
            stream.Close();
            stream.Close();
            EXPECT_FALSE(stream.IsOpen());
            EXPECT_TRUE(state->Open());
            EXPECT_FALSE(cancellation.notified);
            EXPECT_THROW(state->CheckWriteOpen(), transport::WriteClosed);
        }
        // The facade's destructor must not turn completed application I/O into
        // RESET_STREAM while the connection still owns unacknowledged output.
        EXPECT_TRUE(state->Open());
        EXPECT_FALSE(cancellation.notified);
        state->OnStreamClosed();
        EXPECT_TRUE((co_await state->ReadMultiBuffer()).empty());
        EXPECT_FALSE(cancellation.notified);
    });
}

TEST(QuicStreamClose, UnreadFinTailIsDiscardedAndCancelled) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        auto state = std::make_shared<QuicStreamState>(io, 8, std::weak_ptr<transport::HysteriaConnection>{});
        transport::QuicStream stream(state);
        StreamCancellation cancellation;
        cancellation.Resubscribe(stream.Cancellation());
        const std::array<uint8_t, 3> input{0x21, 0x43, 0x65};
        const bool admitted = state->PushInput(input, true);
        EXPECT_TRUE(admitted);
        if (!admitted) co_return;
        uint8_t first = 0;
        EXPECT_EQ(co_await stream.AsyncRead(net::buffer(&first, 1)), 1);
        EXPECT_EQ(first, input.front());
        stream.ShutdownWrite();
        stream.Close();
        EXPECT_FALSE(stream.IsOpen());
        EXPECT_FALSE(state->Open());
        EXPECT_TRUE(state->PendingInput().empty());
        EXPECT_TRUE(cancellation.notified);
        EXPECT_TRUE(cancellation.terminal);
        EXPECT_EQ(cancellation.reason, common::ErrorCode::CANCELLED);
        try {
            (void)co_await state->ReadMultiBuffer();
            ADD_FAILURE() << "aborted input tail became graceful EOF";
        } catch (const transport::LinkError& error) {
            EXPECT_EQ(error.code(), common::ErrorCode::CANCELLED);
        }
    });
}

class QuicStreamHalfClose : public testing::TestWithParam<bool> {};

TEST_P(QuicStreamHalfClose, CloseAbortsIncompleteDuplex) {
    const bool remote_fin = GetParam();
    RunInDomain([remote_fin](net::io_context& io) -> net::awaitable<void> {
        auto state = std::make_shared<QuicStreamState>(io, 12, std::weak_ptr<transport::HysteriaConnection>{});
        transport::QuicStream stream(state);
        StreamCancellation cancellation;
        cancellation.Resubscribe(stream.Cancellation());
        if (remote_fin) {
            const bool admitted = state->PushInput({}, true);
            EXPECT_TRUE(admitted);
            if (!admitted) co_return;
            EXPECT_TRUE((co_await stream.ReadMultiBuffer()).empty());
        } else {
            stream.ShutdownWrite();
        }
        stream.Close();
        EXPECT_FALSE(stream.IsOpen());
        EXPECT_FALSE(state->Open());
        EXPECT_TRUE(cancellation.notified);
        EXPECT_TRUE(cancellation.terminal);
        EXPECT_EQ(cancellation.reason, common::ErrorCode::CANCELLED);
        EXPECT_THROW(state->CheckWriteOpen(), transport::LinkError);
        co_return;
    });
}

INSTANTIATE_TEST_SUITE_P(Directions, QuicStreamHalfClose, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "RemoteFin" : "LocalShutdown";
    });

class QuicStreamAbort : public testing::TestWithParam<bool> {};

TEST_P(QuicStreamAbort, ExplicitAbortCancelsEvenCompletedDuplex) {
    const bool abortive_close = GetParam();
    RunInDomain([abortive_close](net::io_context& io) -> net::awaitable<void> {
        auto state = std::make_shared<QuicStreamState>(io, 16, std::weak_ptr<transport::HysteriaConnection>{});
        transport::QuicStream stream(state);
        StreamCancellation cancellation;
        cancellation.Resubscribe(stream.Cancellation());
        const bool admitted = state->PushInput({}, true);
        EXPECT_TRUE(admitted);
        if (!admitted) co_return;
        EXPECT_TRUE((co_await stream.ReadMultiBuffer()).empty());
        stream.ShutdownWrite();
        if (abortive_close) stream.CloseAbortive();
        else stream.Cancel();
        stream.Close();
        EXPECT_FALSE(state->Open());
        EXPECT_TRUE(cancellation.notified);
        EXPECT_TRUE(cancellation.terminal);
        EXPECT_EQ(cancellation.reason, common::ErrorCode::CANCELLED);
        try {
            (void)co_await state->ReadMultiBuffer();
            ADD_FAILURE() << "explicit cancellation became graceful EOF";
        } catch (const transport::LinkError& error) {
            EXPECT_EQ(error.code(), common::ErrorCode::CANCELLED);
        }
    });
}

INSTANTIATE_TEST_SUITE_P(Operations, QuicStreamAbort, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "CloseAbortive" : "Cancel";
    });

TEST(QuicStreamWriteWait, BroadcastsWithoutLeavingStaleReadiness) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        QuicStreamState state(io, 4, {});
        const auto executor = co_await net::this_coro::executor;
        common::SignalChannel joined(executor, 2);
        std::exception_ptr failure;
        size_t started = 0;
        size_t completed = 0;
        auto wait = [&]() -> net::awaitable<void> {
            ++started;
            co_await state.WaitWritable();
            ++completed;
        };
        auto finish = [&](std::exception_ptr error) {
            if (error) failure = error;
            (void)joined.try_send(IoErrorCode{});
        };
        for (size_t round = 0; round < 2; ++round) {
            // An ACK with no current waiter must not make a later full-queue
            // wait complete immediately.
            state.NotifyWritable();
            net::co_spawn(executor, wait(), finish);
            net::co_spawn(executor, wait(), finish);
            co_await net::post(executor, net::use_awaitable);
            EXPECT_EQ(started, (round + 1) * 2);
            EXPECT_EQ(completed, round * 2);
            state.NotifyWritable();
            co_await joined.async_receive(net::use_awaitable);
            co_await joined.async_receive(net::use_awaitable);
            if (failure) std::rethrow_exception(failure);
            EXPECT_EQ(completed, (round + 1) * 2);
        }
    });
}

enum class WriteWaitEnd { ShutdownWrite, Cancel, Reset, StreamClose, HostClose };
class QuicStreamWriteWaitEnd : public testing::TestWithParam<WriteWaitEnd> {};

TEST_P(QuicStreamWriteWaitEnd, SettlesPendingAndSubsequentWaits) {
    const auto ending = GetParam();
    RunInDomain([ending](net::io_context& io) -> net::awaitable<void> {
        auto state = std::make_shared<QuicStreamState>(io, 8, std::weak_ptr<transport::HysteriaConnection>{});
        transport::QuicStream stream(state);
        const std::array<uint8_t, 3> tail{0x21, 0x43, 0x65};
        const bool admitted = state->PushInput(tail, false);
        EXPECT_TRUE(admitted);
        if (!admitted) co_return;
        const auto executor = co_await net::this_coro::executor;
        common::SignalChannel joined(executor, 1);
        bool started = false;
        bool completed = false;
        std::exception_ptr failure;
        const bool cancelled = ending == WriteWaitEnd::Cancel ||
            ending == WriteWaitEnd::Reset || ending == WriteWaitEnd::HostClose;
        auto expect_closed = [&]() -> net::awaitable<void> {
            try {
                co_await state->WaitWritable();
                ADD_FAILURE() << "ended output wait succeeded";
            } catch (const transport::WriteClosed&) {
                EXPECT_FALSE(cancelled);
            } catch (const transport::LinkError& error) {
                EXPECT_TRUE(cancelled);
                EXPECT_EQ(error.code(), common::ErrorCode::CANCELLED);
            }
        };
        auto wait = [&]() -> net::awaitable<void> {
            started = true;
            co_await expect_closed();
            completed = true;
        };
        net::co_spawn(executor, wait(), [&](std::exception_ptr error) {
            failure = error;
            (void)joined.try_send(IoErrorCode{});
        });
        co_await net::post(executor, net::use_awaitable);
        EXPECT_TRUE(started);
        EXPECT_FALSE(completed);
        switch (ending) {
        case WriteWaitEnd::ShutdownWrite: state->ShutdownWrite(); break;
        case WriteWaitEnd::Cancel: state->Cancel(); break;
        case WriteWaitEnd::Reset: state->RemoteReset(); break;
        case WriteWaitEnd::StreamClose: state->OnStreamClosed(); break;
        case WriteWaitEnd::HostClose: stream.Close(); break;
        }
        co_await joined.async_receive(net::use_awaitable);
        if (failure) std::rethrow_exception(failure);
        EXPECT_TRUE(completed);
        co_await expect_closed();
        if (!cancelled) {
            EXPECT_TRUE(state->Open());
            auto input = co_await state->ReadMultiBuffer();
            const auto bytes = input.FrontSpan();
            std::vector<uint8_t> received(bytes.begin(), bytes.end());
            EXPECT_EQ(received, std::vector<uint8_t>(tail.begin(), tail.end()));
            if (ending == WriteWaitEnd::ShutdownWrite) {
                const bool admitted = state->PushInput({}, true);
                EXPECT_TRUE(admitted);
                if (!admitted) co_return;
            }
            EXPECT_EQ((co_await state->ReadMultiBuffer()).byte_size(), 0);
        } else {
            EXPECT_FALSE(state->Open());
            EXPECT_TRUE(state->PendingInput().empty());
        }
    });
}

INSTANTIATE_TEST_SUITE_P(Lifecycle, QuicStreamWriteWaitEnd,
    testing::Values(WriteWaitEnd::ShutdownWrite, WriteWaitEnd::Cancel,
                    WriteWaitEnd::Reset, WriteWaitEnd::StreamClose, WriteWaitEnd::HostClose),
    [](const testing::TestParamInfo<WriteWaitEnd>& info) {
        switch (info.param) {
        case WriteWaitEnd::ShutdownWrite: return "ShutdownWrite";
        case WriteWaitEnd::Cancel: return "Cancel";
        case WriteWaitEnd::Reset: return "Reset";
        case WriteWaitEnd::StreamClose: return "StreamClose";
        case WriteWaitEnd::HostClose: return "HostClose";
        }
        return "Unknown";
    });

TEST(QuicStreamWriteWait, RemoteFinLeavesWriterWaitingForOutputCredit) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        QuicStreamState state(io, 12, {});
        const auto executor = co_await net::this_coro::executor;
        common::SignalChannel joined(executor, 1);
        std::exception_ptr failure;
        bool started = false;
        bool completed = false;
        auto wait = [&]() -> net::awaitable<void> {
            started = true;
            co_await state.WaitWritable();
            completed = true;
        };
        net::co_spawn(executor, wait(), [&](std::exception_ptr error) {
            failure = error;
            (void)joined.try_send(IoErrorCode{});
        });
        co_await net::post(executor, net::use_awaitable);
        EXPECT_TRUE(started);
        EXPECT_FALSE(completed);
        const bool admitted = state.PushInput({}, true);
        EXPECT_TRUE(admitted);
        if (admitted) EXPECT_EQ((co_await state.ReadMultiBuffer()).byte_size(), 0);
        co_await net::post(executor, net::use_awaitable);
        EXPECT_FALSE(completed);
        EXPECT_NO_THROW(state.CheckWriteOpen());
        state.NotifyWritable();
        co_await joined.async_receive(net::use_awaitable);
        if (failure) std::rethrow_exception(failure);
        EXPECT_TRUE(completed);
    });
}

TEST(QuicStreamWriteWait, CoroutineCancellationDoesNotBecomeAnAck) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        QuicStreamState state(io, 16, {});
        const auto executor = co_await net::this_coro::executor;
        common::SignalChannel joined(executor, 1);
        net::cancellation_signal cancellation;
        std::exception_ptr failure;
        bool started = false;
        auto wait = [&]() -> net::awaitable<void> {
            started = true;
            co_await state.WaitWritable();
        };
        net::co_spawn(executor, wait(), net::bind_cancellation_slot(
            cancellation.slot(), [&](std::exception_ptr error) {
                failure = error;
                (void)joined.try_send(IoErrorCode{});
            }));
        co_await net::post(executor, net::use_awaitable);
        EXPECT_TRUE(started);
        cancellation.emit(net::cancellation_type::terminal);
        co_await joined.async_receive(net::use_awaitable);
        EXPECT_NE(failure, nullptr);
        if (!failure) co_return;
        try {
            std::rethrow_exception(failure);
        } catch (const IoSystemError& error) {
            EXPECT_EQ(error.code(), net::error::operation_aborted);
        }
        // Cancelling one operation must leave this stream usable.
        state.CheckWriteOpen();
        EXPECT_TRUE(state.Open());
    });
}

INSTANTIATE_TEST_SUITE_P(HostLifetime, QuicUdpCancellation, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "DestroyInCallback" : "KeepHost";
    });
} // namespace
