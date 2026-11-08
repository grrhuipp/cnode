#include <gtest/gtest.h>

#include "quic_stream.hpp"
#include "common/memory_stats.hpp"
#include "transport/link_error.hpp"

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
using transport::internet::hysteria::UdpSessionStream;
using transport::internet::hysteria::QuicStreamState;

void Require(bool value, const char* reason) {
    if (!value) throw std::runtime_error(reason);
}

struct Hooks final : ExecutionDomain::Hooks {
    memory::AllocationDomain allocation;
    std::optional<memory::ScopedAllocationDomain> lease;
    std::exception_ptr failure;
    void Enter() noexcept override { lease.emplace(allocation); }
    void Leave() noexcept override { lease.reset(); }
    void OnFailure(std::exception_ptr error) noexcept override { failure = error; }
};

template <class Scenario>
void RunInDomain(Scenario scenario) {
    net::io_context io;
    auto coordinator = std::make_shared<GroupCoordinator>(io);
    coordinator->RegisterWorker(0, io, io.get_executor());
    auto hooks = std::make_shared<Hooks>();
    auto domain = ExecutionDomain::Create(io, 0, io.get_executor(), hooks, coordinator);
    hooks->allocation.SetLeaseGroup(domain->LeaseIdentity(), ExecutionDomain::SharesLeaseIdentity);
    std::exception_ptr failure;
    bool completed = false;
    auto run = [&]() -> net::awaitable<void> {
        try {
            co_await net::co_spawn(domain->Executor(), scenario(io), net::use_awaitable);
        } catch (...) { failure = std::current_exception(); }
        co_await net::post(io, net::use_awaitable);
        coordinator->CloseAdmission();
        co_await coordinator->AsyncJoin();
        coordinator->ReleaseServices();
        domain.reset();
        co_await coordinator->Finalize();
        completed = true;
    };
    net::co_spawn(io, run(), [&](std::exception_ptr error) { if (error) failure = error; });
    io.run_for(3s);
    EXPECT_TRUE(completed) << "UDP scenario left its execution domain alive";
    if (failure) std::rethrow_exception(failure);
    if (hooks->failure) std::rethrow_exception(hooks->failure);
}

class QuicUdpCancellation : public testing::TestWithParam<bool> {};

TEST_P(QuicUdpCancellation, ReturnsUnreadBuffersBeforeNotifyingSubscribers) {
    const bool destroy_host = GetParam();
    RunInDomain([destroy_host](net::io_context& io) -> net::awaitable<void> {
        const auto baseline = memory::detail::test_buffers_live;
        const TargetAddress target("127.0.0.1", 12345);
        auto stream = std::make_unique<UdpSessionStream>(io, 7, target,
            std::weak_ptr<transport::internet::hysteria::Connection>{});
        constexpr std::array<std::string_view, 3> input{
            "delivered-first", "discard-second", "discard-third"};
        for (const auto bytes : input) {
            Require(stream->Push(target, {reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()}),
                    "UDP input was not admitted");
        }
        auto delivered = co_await stream->ReadMultiBuffer();
        Require(delivered.size() == 1 && delivered.byte_size() == input[0].size(),
                "UDP read did not transfer the first datagram");
        EXPECT_EQ(memory::detail::test_buffers_live, baseline + input.size());
        struct Observer final : transport::CancellationSubscription {
            std::unique_ptr<UdpSessionStream>& host;
            bool destroy;
            bool notified = false;
            uint64_t buffers_at_notification = 0;
            ErrorCode reason = ErrorCode::OK;
            Observer(std::unique_ptr<UdpSessionStream>& host, bool destroy)
                : host(host), destroy(destroy) {}
            void OnCancellation(transport::Cancellation cancellation) noexcept override {
                notified = true;
                reason = cancellation.reason;
                buffers_at_notification = memory::detail::test_buffers_live;
                if (destroy) host.reset();
            }
        } observer(stream, destroy_host);
        observer.Resubscribe(stream->Cancellation());
        const auto rejected = memory::rejected_pmr_allocations;
        memory::reject_next_pmr_allocation = true;
        stream->Cancel();
        memory::reject_next_pmr_allocation = false;
        EXPECT_EQ(memory::rejected_pmr_allocations, rejected);
        EXPECT_TRUE(observer.notified);
        EXPECT_EQ(observer.reason, ErrorCode::CANCELLED);
        EXPECT_EQ(observer.buffers_at_notification, baseline + delivered.size())
            << "unread input was still owned during cancellation delivery";
        EXPECT_EQ(memory::detail::test_buffers_live, baseline + delivered.size())
            << "cancelled UDP host retained unreachable input";
        if (stream) stream->Cancel();
        {
            const auto* buffer = *delivered.begin();
            const auto bytes = buffer->Bytes();
            EXPECT_EQ(std::string_view(reinterpret_cast<const char*>(bytes.data()), bytes.size()), input[0]);
            EXPECT_TRUE(buffer->UDP().SameEndpoint(target));
        }
        delivered.clear();
        EXPECT_EQ(memory::detail::test_buffers_live, baseline);
        stream.reset();
    });
}

TEST(QuicUdpQueue, BoundsBufferCapacityAndReturnsAdmissionOnRead) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        const auto baseline = memory::detail::test_buffers_live;
        const TargetAddress target("127.0.0.1", 12345);
        UdpSessionStream stream(io, 9, target, {});
        constexpr size_t limit = UdpSessionStream::kMaxQueuedBytes / buf::Buffer::kSize;
        size_t accepted = 0;
        for (size_t index = 0; index < 2 * limit; ++index) {
            const uint8_t byte = static_cast<uint8_t>(index % 251);
            if (stream.Push(target, {&byte, 1})) ++accepted;
        }
        EXPECT_EQ(accepted, limit);
        EXPECT_EQ(memory::detail::test_buffers_live, baseline + limit);
        const uint8_t replacement = 0xee;
        const auto rejected = memory::rejected_pmr_allocations;
        memory::reject_next_pmr_allocation = true;
        const bool admitted_when_full = stream.Push(target, {&replacement, 1});
        memory::reject_next_pmr_allocation = false;
        EXPECT_FALSE(admitted_when_full);
        EXPECT_EQ(memory::rejected_pmr_allocations, rejected)
            << "full UDP queue attempted allocation before rejecting input";

        auto first = co_await stream.ReadMultiBuffer();
        Require(first.size() == 1 && first.byte_size() == 1, "UDP first packet changed");
        EXPECT_EQ((*first.begin())->Bytes().front(), 0);
        std::vector<uint8_t> two_blocks(buf::Buffer::kSize + 1, 0x6c);
        two_blocks.front() = 0x12;
        two_blocks.back() = 0x91;
        const auto rejected_with_one_slot = memory::rejected_pmr_allocations;
        memory::reject_next_pmr_allocation = true;
        const bool admitted_with_one_slot = stream.Push(target, two_blocks);
        memory::reject_next_pmr_allocation = false;
        EXPECT_FALSE(admitted_with_one_slot);
        EXPECT_EQ(memory::rejected_pmr_allocations, rejected_with_one_slot)
            << "two-block input allocated with only one queued block available";
        auto second = co_await stream.ReadMultiBuffer();
        Require(second.size() == 1 && second.byte_size() == 1, "UDP second packet changed");
        EXPECT_EQ((*second.begin())->Bytes().front(), 1);
        Require(stream.Push(target, two_blocks), "UDP reads did not return two-block admission");
        EXPECT_EQ((*first.begin())->Bytes().front(), 0);
        EXPECT_TRUE((*first.begin())->UDP().SameEndpoint(target));
        first.clear();
        second.clear();
        for (size_t index = 2; index < accepted; ++index) {
            auto packet = co_await stream.ReadMultiBuffer();
            Require(packet.size() == 1 && packet.byte_size() == 1, "UDP packet boundary changed");
            EXPECT_EQ((*packet.begin())->Bytes().front(), static_cast<uint8_t>(index % 251));
            EXPECT_TRUE((*packet.begin())->UDP().SameEndpoint(target));
        }
        auto tail = co_await stream.ReadMultiBuffer();
        Require(tail.size() == 2 && tail.byte_size() == two_blocks.size(),
                "UDP multi-block packet boundary changed");
        size_t offset = 0;
        for (const auto* buffer : tail) {
            const auto bytes = buffer->Bytes();
            EXPECT_TRUE(std::equal(bytes.begin(), bytes.end(), two_blocks.begin() + offset));
            EXPECT_TRUE(buffer->UDP().SameEndpoint(target));
            offset += bytes.size();
        }
        tail.clear();
        EXPECT_EQ(memory::detail::test_buffers_live, baseline);

        const std::vector<uint8_t> oversized(UdpSessionStream::kMaxQueuedBytes + 1, 0x7a);
        const auto rejected_before_oversized = memory::rejected_pmr_allocations;
        memory::reject_next_pmr_allocation = true;
        const bool oversized_admitted = stream.Push(target, oversized);
        memory::reject_next_pmr_allocation = false;
        EXPECT_FALSE(oversized_admitted);
        EXPECT_EQ(memory::rejected_pmr_allocations, rejected_before_oversized)
            << "oversized UDP input underflowed its budget check";
        const bool oversized_without_fault = stream.Push(target, oversized);
        EXPECT_FALSE(oversized_without_fault);
        if (oversized_without_fault) stream.Cancel();
        EXPECT_EQ(memory::detail::test_buffers_live, baseline);
    });
}

TEST(QuicUdpQueue, EmptyMessagesConsumeBufferAdmissionAndRemainReadable) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        const auto baseline = memory::detail::test_buffers_live;
        const TargetAddress target("127.0.0.1", 12345);
        UdpSessionStream stream(io, 10, target, {});
        constexpr size_t limit = UdpSessionStream::kMaxQueuedBytes / buf::Buffer::kSize;
        size_t admitted = 0;
        for (size_t index = 0; index <= limit; ++index)
            admitted += stream.Push(target, {});
        Require(admitted == limit, "empty UDP messages did not consume buffer admission");
        EXPECT_EQ(memory::detail::test_buffers_live, baseline + limit);
        const auto rejected = memory::rejected_pmr_allocations;
        memory::reject_next_pmr_allocation = true;
        const bool overflow = stream.Push(target, {});
        memory::reject_next_pmr_allocation = false;
        EXPECT_FALSE(overflow);
        EXPECT_EQ(memory::rejected_pmr_allocations, rejected);

        auto packet = co_await stream.ReadMultiBuffer();
        {
            const auto datagram = buf::InspectUdpDatagram(packet);
            Require(datagram.Valid() && datagram.target, "empty UDP message became EOF");
            EXPECT_EQ(datagram.payload_size, 0);
            EXPECT_EQ(datagram.buffer_count, 1);
            EXPECT_TRUE(datagram.target->SameEndpoint(target));
        }
        const uint8_t later = 0x7a;
        Require(stream.Push(target, {&later, 1}), "empty UDP read did not return admission");
        stream.Cancel();
        EXPECT_EQ(memory::detail::test_buffers_live, baseline + 1);
        EXPECT_EQ(buf::InspectUdpDatagram(packet).status, buf::UdpDatagramStatus::Valid);
        packet.clear();
        EXPECT_EQ(memory::detail::test_buffers_live, baseline);
    });
}

struct StreamCancellation final : transport::CancellationSubscription {
    bool notified = false;
    ErrorCode reason = ErrorCode::OK;
    bool terminal = false;

    void OnCancellation(transport::Cancellation cancellation) noexcept override {
        notified = true;
        reason = cancellation.reason;
        terminal = cancellation.terminal;
    }
};

TEST(QuicStreamClose, CompletedDuplexLeavesTransportAliveUntilNativeRetirement) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        auto state = memory::AllocateShared<QuicStreamState>(
            io, 4, std::weak_ptr<transport::internet::hysteria::Connection>{});
        StreamCancellation cancellation;
        cancellation.Resubscribe(state->Cancellation());
        {
            transport::internet::hysteria::QuicStream stream(state);
            const std::array<uint8_t, 3> input{0x12, 0x34, 0x56};
            Require(state->PushInput(input, true), "input FIN was not admitted");
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
        auto state = memory::AllocateShared<QuicStreamState>(
            io, 8, std::weak_ptr<transport::internet::hysteria::Connection>{});
        transport::internet::hysteria::QuicStream stream(state);
        StreamCancellation cancellation;
        cancellation.Resubscribe(stream.Cancellation());
        const std::array<uint8_t, 3> input{0x21, 0x43, 0x65};
        Require(state->PushInput(input, true), "input FIN was not admitted");
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
        EXPECT_EQ(cancellation.reason, ErrorCode::CANCELLED);
        try {
            (void)co_await state->ReadMultiBuffer();
            throw std::runtime_error("aborted input tail became graceful EOF");
        } catch (const transport::LinkError& error) {
            EXPECT_EQ(error.code(), ErrorCode::CANCELLED);
        }
    });
}

class QuicStreamHalfClose : public testing::TestWithParam<bool> {};

TEST_P(QuicStreamHalfClose, CloseAbortsIncompleteDuplex) {
    const bool remote_fin = GetParam();
    RunInDomain([remote_fin](net::io_context& io) -> net::awaitable<void> {
        auto state = memory::AllocateShared<QuicStreamState>(
            io, 12, std::weak_ptr<transport::internet::hysteria::Connection>{});
        transport::internet::hysteria::QuicStream stream(state);
        StreamCancellation cancellation;
        cancellation.Resubscribe(stream.Cancellation());
        if (remote_fin) {
            Require(state->PushInput({}, true), "input FIN was not admitted");
            EXPECT_TRUE((co_await stream.ReadMultiBuffer()).empty());
        } else {
            stream.ShutdownWrite();
        }
        stream.Close();
        EXPECT_FALSE(stream.IsOpen());
        EXPECT_FALSE(state->Open());
        EXPECT_TRUE(cancellation.notified);
        EXPECT_TRUE(cancellation.terminal);
        EXPECT_EQ(cancellation.reason, ErrorCode::CANCELLED);
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
        auto state = memory::AllocateShared<QuicStreamState>(
            io, 16, std::weak_ptr<transport::internet::hysteria::Connection>{});
        transport::internet::hysteria::QuicStream stream(state);
        StreamCancellation cancellation;
        cancellation.Resubscribe(stream.Cancellation());
        Require(state->PushInput({}, true), "input FIN was not admitted");
        EXPECT_TRUE((co_await stream.ReadMultiBuffer()).empty());
        stream.ShutdownWrite();
        if (abortive_close) stream.CloseAbortive();
        else stream.Cancel();
        stream.Close();
        EXPECT_FALSE(state->Open());
        EXPECT_TRUE(cancellation.notified);
        EXPECT_TRUE(cancellation.terminal);
        EXPECT_EQ(cancellation.reason, ErrorCode::CANCELLED);
        try {
            (void)co_await state->ReadMultiBuffer();
            throw std::runtime_error("explicit cancellation became graceful EOF");
        } catch (const transport::LinkError& error) {
            EXPECT_EQ(error.code(), ErrorCode::CANCELLED);
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
        SignalChannel joined(executor, 2);
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
            Require(started == (round + 1) * 2, "output waiters did not start");
            Require(completed == round * 2, "output wait retained stale readiness");
            state.NotifyWritable();
            co_await joined.async_receive(net::use_awaitable);
            co_await joined.async_receive(net::use_awaitable);
            if (failure) std::rethrow_exception(failure);
            Require(completed == (round + 1) * 2, "output event did not broadcast");
        }
    });
}

enum class WriteWaitEnd { ShutdownWrite, Cancel, Reset, StreamClose, HostClose };
class QuicStreamWriteWaitEnd : public testing::TestWithParam<WriteWaitEnd> {};

TEST_P(QuicStreamWriteWaitEnd, SettlesPendingAndSubsequentWaits) {
    const auto ending = GetParam();
    RunInDomain([ending](net::io_context& io) -> net::awaitable<void> {
        auto state = memory::AllocateShared<QuicStreamState>(
            io, 8, std::weak_ptr<transport::internet::hysteria::Connection>{});
        transport::internet::hysteria::QuicStream stream(state);
        const std::array<uint8_t, 3> tail{0x21, 0x43, 0x65};
        Require(state->PushInput(tail, false), "input tail was not admitted");
        const auto executor = co_await net::this_coro::executor;
        SignalChannel joined(executor, 1);
        bool started = false;
        bool completed = false;
        std::exception_ptr failure;
        const bool cancelled = ending == WriteWaitEnd::Cancel ||
            ending == WriteWaitEnd::Reset || ending == WriteWaitEnd::HostClose;
        auto expect_closed = [&]() -> net::awaitable<void> {
            try {
                co_await state->WaitWritable();
                throw std::runtime_error("ended output wait succeeded");
            } catch (const transport::WriteClosed&) {
                Require(!cancelled, "cancelled stream reported graceful write closure");
            } catch (const transport::LinkError& error) {
                Require(cancelled && error.code() == ErrorCode::CANCELLED,
                        "output wait lost its cancellation reason");
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
        Require(started && !completed, "write did not suspend before termination");
        switch (ending) {
        case WriteWaitEnd::ShutdownWrite: state->ShutdownWrite(); break;
        case WriteWaitEnd::Cancel: state->Cancel(); break;
        case WriteWaitEnd::Reset: state->RemoteReset(); break;
        case WriteWaitEnd::StreamClose: state->OnStreamClosed(); break;
        case WriteWaitEnd::HostClose: stream.Close(); break;
        }
        co_await joined.async_receive(net::use_awaitable);
        if (failure) std::rethrow_exception(failure);
        Require(completed, "ended stream left a writer suspended");
        co_await expect_closed();
        if (!cancelled) {
            Require(state->Open(), "write closure cancelled the readable stream");
            auto input = co_await state->ReadMultiBuffer();
            Require(input.byte_size() == tail.size(), "write closure discarded unread input");
            EXPECT_TRUE(std::equal(tail.begin(), tail.end(), (*input.begin())->Bytes().begin()));
            if (ending == WriteWaitEnd::ShutdownWrite)
                Require(state->PushInput({}, true), "write shutdown rejected remote FIN");
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
        SignalChannel joined(executor, 1);
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
        Require(started && !completed, "writer did not wait for credit");
        Require(state.PushInput({}, true), "remote FIN was not admitted");
        EXPECT_EQ((co_await state.ReadMultiBuffer()).byte_size(), 0);
        co_await net::post(executor, net::use_awaitable);
        Require(!completed, "remote FIN spuriously supplied output credit");
        state.CheckWriteOpen();
        state.NotifyWritable();
        co_await joined.async_receive(net::use_awaitable);
        if (failure) std::rethrow_exception(failure);
        Require(completed, "remote FIN prevented ACK wakeup");
    });
}

TEST(QuicStreamWriteWait, CoroutineCancellationDoesNotBecomeAnAck) {
    RunInDomain([](net::io_context& io) -> net::awaitable<void> {
        QuicStreamState state(io, 16, {});
        const auto executor = co_await net::this_coro::executor;
        SignalChannel joined(executor, 1);
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
        Require(started, "writer did not begin its cancellation-aware wait");
        cancellation.emit(net::cancellation_type::terminal);
        co_await joined.async_receive(net::use_awaitable);
        Require(failure != nullptr, "coroutine cancellation was mistaken for credit");
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
