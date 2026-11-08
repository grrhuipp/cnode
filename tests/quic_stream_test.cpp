#include <gtest/gtest.h>

#include "quic_stream.hpp"
#include "common/memory_stats.hpp"

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

INSTANTIATE_TEST_SUITE_P(HostLifetime, QuicUdpCancellation, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "DestroyInCallback" : "KeepHost";
    });
} // namespace
