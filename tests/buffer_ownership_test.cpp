#include <gtest/gtest.h>

#include "common/initial_payload.hpp"
#include "common/length_prefixed_packet_buffer.hpp"
#include <array>
#include <limits>
#include <type_traits>
#include <vector>

namespace {
thread_local size_t failures = 0;

static_assert(alignof(common::Buffer) <= alignof(std::max_align_t));
static_assert(sizeof(common::MultiBuffer) == sizeof(common::Buffer*));

common::BufferGuard Buffer(size_t bytes, uint8_t value) {
    common::BufferGuard buffer{common::Buffer::New(bytes)};
    if (!buffer) throw std::bad_alloc();
    std::memset(buffer->Tail().data(), value, bytes);
    buffer->Produce(bytes);
    return buffer;
}

common::BufferGuard Buffer(size_t bytes) {
    return Buffer(bytes, 0x42);
}

std::vector<uint8_t> Flatten(const common::MultiBuffer& payload) {
    const auto bytes = payload.FrontSpan();
    return std::vector<uint8_t>(bytes.begin(), bytes.end());
}

bool Consistent(const common::MultiBuffer& payload) {
    size_t bytes = 0;
    for (const auto* buffer : payload) {
        if (buffer) bytes += buffer->Len();
    }
    return payload.byte_size() == bytes && payload.empty() == (payload.size() == 0);
}

std::vector<uint8_t> Pattern(size_t bytes) {
    std::vector<uint8_t> result(bytes);
    for (size_t i = 0; i < bytes; ++i) result[i] = static_cast<uint8_t>((i * 31 + i / 7) % 251);
    return result;
}

common::MultiBuffer Packet(std::span<const uint8_t> data) {
    common::MultiBuffer result;
    if (!result.AppendSpan(data)) throw std::bad_alloc();
    return result;
}

template <typename Function>
bool Inject(int budget, Function operation) {
    const auto rejected_before = common::rejected_process_allocations;
    struct ResetBudget {
        ~ResetBudget() { common::process_allocation_budget = -1; }
    } reset;
    common::process_allocation_budget = budget;
    bool success = false;
    try { success = operation(); }
    catch (const std::bad_alloc&) {}
    failures = common::rejected_process_allocations - rejected_before;
    return success;
}

template <typename Function>
void FaultMatrix(const char* name, Function operation) {
    bool reached_success = false;
    bool reached_failure = false;
    for (int budget = 0; budget < 48; ++budget) {
        SCOPED_TRACE(name);
        SCOPED_TRACE(budget);
        const auto live_before = common::test_buffers_live;
        EXPECT_TRUE(operation(budget, reached_success));
        reached_failure = reached_failure || failures != 0;
        EXPECT_EQ(common::test_buffers_live, live_before);
        if (reached_success) break;
    }
    EXPECT_TRUE(reached_success);
    EXPECT_TRUE(reached_failure);
}

TEST(BufferOwnership, SpanAppendRollsBackEveryAllocationFailureAndCanRetry) {
    FaultMatrix("span append rolls back data allocation failures", [](int budget, bool& complete) {
        const auto before = Pattern(33);
        const auto added = Pattern(90000);
        auto payload = Packet(before);
        auto* original = *payload.begin();
        complete = Inject(budget, [&] { return payload.AppendSpan(added); });
        const bool unchanged = complete || (failures != 0 && Flatten(payload) == before &&
            Consistent(payload) && payload.size() == 1 && *payload.begin() == original);
        if (!complete && !payload.AppendSpan(added)) return false;
        auto expected = before;
        expected.insert(expected.end(), added.begin(), added.end());
        return unchanged && Flatten(payload) == expected && Consistent(payload);
    });
}

TEST(BufferOwnership, ConsumedGuardIsReleasedWhenGrowthAllocationFails) {
    FaultMatrix("consumed guard is released when growth fails", [](int budget, bool& complete) {
        common::MultiBuffer payload{Buffer(common::Buffer::kSize, 0x22)};
        auto before = Flatten(payload);
        auto extra = Buffer(5, 0x11);
        complete = Inject(budget, [&] { payload.push_back(std::move(extra)); return true; });
        if (extra) return false;
        if (!complete) return failures != 0 && Flatten(payload) == before && Consistent(payload);
        before.insert(before.end(), 5, 0x11);
        return Flatten(payload) == before && Consistent(payload);
    });
}

class BufferTransferFailure : public ::testing::TestWithParam<bool> {};

TEST_P(BufferTransferFailure, PreservesBothContainersAndUdpMetadataOnFailure) {
    const bool prefix = GetParam();
    FaultMatrix(prefix ? "prefix split" : "whole transfer",
            [prefix](int budget, bool& complete) {
                const auto source_bytes = Pattern(common::Buffer::kSize + 100);
                const auto target_bytes = Pattern(common::Buffer::kSize * 2);
                auto source = Packet(source_bytes);
                auto target = Packet(target_bytes);
                auto* original = *source.begin();
                const common::TargetAddress endpoint{"127.0.0.1", 1234};
                original->SetUDP(endpoint);
                const size_t bytes = prefix ? common::Buffer::kSize + 17 : source_bytes.size();
                const auto operation = [&] {
                    if (prefix) return source.MovePrefixTo(target, bytes);
                    source.MoveTo(target, true);
                    return true;
                };
                complete = Inject(budget, operation);
                const bool unchanged = complete || (failures != 0 &&
                    Flatten(source) == source_bytes && Flatten(target) == target_bytes &&
                    Consistent(source) && Consistent(target) && *source.begin() == original &&
                    original->HasUDP() && original->UDP().SameEndpoint(endpoint));
                if (!complete && !operation()) return false;
                auto expected = target_bytes;
                expected.insert(expected.end(), source_bytes.begin(), source_bytes.begin() + bytes);
                return unchanged && Flatten(target) == expected &&
                    Flatten(source) == std::vector<uint8_t>(source_bytes.begin() + bytes, source_bytes.end()) &&
                    Consistent(source) && Consistent(target);
            });
}

INSTANTIATE_TEST_SUITE_P(WholeAndPrefix, BufferTransferFailure, ::testing::Bool());

TEST(BufferOwnership, UdpPrefixAllocationFailureRollsBackBothContainersAndCanRetry) {
    const auto source_bytes = Pattern(91);
    constexpr size_t prefix_bytes = 23;
    FaultMatrix("UDP prefix buffer failure rolls back both containers",
        [&](int budget, bool& complete) {
            const common::TargetAddress long_target{
                "split-copy-target-host-name-longer-than-sso.example.com", 14321};
            auto source = Packet(source_bytes);
            auto* original = *source.begin();
            original->SetUDP(long_target);
            common::MultiBuffer destination;

            complete = Inject(budget, [&] {
                return source.MovePrefixTo(destination, prefix_bytes);
            });
            const bool rolled_back = complete || (failures != 0 &&
                source.size() == 1 && *source.begin() == original &&
                Flatten(source) == source_bytes && source.byte_size() == source_bytes.size() &&
                original->HasUDP() && original->UDP().SameEndpoint(long_target) &&
                destination.empty() && destination.byte_size() == 0 &&
                Consistent(source) && Consistent(destination));
            const bool retried = complete || source.MovePrefixTo(destination, prefix_bytes);
            const bool metadata = retried && source.size() == 1 && original->HasUDP() &&
                original->UDP().SameEndpoint(long_target) && destination.size() == 1 &&
                destination.back()->HasUDP() &&
                destination.back()->UDP().SameEndpoint(long_target) &&
                destination.back()->Len() == prefix_bytes;
            const bool bytes = source.byte_size() == source_bytes.size() - prefix_bytes &&
                destination.byte_size() == prefix_bytes &&
                Consistent(source) && Consistent(destination);
            return rolled_back && metadata && bytes;
        });
}

TEST(BufferOwnership, InitialPayloadTransfersOwnedBlocksWhenAllocationIsUnavailable) {
    auto owned_bytes = Pattern(9000);
    auto owned = Packet(owned_bytes);
    const auto* original_buffer = *owned.begin();
    common::MultiBuffer transferred;
    EXPECT_TRUE(Inject(0, [&] {
        common::InitialPayload from_stream{std::move(owned)};
        transferred = std::move(from_stream).MoveToMultiBuffer();
        return from_stream.empty();
    }) && owned.empty() && *transferred.begin() == original_buffer &&
          Flatten(transferred) == owned_bytes);
}

TEST(BufferOwnership, ShortPrefixTransferLeavesBothPayloadsUnchanged) {
    auto bytes = Pattern(100);
    auto partial = Packet(bytes);
    auto into = Packet(bytes);
    const auto before = Flatten(into);
    EXPECT_TRUE(!partial.MovePrefixTo(into, 101) && Flatten(partial) == bytes && Flatten(into) == before);
}

TEST(BufferOwnership, PrefixTransferRejectsSelfAndAcceptsEmptyPrefix) {
    auto bytes = Pattern(100);
    auto partial = Packet(bytes);
    auto into = Packet(bytes);
    EXPECT_TRUE(!partial.MovePrefixTo(partial, 1) && partial.MovePrefixTo(into, 0));
    EXPECT_EQ(Flatten(partial), bytes);
    EXPECT_EQ(Flatten(into), bytes);
}

TEST(BufferOwnership, PrefixCoalescingReusesConsumedDestinationTail) {
    auto partial = Packet(Pattern(100));
    common::MultiBuffer into{Buffer(common::Buffer::kSize)};
    into.DropPrefixBytes(100);
    EXPECT_TRUE(Inject(0, [&] { return partial.MovePrefixTo(into, 77); }) &&
          partial.byte_size() == 23 && into.byte_size() == common::Buffer::kSize - 23 &&
          Consistent(partial) && Consistent(into));
}

TEST(BufferOwnership, MovedContainersRemainReusable) {
    const auto live_before = common::test_buffers_live;
    for (const size_t source_count : {0u, 1u, 8u, 16u}) {
        for (const size_t destination_count : {0u, 1u, 9u}) {
            SCOPED_TRACE(source_count);
            SCOPED_TRACE(destination_count);
            auto expected = Pattern(source_count);
            common::MultiBuffer source = Packet(expected);
            if (source_count > 1) {
                source.DropPrefixBytes(1);
                expected.erase(expected.begin());
            }
            common::MultiBuffer transferred(std::move(source));
            EXPECT_TRUE(source.empty());
            EXPECT_EQ(source.byte_size(), 0u);
            for (size_t i = 0; i < 9; ++i) source.push_back(Buffer(1, 0xa5));

            common::MultiBuffer destination;
            for (size_t i = 0; i < destination_count; ++i)
                destination.push_back(Buffer(1, 0xff));
            destination = std::move(transferred);
            EXPECT_TRUE(transferred.empty());
            EXPECT_EQ(transferred.byte_size(), 0u);
            EXPECT_EQ(Flatten(destination), expected);
            EXPECT_TRUE(Consistent(destination));
            EXPECT_EQ(Flatten(source), std::vector<uint8_t>(9, 0xa5));

            transferred.push_back(Buffer(1, 0x73));
            EXPECT_EQ(Flatten(transferred), std::vector<uint8_t>{0x73});
            source.clear();
            destination.clear();
            transferred.clear();
            EXPECT_EQ(common::test_buffers_live, live_before);
        }
    }
}

TEST(BufferOwnership, EmptyUdpMessageSurvivesTransfersAndChecksEveryTarget) {
    common::MultiBuffer stream_empty;
    stream_empty.push_back(Buffer(0));
    stream_empty.ReleaseIfIdle();
    EXPECT_TRUE(stream_empty.empty());

    const common::TargetAddress first_target{"127.0.0.1", 1234};
    const common::TargetAddress second_target{"127.0.0.1", 4321};
    common::MultiBuffer packet;
    ASSERT_TRUE(common::SetUdpTarget(packet, first_target));
    const auto* original = *packet.begin();
    common::InitialPayload initial(std::move(packet));
    EXPECT_FALSE(initial.empty());
    auto moved = std::move(initial).MoveToMultiBuffer();
    moved.ReleaseIfIdle();
    EXPECT_TRUE(initial.empty());
    {
        const auto info = common::InspectUdpDatagram(moved);
        ASSERT_TRUE(info.Valid());
        EXPECT_EQ(info.payload_size, 0u);
        EXPECT_TRUE(info.target->SameEndpoint(first_target));
    }
    common::MultiBuffer destination;
    moved.MoveTo(destination);
    ASSERT_EQ(destination.size(), 1u);
    EXPECT_EQ(*destination.begin(), original);
    EXPECT_TRUE(moved.empty());

    common::MultiBuffer later;
    later.push_back(Buffer(1));
    ASSERT_TRUE(common::SetUdpTarget(later, second_target));
    destination.AppendAndCoalesce(std::move(later));
    EXPECT_EQ(destination.byte_size(), 1u);
    EXPECT_EQ(common::InspectUdpDatagram(destination).status, common::UdpDatagramStatus::MixedTarget);
}

TEST(BufferOwnership, UnrepresentableWriteCapacityReturnsFailureAndAllowsReuse) {
    const auto live_before = common::test_buffers_live;
    for (const size_t initial_size : {size_t{32}, size_t{common::Buffer::kSize + 1}}) {
        SCOPED_TRACE(initial_size);
        {
            common::ContiguousWriteBuffer storage;
            (void)storage.Prepare(initial_size);
            EXPECT_EQ(storage.TryPrepare(std::numeric_limits<size_t>::max()), nullptr);
            EXPECT_TRUE(storage.Empty());
            EXPECT_EQ(storage.Data(), nullptr);
            EXPECT_EQ(common::test_buffers_live, live_before);
            const auto expected = Pattern(
                initial_size <= common::Buffer::kSize ? common::Buffer::kSize + 1 : 33);
            auto* data = storage.TryPrepare(expected.size());
            ASSERT_NE(data, nullptr);
            std::memcpy(data, expected.data(), expected.size());
            common::MultiBuffer output;
            ASSERT_TRUE(storage.TryAppendTo(expected.size(), output));
            EXPECT_EQ(Flatten(output), expected);
            EXPECT_TRUE(Consistent(output));
            EXPECT_TRUE(storage.Empty());
            EXPECT_EQ(storage.Data(), nullptr);
        }
        EXPECT_EQ(common::test_buffers_live, live_before);
    }
}

TEST(BufferOwnership, TruncatedPacketStreamCannotResumeAfterEof) {
    const std::array<uint8_t, 5> wire{0, 3, 0x11, 0x22, 0x33};
    for (size_t cut = 1; cut < wire.size(); ++cut) {
        SCOPED_TRACE(cut);
        common::LengthPrefixedPacketBuffer stream;
        ASSERT_TRUE(stream.Append(Packet(std::span(wire).first(cut))));
        common::MultiBuffer output;
        ASSERT_EQ(stream.Pop(output), common::LengthPrefixedPacketBuffer::PopResult::NeedMore);
        EXPECT_FALSE(stream.Finish());
        EXPECT_EQ(stream.PendingBytes(), 0u);
        EXPECT_FALSE(stream.Append(Packet(std::span(wire).subspan(cut))));
        EXPECT_EQ(stream.Pop(output), common::LengthPrefixedPacketBuffer::PopResult::Invalid);
        EXPECT_TRUE(output.empty());
        EXPECT_FALSE(stream.Finish());
        stream.Reset();
        ASSERT_TRUE(stream.Append(Packet(wire)));
        ASSERT_EQ(stream.Pop(output), common::LengthPrefixedPacketBuffer::PopResult::Packet);
        EXPECT_EQ(Flatten(output), std::vector<uint8_t>({0x11, 0x22, 0x33}));
        EXPECT_TRUE(stream.Finish());
    }
}

TEST(BufferOwnership, CleanPacketStreamEofRequiresExplicitResetBeforeReuse) {
    const std::array<uint8_t, 3> wire{0, 1, 0x73};
    common::LengthPrefixedPacketBuffer stream;
    ASSERT_TRUE(stream.Append(Packet(wire)));
    common::MultiBuffer output;
    ASSERT_EQ(stream.Pop(output), common::LengthPrefixedPacketBuffer::PopResult::Packet);
    EXPECT_EQ(Flatten(output), std::vector<uint8_t>({0x73}));
    EXPECT_TRUE(stream.Finish());
    EXPECT_TRUE(stream.Finish());
    EXPECT_FALSE(stream.Append({}));
    EXPECT_FALSE(stream.Append(Packet(wire)));
    EXPECT_EQ(stream.Pop(output), common::LengthPrefixedPacketBuffer::PopResult::Finished);
    EXPECT_TRUE(output.empty());
    stream.Reset();
    ASSERT_TRUE(stream.Append(Packet(wire)));
    ASSERT_EQ(stream.Pop(output), common::LengthPrefixedPacketBuffer::PopResult::Packet);
    EXPECT_EQ(Flatten(output), std::vector<uint8_t>({0x73}));
    EXPECT_TRUE(stream.Finish());
}

}  // namespace
