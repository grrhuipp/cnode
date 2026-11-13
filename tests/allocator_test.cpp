#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "common/multi_buffer.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <thread>
#include <vector>

namespace {
using namespace ::common;

bool Intact(void* p, size_t bytes, uint8_t pattern) {
    const auto* data = static_cast<const uint8_t*>(p);
    for (size_t i = 0; i < bytes; ++i) if (data[i] != pattern) return false;
    return true;
}

TEST(Allocator, BufferReusePreservesOtherLivePayloads) {
    const auto live_before = test_buffers_live;
    {
        std::array<::common::BufferGuard, 64> buffers;
        for (auto& buffer : buffers) {
            buffer.reset(::common::Buffer::New());
            ASSERT_TRUE(buffer);
            std::memset(buffer->data, 0x5a, ::common::Buffer::kSize);
            buffer->Produce(1);
        }
        buffers.back().reset();
        buffers.back().reset(::common::Buffer::New());
        ASSERT_TRUE(buffers.back());
        for (size_t i = 0; i + 1 < buffers.size(); ++i)
            EXPECT_TRUE(Intact(buffers[i]->data, ::common::Buffer::kSize, 0x5a));
    }
    EXPECT_EQ(test_buffers_live, live_before);
}

struct NestedDequeEntry {
    int value;
    common::RingDeque<NestedDequeEntry> children;

    explicit NestedDequeEntry(int v) : value(v) {}
    NestedDequeEntry(NestedDequeEntry&&) noexcept = default;
    NestedDequeEntry(const NestedDequeEntry&) = delete;
};

struct MoveEntry {
    std::vector<int> payload;

    explicit MoveEntry(int value) { payload.push_back(value); }
    MoveEntry(MoveEntry&&) noexcept = default;
    MoveEntry(const MoveEntry&) = delete;
};

TEST(Allocator, NestedDequeMovePreservesDescendants) {
    common::RingDeque<NestedDequeEntry> queue;
    for (int value = 1; value <= 4; ++value)
        queue.emplace_back(value);
    queue.pop_front();
    queue.pop_front();
    queue.emplace_back(5);
    queue.emplace_back(6);
    auto& children = queue.back().children;
    children.emplace_back(71);
    children.emplace_back(72);
    children.front().children.emplace_back(911);
    children.front().children.emplace_back(922);

    queue = std::move(children);
    ASSERT_EQ(queue.size(), 2u);
    EXPECT_EQ(queue.front().value, 71);
    EXPECT_EQ(queue.back().value, 72);
    ASSERT_EQ(queue.front().children.size(), 2u);
    EXPECT_EQ(queue.front().children.front().value, 911);
    EXPECT_EQ(queue.front().children.back().value, 922);

    queue = std::move(queue.front().children);
    ASSERT_EQ(queue.size(), 2u);
    EXPECT_EQ(queue.front().value, 911);
    EXPECT_EQ(queue.back().value, 922);
    queue.clear();
    EXPECT_EQ(queue.capacity(), 0u);
}

TEST(Allocator, DequeGrowthPreservesPayloadsAcrossAllocationFailures) {
    for (std::ptrdiff_t allowance = 0; allowance <= 3; ++allowance) {
        SCOPED_TRACE(allowance);
        common::RingDeque<MoveEntry> queue;
        for (int value = 0; value < 4; ++value) queue.emplace_back(value);
        while (queue.size() < queue.capacity())
            queue.emplace_back(static_cast<int>(queue.size()));
        const auto retained = queue.size();
        bool appended = false;
        process_allocation_budget = allowance;
        try {
            queue.emplace_back(static_cast<int>(retained));
            appended = true;
        } catch (const std::bad_alloc&) {}
        process_allocation_budget = -1;
        ASSERT_EQ(queue.size(), retained + static_cast<std::size_t>(appended));
        for (std::size_t index = 0; index < queue.size(); ++index) {
            ASSERT_EQ(queue[index].payload.size(), 1u) << "index=" << index;
            EXPECT_EQ(queue[index].payload.front(), static_cast<int>(index));
        }
    }
}

TEST(Allocator, DequeShrinkPreservesPayloadsAndReclaimsStorage) {
    common::RingDeque<MoveEntry> queue;
    for (int value = 0; value < 64; ++value) queue.emplace_back(value);
    for (int index = 0; index < 7; ++index) queue.pop_front();
    for (int value = 64; value < 71; ++value) queue.emplace_back(value);
    for (int index = 0; index < 48; ++index) queue.pop_front();
    const auto cap_before = queue.capacity();
    queue.shrink_to_fit();
    EXPECT_LE(queue.capacity(), cap_before);
    ASSERT_EQ(queue.size(), 16u);
    for (std::size_t index = 0; index < queue.size(); ++index) {
        const auto& payload = queue[index].payload;
        ASSERT_EQ(payload.size(), 1u);
        EXPECT_EQ(payload.front(), static_cast<int>(55 + index));
    }
    queue.clear();
    EXPECT_EQ(queue.capacity(), 0u);
}

TEST(Allocator, ProcessAllocationSupportsAlignmentAcrossSizeBoundaries) {
    for (size_t bytes : {0u, 1u, 24u, 31u, 128u, 2048u, 4000u, 8192u, 17408u, 32768u, 65536u}) {
        for (size_t alignment = 1; alignment <= 65536; alignment *= 2) {
            void* block = AllocateProcessRaw(bytes, alignment);
            const bool aligned = reinterpret_cast<uintptr_t>(block) % alignment == 0;
            std::memset(block, 0x6b, bytes);
            const bool intact = Intact(block, bytes, 0x6b);
            mi_free(block);
            ASSERT_TRUE(aligned && intact);
        }
    }
}

TEST(Allocator, ProcessAllocationPreservesMixedLivePayloadsDuringReuse) {
    struct Slot {
        void* block = nullptr;
        size_t bytes = 0, alignment = 0;
        uint8_t pattern = 0;
    };
    std::array<Slot, 256> slots{};
    bool intact = true;
    uint32_t state = 0xb35dff21u;
    const auto next = [&] {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        return state;
    };
    for (int step = 0; step < 100000; ++step) {
        auto& slot = slots[next() % slots.size()];
        if (slot.block) {
            intact &= Intact(slot.block, slot.bytes, slot.pattern);
            mi_free(slot.block);
            slot.block = nullptr;
        } else {
            slot.bytes = 8 + next() % (step % 5 ? 2000 : 34000);
            slot.alignment = size_t{1} << (3 + next() % 8);
            slot.pattern = static_cast<uint8_t>(next());
            slot.block = AllocateProcessRaw(slot.bytes, slot.alignment);
            intact &= reinterpret_cast<uintptr_t>(slot.block) % slot.alignment == 0;
            std::memset(slot.block, slot.pattern, slot.bytes);
        }
        if (step % 97 == 0)
            for (const auto& held : slots)
                if (held.block) intact &= Intact(held.block, held.bytes, held.pattern);
    }
    for (const auto& slot : slots) {
        if (!slot.block) continue;
        intact &= Intact(slot.block, slot.bytes, slot.pattern);
        mi_free(slot.block);
    }
    EXPECT_TRUE(intact);
}

TEST(Allocator, ProcessAllocationCanRetireRawStorageOnAnotherThread) {
    void* block = AllocateProcessRaw(17408, 4096);
    std::memset(block, 0xa5, 17408);
    bool intact = false;
    std::thread retire([&] {
        intact = Intact(block, 17408, 0xa5);
        mi_free(block);
    });
    retire.join();
    EXPECT_TRUE(intact);
}

TEST(Allocator, BufferAllocationFailureReturnsNullWithoutLeaking) {
    const auto live_before = test_buffers_live;
    reject_next_process_allocation = true;
    auto* block = ::common::Buffer::New();
    reject_next_process_allocation = false;
    if (block) ::common::Buffer::Free(block);
    EXPECT_EQ(block, nullptr);
    EXPECT_EQ(test_buffers_live, live_before);
}

TEST(Allocator, IdleDequeReleasesStorageOnDrain) {
    RingDeque<int> queue;
    for (int value = 0; value < 16; ++value) queue.push_back(value);
    for (int value = 0; value < 16; ++value) {
        EXPECT_EQ(queue.front(), value);
        queue.pop_front();
    }
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(queue.capacity(), 0u);
}
}  // namespace
