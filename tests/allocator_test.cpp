#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <thread>
#include <vector>

namespace {
using namespace ::memory;

bool Intact(void* p, size_t bytes, uint8_t pattern) {
    const auto* data = static_cast<const uint8_t*>(p);
    for (size_t i = 0; i < bytes; ++i) if (data[i] != pattern) return false;
    return true;
}


TEST(Allocator, BufferReusePreservesOtherLivePayloads) {
    const auto live_before = detail::test_buffers_live;
    {
        std::array<::buf::BufferGuard, 64> buffers;
        for (auto& buffer : buffers) {
            buffer.reset(::buf::Buffer::New());
            ASSERT_TRUE(buffer);
            std::memset(buffer->data, 0x5a, ::buf::Buffer::kSize);
            buffer->Produce(1);
        }
        buffers.back().reset();
        buffers.back().reset(::buf::Buffer::New());
        ASSERT_TRUE(buffers.back());
        for (size_t i = 0; i + 1 < buffers.size(); ++i)
            EXPECT_TRUE(Intact(buffers[i]->data, ::buf::Buffer::kSize, 0x5a));
    }
    EXPECT_EQ(detail::test_buffers_live, live_before);
}


class CountingResource final : public std::pmr::memory_resource {
public:
    std::size_t live = 0;
    std::size_t live_bytes = 0;

    void LimitAllocations(std::size_t count) noexcept { remaining_ = count; }
    void AllowAllocations() noexcept { remaining_ = std::numeric_limits<std::size_t>::max(); }

private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
        if (remaining_ != std::numeric_limits<std::size_t>::max()) {
            if (remaining_ == 0) throw std::bad_alloc();
            --remaining_;
        }
        void* block = process_resource()->allocate(bytes, alignment);
        ++live;
        live_bytes += bytes;
        return block;
    }
    void do_deallocate(void* block, std::size_t bytes, std::size_t alignment) override {
        process_resource()->deallocate(block, bytes, alignment);
        --live;
        live_bytes -= bytes;
    }
    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
    std::size_t remaining_ = std::numeric_limits<std::size_t>::max();
};

struct NestedDequeEntry {
    int value;
    memory::RingDeque<NestedDequeEntry> children;

    NestedDequeEntry(int value, std::pmr::memory_resource* resource)
        : value(value), children(resource) {}
    NestedDequeEntry(NestedDequeEntry&&) noexcept = default;
    NestedDequeEntry(const NestedDequeEntry&) = delete;
};

struct AllocatorAwareEntry {
    using allocator_type = std::pmr::polymorphic_allocator<std::byte>;
    std::pmr::vector<int> payload;

    AllocatorAwareEntry(std::allocator_arg_t, allocator_type allocator, int value)
        : payload(allocator.resource()) { payload.push_back(value); }
    AllocatorAwareEntry(AllocatorAwareEntry&&) noexcept = default;
    AllocatorAwareEntry(const AllocatorAwareEntry&) = delete;
    // 指定分配器的构造可以重建载荷，不能用普通移动的 noexcept 推断它不会失败。
    AllocatorAwareEntry(std::allocator_arg_t, allocator_type allocator, AllocatorAwareEntry&& other)
        : payload(other.payload, std::pmr::polymorphic_allocator<int>(allocator.resource())) {
        other.payload.clear();
    }
};


TEST(Allocator, NestedDequeMovePreservesDescendantsAndResourceOwnership) {
    CountingResource outer_resource;
    CountingResource child_resource;
    memory::RingDeque<NestedDequeEntry> queue(&outer_resource);
    for (int value = 1; value <= 4; ++value)
        queue.emplace_back(value, &child_resource);
    queue.pop_front();
    queue.pop_front();
    queue.emplace_back(5, &child_resource);
    queue.emplace_back(6, &child_resource);
    auto& children = queue.back().children;
    children.emplace_back(71, &outer_resource);
    children.emplace_back(72, &child_resource);
    children.front().children.emplace_back(911, &outer_resource);
    children.front().children.emplace_back(922, &outer_resource);

    queue = std::move(children);
    ASSERT_EQ(queue.size(), 2u);
    EXPECT_EQ(queue.front().value, 71);
    EXPECT_EQ(queue.back().value, 72);
    EXPECT_EQ(queue.get_allocator().resource(), &child_resource);
    ASSERT_EQ(queue.front().children.size(), 2u);
    EXPECT_EQ(queue.front().children.front().value, 911);
    EXPECT_EQ(queue.front().children.back().value, 922);

    queue = std::move(queue.front().children);
    ASSERT_EQ(queue.size(), 2u);
    EXPECT_EQ(queue.front().value, 911);
    EXPECT_EQ(queue.back().value, 922);
    EXPECT_EQ(queue.get_allocator().resource(), &outer_resource);
    EXPECT_EQ(child_resource.live, 0u);
    queue.clear();
    EXPECT_EQ(outer_resource.live, 0u);
    EXPECT_EQ(child_resource.live, 0u);
    EXPECT_EQ(outer_resource.live_bytes, 0u);
    EXPECT_EQ(child_resource.live_bytes, 0u);
}

TEST(Allocator, AllocatorAwareDequeGrowthPreservesPayloadsAcrossAllocationFailures) {
    for (std::size_t allowance = 0; allowance <= 3; ++allowance) {
        SCOPED_TRACE(allowance);
        CountingResource resource;
        {
            memory::RingDeque<AllocatorAwareEntry> queue(&resource);
            for (int value = 0; value < 4; ++value) queue.emplace_back(value);
            while (queue.size() < queue.capacity())
                queue.emplace_back(static_cast<int>(queue.size()));
            const auto retained = queue.size();
            bool appended = false;
            resource.LimitAllocations(allowance);
            try {
                queue.emplace_back(static_cast<int>(retained));
                appended = true;
            } catch (const std::bad_alloc&) {}
            resource.AllowAllocations();
            ASSERT_EQ(queue.size(), retained + static_cast<std::size_t>(appended));
            for (std::size_t index = 0; index < queue.size(); ++index) {
                ASSERT_EQ(queue[index].payload.size(), 1u) << "index=" << index;
                EXPECT_EQ(queue[index].payload.front(), static_cast<int>(index));
                EXPECT_EQ(queue[index].payload.get_allocator().resource(), &resource);
            }
        }
        EXPECT_EQ(resource.live, 0u);
        EXPECT_EQ(resource.live_bytes, 0u);
    }
}

TEST(Allocator, AllocatorAwareDequeShrinkPreservesPayloadsAndReclaimsStorage) {
    CountingResource resource;
    {
        memory::RingDeque<AllocatorAwareEntry> queue(&resource);
        for (int value = 0; value < 64; ++value) queue.emplace_back(value);
        for (int index = 0; index < 7; ++index) queue.pop_front();
        for (int value = 64; value < 71; ++value) queue.emplace_back(value);
        for (int index = 0; index < 48; ++index) queue.pop_front();
        const auto before = resource.live_bytes;
        resource.LimitAllocations(2);
        queue.shrink_to_fit();
        resource.AllowAllocations();
        EXPECT_LE(resource.live_bytes, before);
        ASSERT_EQ(queue.size(), 16u);
        for (std::size_t index = 0; index < queue.size(); ++index) {
            const auto& payload = queue[index].payload;
            ASSERT_EQ(payload.size(), 1u);
            EXPECT_EQ(payload.front(), static_cast<int>(55 + index));
            EXPECT_EQ(payload.get_allocator().resource(), &resource);
        }
        queue.clear();
    }
    EXPECT_EQ(resource.live, 0u);
    EXPECT_EQ(resource.live_bytes, 0u);
}

TEST(Allocator, AllocatorAwareDequeInsertionKeepsDestinationResource) {
    CountingResource source;
    CountingResource destination;
    {
        AllocatorAwareEntry incoming(std::allocator_arg,
            AllocatorAwareEntry::allocator_type(&source), 77);
        memory::RingDeque<AllocatorAwareEntry> queue(&destination);
        for (int value = 0; value < 4; ++value) queue.emplace_back(value);
        while (queue.size() < queue.capacity())
            queue.emplace_back(static_cast<int>(queue.size()));
        const auto retained = queue.size();
        queue.emplace_back(std::move(incoming));
        ASSERT_EQ(queue.size(), retained + 1);
        for (std::size_t index = 0; index < queue.size(); ++index) {
            ASSERT_EQ(queue[index].payload.size(), 1u);
            EXPECT_EQ(queue[index].payload.front(), index == retained ? 77 : static_cast<int>(index));
            EXPECT_EQ(queue[index].payload.get_allocator().resource(), &destination);
        }
    }
    EXPECT_EQ(source.live, 0u);
    EXPECT_EQ(destination.live, 0u);
}

TEST(Allocator, ProcessResourceSupportsAlignmentAcrossSizeBoundaries) {
    auto* const resource = process_resource();
    for (size_t bytes : {0u, 1u, 24u, 31u, 128u, 2048u, 4000u, 8192u, 17408u, 32768u, 65536u}) {
        for (size_t alignment = 1; alignment <= 65536; alignment *= 2) {
            void* block = resource->allocate(bytes, alignment);
            const bool aligned = reinterpret_cast<uintptr_t>(block) % alignment == 0;
            std::memset(block, 0x6b, bytes);
            const bool intact = Intact(block, bytes, 0x6b);
            resource->deallocate(block, bytes, alignment);
            ASSERT_TRUE(aligned && intact);
        }
    }
}

TEST(Allocator, ProcessResourcePreservesMixedLivePayloadsDuringReuse) {
    auto* const resource = process_resource();
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
            resource->deallocate(slot.block, slot.bytes, slot.alignment);
            slot.block = nullptr;
        } else {
            slot.bytes = 8 + next() % (step % 5 ? 2000 : 34000);
            slot.alignment = size_t{1} << (3 + next() % 8);
            slot.pattern = static_cast<uint8_t>(next());
            slot.block = resource->allocate(slot.bytes, slot.alignment);
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
        resource->deallocate(slot.block, slot.bytes, slot.alignment);
    }
    EXPECT_TRUE(intact);
}

TEST(Allocator, ProcessResourceCanRetireRawStorageOnAnotherThread) {
    auto* const resource = process_resource();
    void* block = resource->allocate(17408, 4096);
    std::memset(block, 0xa5, 17408);
    bool intact = false;
    std::thread retire([&] {
        intact = Intact(block, 17408, 0xa5);
        resource->deallocate(block, 17408, 4096);
    });
    retire.join();
    EXPECT_TRUE(intact);
}

TEST(Allocator, BufferAllocationFailureReturnsNullWithoutLeaking) {
    const auto live_before = detail::test_buffers_live;
    reject_next_process_allocation = true;
    auto* block = ::buf::Buffer::New();
    reject_next_process_allocation = false;
    if (block) ::buf::Buffer::Free(block);
    EXPECT_EQ(block, nullptr);
    EXPECT_EQ(detail::test_buffers_live, live_before);
}

TEST(Allocator, IdleDequeReleasesCallerOwnedStorageOnDrain) {
    CountingResource resource;
    RingDeque<int> queue(&resource);
    for (int value = 0; value < 16; ++value) queue.push_back(value);
    for (int value = 0; value < 16; ++value) {
        EXPECT_EQ(queue.front(), value);
        queue.pop_front();
    }
    EXPECT_TRUE(queue.empty());
    EXPECT_EQ(resource.live, 0u);
    EXPECT_EQ(resource.live_bytes, 0u);
}
} // namespace
