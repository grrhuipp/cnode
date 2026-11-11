#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/session.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <type_traits>
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

TEST(Allocator, ByteVectorInsertPreservesReservedAndGrowingPrefixes) {
    CountingResource resource;
    {
        memory::Vector<uint8_t> bytes(&resource);
        std::vector<uint8_t> expected;
        bytes.reserve(1024);
        for (const std::size_t count : {64u, 900u, 1024u, 16384u, 65536u}) {
            std::vector<uint8_t> input(count);
            for (std::size_t index = 0; index < count; ++index)
                input[index] = static_cast<uint8_t>(index * 131 + count);
            bytes.insert(bytes.end(), input.begin(), input.end());
            expected.insert(expected.end(), input.begin(), input.end());
            ASSERT_EQ(bytes.size(), expected.size());
            EXPECT_TRUE(std::equal(expected.begin(), expected.end(), bytes.begin()));
            EXPECT_EQ(bytes.get_allocator().resource(), &resource);
        }
        bytes.clear();
        bytes.insert(bytes.end(), expected.begin(), expected.end());
        EXPECT_TRUE(std::equal(expected.begin(), expected.end(), bytes.begin(), bytes.end()));
    }
    EXPECT_EQ(resource.live, 0u);
}

TEST(Allocator, VectorConstructionPropagatesNestedAllocators) {
    CountingResource destination;
    {
        // The destination differs from the process layer, so default construction
        // cannot accidentally satisfy the propagation checks.
        memory::Vector<AllocatorAwareEntry> entries{
            memory::Allocator<AllocatorAwareEntry>(&destination)};
        for (int value = 0; value < 20; ++value) entries.emplace_back(value);
        for (int value = 0; value < 20; ++value) {
            ASSERT_EQ(entries[value].payload.size(), 1u);
            EXPECT_EQ(entries[value].payload.front(), value);
            EXPECT_EQ(entries[value].payload.get_allocator().resource(), &destination);
        }
    }
    EXPECT_EQ(destination.live, 0u);
}

TEST(Allocator, PairConstructionPropagatesNestedAllocators) {
    CountingResource destination;
    {
        using Strings = memory::Vector<memory::String>;
        using Pair = std::pair<memory::String, Strings>;
        memory::Vector<Pair> pairs{memory::Allocator<Pair>(&destination)};
        pairs.emplace_back(std::piecewise_construct,
            std::forward_as_tuple(80, 'p'), std::tuple<>{});
        pairs.front().second.emplace_back(90, 'v');
        pairs.push_back(pairs.front());
        for (const auto& pair : pairs) {
            EXPECT_EQ(pair.first, memory::String(80, 'p'));
            EXPECT_EQ(pair.first.get_allocator().resource(), &destination);
            EXPECT_EQ(pair.second.get_allocator().resource(), &destination);
            ASSERT_EQ(pair.second.size(), 1u);
            EXPECT_EQ(pair.second.front(), memory::String(90, 'v'));
            EXPECT_EQ(pair.second.front().get_allocator().resource(), &destination);
        }
    }
    EXPECT_EQ(destination.live, 0u);
}

TEST(Allocator, MapConstructionPropagatesNestedAllocators) {
    CountingResource destination;
    {
        using Strings = memory::Vector<memory::String>;
        using Map = memory::Map<memory::String, Strings>;
        Map map{Map::allocator_type(&destination)};
        map.try_emplace(memory::String(100, 'k')).first->second.emplace_back(110, 'x');
        map.emplace(std::piecewise_construct,
            std::forward_as_tuple(120, 'm'), std::tuple<>{}).first->second.emplace_back(130, 'y');
        ASSERT_EQ(map.size(), 2u);
        for (const auto& [key, values] : map) {
            EXPECT_EQ(key.get_allocator().resource(), &destination);
            EXPECT_EQ(values.get_allocator().resource(), &destination);
            ASSERT_EQ(values.size(), 1u);
            EXPECT_EQ(values.front().get_allocator().resource(), &destination);
            const bool first = key.front() == 'k';
            EXPECT_EQ(key, memory::String(first ? 100 : 120, first ? 'k' : 'm'));
            EXPECT_EQ(values.front(), memory::String(first ? 110 : 130, first ? 'x' : 'y'));
        }
    }
    EXPECT_EQ(destination.live, 0u);
}

TEST(Allocator, TrivialCopyStillUsesAllocatorExtendedConstruction) {
    struct Entry {
        using allocator_type = std::pmr::polymorphic_allocator<std::byte>;
        std::pmr::memory_resource* resource;
        int value;

        Entry(int value) : resource(nullptr), value(value) {}
        Entry(std::allocator_arg_t, allocator_type allocator, const Entry& other)
            : resource(allocator.resource()), value(other.value) {}
    };
    static_assert(std::is_trivially_copy_constructible_v<Entry>);
    static_assert(std::uses_allocator_v<Entry, std::pmr::polymorphic_allocator<Entry>>);
    CountingResource destination;
    {
        memory::Vector<Entry> entries{memory::Allocator<Entry>(&destination)};
        const Entry source(42);
        entries.push_back(source);
        entries.reserve(entries.capacity() + 1);
        entries.push_back(source);
        for (const auto& entry : entries) {
            EXPECT_EQ(entry.value, 42);
            EXPECT_EQ(entry.resource, &destination);
        }
    }
    EXPECT_EQ(destination.live, 0u);
}

TEST(Allocator, DefaultContainersUseProcessResourceWithoutChangingGlobalPmrDefault) {
    CountingResource external_default;
    struct DefaultGuard {
        std::pmr::memory_resource* previous;
        ~DefaultGuard() { std::pmr::set_default_resource(previous); }
    } guard{std::pmr::set_default_resource(&external_default)};
    external_default.LimitAllocations(0);
    auto* const resource = process_resource();
    EXPECT_EQ(std::pmr::get_default_resource(), &external_default);
    EXPECT_EQ(Allocator<int>().resource(), resource);
    EXPECT_EQ(ProcessAllocator<int>().resource(), resource);
    EXPECT_EQ(Allocator<int>(nullptr).resource(), resource);
    Vector<int> values;
    values.push_back(42);
    String text(100, 'x');
    RingDeque<int> queue;
    queue.push_back(71);
    ::session::Context context;
    context.inbound.tag = "process-default-inbound-tag-longer-than-sso";
    context.content.protocol = "process-default-protocol-longer-than-sso";
    EXPECT_EQ(values.get_allocator().resource(), resource);
    EXPECT_EQ(text.get_allocator().resource(), resource);
    EXPECT_EQ(queue.get_allocator().resource(), resource);
    EXPECT_EQ(context.inbound.tag.get_allocator().resource(), resource);
    EXPECT_EQ(context.content.protocol.get_allocator().resource(), resource);
    EXPECT_EQ(values.front(), 42);
    EXPECT_EQ(queue.front(), 71);
    EXPECT_EQ(std::pmr::get_default_resource(), &external_default);
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

TEST(Allocator, SharedAllocationPreservesAlignmentAndWeakLifetime) {
    struct alignas(64) SharedObject : std::enable_shared_from_this<SharedObject> {
        SharedObject(std::unique_ptr<int> payload, int& destroyed)
            : payload(std::move(payload)), destroyed(destroyed) {}
        ~SharedObject() { ++destroyed; }
        std::unique_ptr<int> payload;
        int& destroyed;
    };
    CountingResource resource;
    int destroyed = 0;
    std::weak_ptr<SharedObject> weak;
    {
        auto object = std::allocate_shared<SharedObject>(Allocator<SharedObject>(&resource),
            std::make_unique<int>(42), destroyed);
        weak = object;
        EXPECT_EQ(*object->payload, 42);
        EXPECT_EQ(reinterpret_cast<uintptr_t>(object.get()) % alignof(SharedObject), 0u);
        EXPECT_EQ(object->shared_from_this(), object);
    }
    EXPECT_EQ(destroyed, 1);
    EXPECT_TRUE(weak.expired());
    weak.reset();
    EXPECT_EQ(resource.live, 0u);
}

TEST(Allocator, SharedConstructorFailureRollsBackStorage) {
    struct ThrowingObject {
        ThrowingObject() { throw std::runtime_error("construction failed"); }
    };
    CountingResource resource;
    EXPECT_THROW((void)std::allocate_shared<ThrowingObject>(Allocator<ThrowingObject>(&resource)),
        std::runtime_error);
    EXPECT_EQ(resource.live, 0u);
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

TEST(Allocator, DefaultVectorAllocationFailurePreservesPayloadAndCanRetry) {
    Vector<uint8_t> bytes;
    bytes.reserve(8);
    for (uint8_t value = 0; value < 8; ++value) bytes.push_back(value);
    const std::array<uint8_t, 8> expected{0, 1, 2, 3, 4, 5, 6, 7};
    const auto* const storage = bytes.data();
    const auto capacity = bytes.capacity();
    reject_next_process_allocation = true;
    bool failed = false;
    try { bytes.reserve(capacity + 1); }
    catch (const std::bad_alloc&) { failed = true; }
    reject_next_process_allocation = false;
    EXPECT_TRUE(failed);
    EXPECT_EQ(bytes.data(), storage);
    EXPECT_EQ(bytes.capacity(), capacity);
    EXPECT_TRUE(std::equal(bytes.begin(), bytes.end(), expected.begin(), expected.end()));
    bytes.reserve(capacity + 1);
    bytes.push_back(0x91);
    ASSERT_EQ(bytes.size(), expected.size() + 1);
    EXPECT_TRUE(std::equal(expected.begin(), expected.end(), bytes.begin()));
    EXPECT_EQ(bytes.back(), 0x91);
}

TEST(Allocator, UnrepresentableVectorReservePreservesPayload) {
    Vector<uint8_t> bytes{0x42, 0x91};
    EXPECT_THROW(bytes.reserve(std::numeric_limits<size_t>::max()), std::length_error);
    EXPECT_EQ(bytes.size(), 2u);
    EXPECT_EQ(bytes.back(), 0x91);
}
} // namespace
