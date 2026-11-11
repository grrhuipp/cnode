#include <gtest/gtest.h>

#include "common/allocator.hpp"
#include "common/buf/multi_buffer.hpp"
#include "common/session.hpp"
#include <algorithm>
#include <array>
#include <barrier>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <thread>
#include <tuple>
#include <type_traits>
#include <vector>
#include <cstdlib>

namespace {
using namespace ::memory;
using Pool = worker_memory;
using namespace std::chrono_literals;

bool Intact(void* p, size_t bytes, uint8_t pattern) {
    const auto* data = static_cast<const uint8_t*>(p);
    for (size_t i = 0; i < bytes; ++i) if (data[i] != pattern) return false;
    return true;
}

bool RunBoundaries() {
    Pool pool;
    for (size_t bytes = 0; bytes <= 16 * 1024 + 32; ++bytes) {
        void* p = pool.Allocate(bytes, 16);
        if (!p || reinterpret_cast<uintptr_t>(p) % 16) return false;
        std::memset(p, 0xa5, bytes);
        pool.Deallocate(p, bytes, 16);
    }
    for (size_t bytes : {1u, 24u, 31u, 128u, 2048u, 4000u, 8192u, 17408u, 32768u, 65536u}) {
        for (size_t alignment = 1; alignment <= 65536; alignment *= 2) {
            for (int round = 0; round < 8; ++round) {
                void* p = pool.Allocate(bytes, alignment);
                if (!p || reinterpret_cast<uintptr_t>(p) % alignment) return false;
                std::memset(p, 0x6b, bytes);
                pool.Deallocate(p, bytes, alignment);
            }
        }
    }
    constexpr auto maximum = std::numeric_limits<size_t>::max();
    return !pool.Allocate(maximum, 16) && !pool.Allocate(maximum - 8, 16) &&
        !pool.Allocate(1024, 0) && !pool.Allocate(1024, 3) &&
        !pool.Allocate(1024, maximum) && pool.OutstandingAllocations() == 0;
}

bool RunMixed() {
    Pool pool;
    struct Slot { void* ptr = nullptr; size_t bytes = 0; size_t alignment = 0; uint8_t pattern = 0; };
    std::array<Slot, 256> slots{};
    size_t live = 0;
    uint32_t state = 0xb35dff21u;
    const auto next = [&state] {
        state ^= state << 13; state ^= state >> 17; state ^= state << 5;
        return state;
    };
    for (int step = 0; step < 100000; ++step) {
        auto& slot = slots[next() % slots.size()];
        if (slot.ptr) {
            if (!Intact(slot.ptr, slot.bytes, slot.pattern)) return false;
            pool.Deallocate(slot.ptr, slot.bytes, slot.alignment);
            slot.ptr = nullptr;
            --live;
        } else {
            slot.bytes = 8 + next() % (step % 5 ? 2000 : 34000);
            slot.alignment = step % 8 ? (next() % 2 ? 8 : 16) : size_t{1} << (3 + next() % 8);
            slot.pattern = static_cast<uint8_t>(next());
            slot.ptr = pool.Allocate(slot.bytes, slot.alignment);
            if (!slot.ptr || reinterpret_cast<uintptr_t>(slot.ptr) % slot.alignment) return false;
            std::memset(slot.ptr, slot.pattern, slot.bytes);
            ++live;
        }
        if (step % 997 == 0 && pool.OutstandingAllocations() != live) return false;
        if (step % 97 == 0) for (const auto& held : slots)
            if (held.ptr && !Intact(held.ptr, held.bytes, held.pattern)) return false;
    }
    for (const auto& slot : slots) {
        if (slot.ptr && !Intact(slot.ptr, slot.bytes, slot.pattern)) return false;
        pool.Deallocate(slot.ptr, slot.bytes, slot.alignment);
    }
    pool.Collect();
    return pool.OutstandingAllocations() == 0;
}

bool RunCollectReleasesEmptyPages() {
    Pool pool;
    std::vector<void*> blocks;
    for (size_t i = 0; i < 4096; ++i) {
        void* p = pool.Allocate(i % 2 ? 96 : 8192, 16);
        if (!p) return false;
        blocks.push_back(p);
    }
    const auto loaded = pool.GetFootprint();
    if (pool.OutstandingAllocations() != blocks.size() || loaded.pages == 0 ||
        loaded.committed_bytes < loaded.used_bytes) return false;
    for (auto* p : blocks) pool.Deallocate(p);
    pool.Collect();
    const auto collected = pool.GetFootprint();
    return pool.OutstandingAllocations() == 0 && collected.used_bytes == 0 &&
        collected.committed_bytes < loaded.committed_bytes;
}

bool RunOwnershipAndPmr() {
    Pool pool;
    void* p = pool.Allocate(8192, 16);
    if (!p || pool.OutstandingAllocations() != 1) return false;
    std::memset(p, 0xa5, 8192);
    pool.Deallocate(p);
    if (pool.OutstandingAllocations() != 0) return false;
    reject_next_pmr_allocation = true;
    if (pool.Allocate(17, 16) || reject_next_pmr_allocation) return false;
    for (size_t alignment : {8u, 16u, 64u, 4096u}) {
        p = pool.Allocate(17408, alignment);
        if (!p || reinterpret_cast<uintptr_t>(p) % alignment) return false;
        pool.Deallocate(p);
    }
    return pool.OutstandingAllocations() == 0 &&
        !pool.Allocate(std::numeric_limits<size_t>::max(), 16);
}

bool RunBuffer() {
    using ::buf::Buffer;
    Pool pool;
    std::array<Buffer*, 64> buffers{};
    for (auto& p : buffers) {
        p = Buffer::New(pool);
        if (!p || p->Len() || p->HasUDP() || &p->Pool() != &pool) return false;
        std::memset(p->data, 0x5a, Buffer::kSize);
        p->Produce(1);
    }
    if (pool.OutstandingAllocations() != buffers.size()) return false;
    Buffer::Free(buffers.back());
    buffers.back() = Buffer::New(pool);
    if (!buffers.back() || buffers.back()->Len() || buffers.back()->HasUDP()) return false;
    for (size_t i = 0; i + 1 < buffers.size(); ++i)
        if (!Intact(buffers[i]->data, Buffer::kSize, 0x5a)) return false;
    for (auto* p : buffers) Buffer::Free(p);
    return pool.OutstandingAllocations() == 0;
}

bool RunSharedAllocation() {
    struct alignas(64) SharedObject final
        : WorkerAllocated, std::enable_shared_from_this<SharedObject> {
        SharedObject(std::unique_ptr<int> payload, int& destroyed)
            : payload(std::move(payload)), destroyed(destroyed) {}
        ~SharedObject() { ++destroyed; }
        std::unique_ptr<int> payload;
        int& destroyed;
    };
    struct ThrowingObject final : WorkerAllocated {
        ThrowingObject() { throw std::runtime_error("construction failed"); }
    };

    Pool pool;
    int destroyed = 0;
    bool passed = true;
    std::weak_ptr<SharedObject> weak;
    {
        auto object = AllocateShared<SharedObject>(pool.resource(), std::make_unique<int>(42), destroyed);
        weak = object;
        passed &= *object->payload == 42 &&
            reinterpret_cast<uintptr_t>(object.get()) % alignof(SharedObject) == 0 &&
            object->shared_from_this() == object && pool.OutstandingAllocations() == 1;
    }
    // The control block outlives the object while a weak reference remains.
    passed &= destroyed == 1 && weak.expired() && pool.OutstandingAllocations() == 1;
    weak.reset();
    passed &= pool.OutstandingAllocations() == 0;

    bool threw = false;
    try {
        (void)AllocateShared<ThrowingObject>(pool.resource());
    } catch (const std::runtime_error&) {
        threw = true;
    }
    passed &= threw && pool.OutstandingAllocations() == 0;
    return passed;
}

class CountingResource final : public std::pmr::memory_resource {
public:
    std::size_t allocations = 0;
    std::size_t returns = 0;
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
        ++allocations;
        ++live;
        live_bytes += bytes;
        return block;
    }
    void do_deallocate(void* block, std::size_t bytes, std::size_t alignment) override {
        process_resource()->deallocate(block, bytes, alignment);
        ++returns;
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

bool RunSessionContextAndIdleDeque() {
    Pool worker;
    bool passed = true;
    {
        ::session::Context ctx(worker);
        passed &= ctx.inbound.tag.get_allocator().resource() == worker.resource() &&
            ctx.content.protocol.get_allocator().resource() == worker.resource();
        ctx.inbound.tag = "panel/multi-tier-arena-test/node-100/vless/443";
        ctx.inbound.user_email = "arena-user-with-long-identifier@example.com";
        passed &= worker.OutstandingAllocations() == 2;
    }
    passed &= worker.OutstandingAllocations() == 0;
    {
        RingDeque<int> idle_deque(worker.resource());
        passed &= worker.OutstandingAllocations() == 0 && idle_deque.capacity() == 0;
        for (int i = 0; i < 16; ++i) idle_deque.push_back(i);
        for (int i = 0; i < 16; ++i) {
            passed &= idle_deque.front() == i;
            idle_deque.pop_front();
        }
        passed &= idle_deque.empty() && idle_deque.capacity() == 0 &&
            worker.OutstandingAllocations() == 0;
    }
    return passed;
}

bool RunAll() {
    struct Case { const char* name; bool (*run)(); };
    for (const auto& test : std::array{
        Case{"boundaries/alignment/overflow", RunBoundaries},
        Case{"mixed lifetime", RunMixed},
        Case{"collect releases empty pages", RunCollectReleasesEmptyPages},
        Case{"ownership/PMR/OOM", RunOwnershipAndPmr}, Case{"Buffer", RunBuffer},
        Case{"shared allocation/alignment/exception", RunSharedAllocation},
        Case{"session context and idle deque", RunSessionContextAndIdleDeque}}) {
        if (!test.run()) {
            std::fprintf(stderr, "pool case failed: %s\n", test.name);
            return false;
        }
    }
    return true;
}
} // namespace

TEST(WorkerMemory, Contract) {
    bool worker = false;
    std::thread thread([&] { worker = RunAll(); });
    thread.join();
    const bool main = RunAll();
    std::printf("unified pool layout/ownership/reuse/purge: %s\n", worker && main ? "PASS" : "FAIL");
    { ASSERT_TRUE(worker && main); return; }
}

TEST(WorkerMemory, NestedDequeMovePreservesDescendantsAndResourceOwnership) {
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

TEST(WorkerMemory, AllocatorAwareDequeGrowthPreservesPayloadsAcrossAllocationFailures) {
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

TEST(WorkerMemory, AllocatorAwareDequeShrinkPreservesPayloadsAndReclaimsStorage) {
    ASSERT_EXIT({
        CountingResource resource;
        memory::RingDeque<AllocatorAwareEntry> queue(&resource);
        for (int value = 0; value < 64; ++value) queue.emplace_back(value);
        for (int index = 0; index < 7; ++index) queue.pop_front();
        for (int value = 64; value < 71; ++value) queue.emplace_back(value);
        for (int index = 0; index < 48; ++index) queue.pop_front();
        const auto before = resource.live_bytes;
        resource.LimitAllocations(2);
        queue.shrink_to_fit();
        resource.AllowAllocations();
        // 失败实现可能已析构旧前缀；先在隔离进程检查泄漏，避免继续触碰失效对象。
        if (resource.live_bytes > before) {
            std::fprintf(stderr, "shrink leaked storage: before=%zu after=%zu live=%zu\n",
                before, resource.live_bytes, resource.live);
            std::_Exit(2);
        }
        if (queue.size() != 16) std::_Exit(3);
        for (std::size_t index = 0; index < queue.size(); ++index) {
            const auto& payload = queue[index].payload;
            if (payload.size() != 1 || payload.front() != static_cast<int>(55 + index) ||
                payload.get_allocator().resource() != &resource) std::_Exit(4);
        }
        queue.clear();
        if (resource.live != 0 || resource.live_bytes != 0) std::_Exit(5);
        std::_Exit(0);
    }, ::testing::ExitedWithCode(0), "");
}

TEST(WorkerMemory, AllocatorAwareDequeInsertionKeepsDestinationResource) {
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

TEST(WorkerMemory, ByteVectorInsertPreservesReservedAndGrowingPrefixes) {
    Pool pool;
    {
        memory::Vector<uint8_t> bytes(pool.resource());
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
            EXPECT_EQ(bytes.get_allocator().resource(), pool.resource());
        }
        bytes.clear();
        bytes.insert(bytes.end(), expected.begin(), expected.end());
        EXPECT_TRUE(std::equal(expected.begin(), expected.end(), bytes.begin(), bytes.end()));
    }
    EXPECT_EQ(pool.OutstandingAllocations(), 0u);
}

TEST(WorkerMemory, VectorPairAndMapConstructionPropagatesNestedAllocators) {
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
    EXPECT_EQ(destination.allocations, destination.returns);
}

TEST(WorkerMemory, TrivialCopyStillUsesAllocatorExtendedConstruction) {
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
