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
#include <sys/wait.h>
#include <unistd.h>

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
    for (size_t bytes = 0; bytes <= kThreadMemoryPoolMaxClass + 32; ++bytes) {
        const auto layout = Pool::Describe(bytes, 16);
        void* p = pool.Allocate(bytes, 16);
        if (!p || reinterpret_cast<uintptr_t>(p) % 16 || layout.slots == 0) return false;
        std::memset(p, 0xa5, bytes);
        pool.Deallocate(p, bytes, 16);
    }
    pool.PurgeIdle();
    for (size_t bytes : {1u, 31u, 128u, 2048u, 4000u, 8192u, 17408u, 32768u, 65536u}) {
        for (size_t alignment = 1; alignment <= 65536; alignment *= 2) {
            for (int round = 0; round < 8; ++round) {
                void* p = pool.Allocate(bytes, alignment);
                if (!p || reinterpret_cast<uintptr_t>(p) % alignment) return false;
                std::memset(p, 0x6b, bytes);
                pool.Deallocate(p, bytes, alignment);
                if (pool.GetFootprint().direct_bytes) return false;
            }
        }
    }
    pool.PurgeIdle();
    constexpr auto maximum = std::numeric_limits<size_t>::max();
    return !pool.Allocate(maximum, 16) && !pool.Allocate(maximum - 64, 16) &&
        !pool.Allocate(1024, 0) && !pool.Allocate(1024, 3) &&
        !pool.Allocate(1024, maximum) && pool.GetFootprint().mapped_bytes == 0;
}

bool RunGeometry() {
    // Finer classes and a single header, with no protocol-specific exceptions.
    if (Pool::Describe(240, 8).slot_bytes != 256 ||
        Pool::Describe(632, 8).slot_bytes != 704 ||
        Pool::Describe(8296, 8).slot_bytes != 8448 ||
        Pool::Describe(17408, 8).slot_bytes != 20480) return false;
    size_t last_stride = 0;
    for (size_t bytes = 1; bytes <= kThreadMemoryPoolMaxClass - 16; ++bytes) {
        const auto layout = Pool::Describe(bytes, 8, 4);
        if (layout.slot_bytes == last_stride) continue;
        last_stride = layout.slot_bytes;
        Pool pool;
        std::vector<void*> blocks;
        size_t expected_maps = 0;
        for (size_t depth = 0; depth < 5; ++depth) {
            const auto tier = Pool::Describe(bytes, 16, depth);
            if (!tier.slots || tier.direct || tier.map_bytes % kAllocationPageBytes ||
                tier.slot_bytes % 16 || tier.map_bytes > std::max(kAllocationPageBytes, kThreadMemoryPoolTargetBytes))
                return false;
            expected_maps += tier.map_bytes;
            for (size_t i = 0; i < tier.slots; ++i) {
                void* p = pool.Allocate(bytes, i % 2 ? 8 : 16);
                if (!p || reinterpret_cast<uintptr_t>(p) % 16) return false;
                std::memset(p, 0x5a, bytes);
                blocks.push_back(p);
                if (pool.GetFootprint().chunks != depth + 1) return false;
            }
            if (pool.GetFootprint().mapped_bytes != expected_maps || pool.GetFootprint().direct_bytes)
                return false;
        }
        for (auto* p : blocks) {
            if (!Intact(p, bytes, 0x5a)) return false;
            pool.Deallocate(p);
        }
        if (pool.GetFootprint().idle_bytes != expected_maps) return false;
        pool.PurgeIdle();
        if (pool.GetFootprint().mapped_bytes || pool.GetFootprint().chunks) return false;
    }
    return true;
}

bool RunFragmented() {
    Pool pool;
    std::array<void*, 512> blocks{};
    std::array<void*, 48> pinned{};
    for (auto& pin : pinned) {
        for (auto& block : blocks) {
            block = pool.Allocate(128, 16);
            if (!block) return false;
            std::memset(block, 0x5a, 128);
        }
        pin = blocks[0];
        for (size_t i = 1; i < blocks.size(); ++i) pool.Deallocate(blocks[i]);
        if (pool.GetFootprint().mapped_bytes > 8 * kThreadMemoryPoolTargetBytes) return false;
    }
    for (auto* pin : pinned) {
        if (!Intact(pin, 128, 0x5a)) return false;
        pool.Deallocate(pin);
    }
    pool.PurgeIdle();

    // Mixed 8/16-byte callers reuse identical, baseline-aligned slots. An
    // oversized next request must not inflate the old slot into its neighbor.
    void* first = pool.Allocate(600, 8);
    void* held = pool.Allocate(600, 16);
    if (!first || !held) return false;
    std::memset(held, 0x6b, 600);
    pool.Deallocate(first);
    void* reused = pool.Allocate(624, 16);
    if (reused != first) return false;
    std::memset(reused, 0xa5, 624);
    pool.Deallocate(reused);
    void* larger = pool.Allocate(625, 8);
    if (!larger || larger == first) return false;
    std::memset(larger, 0xa7, 625);
    if (!Intact(held, 600, 0x6b)) return false;
    pool.Deallocate(larger);
    pool.Deallocate(held);
    return true;
}

bool RunMixed() {
    Pool pool;
    struct Slot { void* ptr = nullptr; size_t bytes = 0; size_t alignment = 0; uint8_t pattern = 0; };
    std::array<Slot, 256> slots{};
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
        } else {
            slot.bytes = 8 + next() % (step % 5 ? 2000 : 34000);
            slot.alignment = step % 8 ? (next() % 2 ? 8 : 16) : size_t{1} << (3 + next() % 8);
            slot.pattern = static_cast<uint8_t>(next());
            slot.ptr = pool.Allocate(slot.bytes, slot.alignment);
            if (!slot.ptr || reinterpret_cast<uintptr_t>(slot.ptr) % slot.alignment) return false;
            std::memset(slot.ptr, slot.pattern, slot.bytes);
        }
        if (step % 97 == 0) for (const auto& live : slots)
            if (live.ptr && !Intact(live.ptr, live.bytes, live.pattern)) return false;
    }
    for (const auto& slot : slots) {
        if (slot.ptr && !Intact(slot.ptr, slot.bytes, slot.pattern)) return false;
        pool.Deallocate(slot.ptr, slot.bytes, slot.alignment);
    }
    pool.PurgeIdle();
    return pool.GetFootprint().mapped_bytes == 0;
}

bool RunPinnedChunks() {
    Pool pool;
    constexpr size_t bytes = 8192;
    std::vector<void*> blocks;
    for (size_t depth = 0; depth < 5; ++depth) {
        const auto layout = Pool::Describe(bytes, 16, depth);
        for (size_t i = 0; i < layout.slots; ++i) {
            auto* p = pool.Allocate(bytes, 16);
            if (!p) return false;
            std::memset(p, 0xa5, bytes);
            blocks.push_back(p);
        }
    }
    void* held = blocks.back();
    const auto held_map = Pool::Describe(bytes, 16, 4).map_bytes;
    for (auto* p : blocks) if (p != held) pool.Deallocate(p);
    std::this_thread::sleep_for(kThreadMemoryPoolPurgeDelay + 5ms);
    pool.Purge();
    if (pool.GetFootprint().mapped_bytes != held_map || pool.GetFootprint().idle_bytes ||
        !Intact(held, bytes, 0xa5)) return false;
    auto* reused = pool.Allocate(bytes, 8);
    if (!reused || pool.GetFootprint().chunks != 1) return false;
    pool.Deallocate(reused);
    pool.Deallocate(held);
    pool.PurgeIdle();
    return !pool.GetFootprint().mapped_bytes;
}

bool RunIdleQueue() {
    Pool pool;
    struct Observer final : Pool::IdleWakeup {
        int wakeups = 0;
        void OnPoolIdle() noexcept override { ++wakeups; }
    } observer, other;
    if (!pool.BindIdleWakeup(observer)) return false;
    if (pool.BindIdleWakeup(other)) return false;
    std::array<void*, 3> blocks{};
    constexpr std::array<size_t, 3> sizes{64, 256, 8192};
    size_t idle_bytes = 0;
    for (size_t i = 0; i < 3; ++i) {
        blocks[i] = pool.Allocate(sizes[i], 16);
        if (!blocks[i]) return false;
        idle_bytes += Pool::Describe(sizes[i], 16).map_bytes;
    }
    for (auto* p : blocks) pool.Deallocate(p);
    if (observer.wakeups != 1 || pool.GetFootprint().idle_bytes != idle_bytes) return false;
    for (size_t i : {1, 0, 2}) {
        blocks[i] = pool.Allocate(sizes[i], 8);
        idle_bytes -= Pool::Describe(sizes[i], 16).map_bytes;
        if (!blocks[i] || pool.GetFootprint().idle_bytes != idle_bytes) return false;
        std::memset(blocks[i], 0x5a, sizes[i]);
    }
    pool.Deallocate(blocks[0]);
    const auto deadline = pool.NextPurgeDeadline();
    std::this_thread::sleep_until(deadline + 5ms);
    pool.Deallocate(blocks[1]);
    if (pool.GetFootprint().chunks != 2 || pool.NextPurgeDeadline() <= deadline ||
        !Intact(blocks[2], sizes[2], 0x5a)) return false;
    pool.Deallocate(blocks[2]);
    std::this_thread::sleep_until(pool.NextPurgeDeadline() + kThreadMemoryPoolPurgeDelay);
    pool.Purge();
    if (pool.GetFootprint().chunks || pool.GetFootprint().idle_bytes) return false;
    pool.UnbindIdleWakeup(observer);
    // A scheduling-OOM fallback may immediately destroy the just-freed chunk.
    struct ImmediatePurge final : Pool::IdleWakeup {
        explicit ImmediatePurge(Pool& pool) : pool(pool) {}
        void OnPoolIdle() noexcept override { pool.PurgeIdle(); }
        Pool& pool;
    } immediate(pool);
    if (!pool.BindIdleWakeup(immediate)) return false;
    void* p = pool.Allocate(256, 16);
    if (!p) return false;
    pool.Deallocate(p);
    pool.UnbindIdleWakeup(immediate);
    return !pool.GetFootprint().mapped_bytes;
}

bool RunOwnershipAndPmr() {
    auto& pool = ThreadMemoryPool();
    pool.PurgeIdle();
    void* p = AllocatePmr(8192, 16);
    if (!p) return false;
    std::memset(p, 0xa5, 8192);
    const auto remote_frees = RemoteFreeCount();
    std::thread wrong([p] { DeallocatePmr(p); });
    wrong.join();
    if (RemoteFreeCount() != remote_frees + 1 ||
        pool.GetFootprint().mapped_bytes == 0) return false;
    pool.PurgeIdle();
    if (pool.GetFootprint().mapped_bytes != 0) return false;
    reject_next_pmr_allocation = true;
    if (AllocatePmr(17) || reject_next_pmr_allocation) return false;
    for (size_t alignment : {8u, 16u, 64u, 4096u}) {
        p = AllocatePmr(17408, alignment);
        if (!p || reinterpret_cast<uintptr_t>(p) % alignment) return false;
        DeallocatePmr(p);
    }
    pool.PurgeIdle();
    return pool.GetFootprint().mapped_bytes == 0 && !AllocatePmr(std::numeric_limits<size_t>::max());
}

bool RunBuffer() {
    using ::buf::Buffer;
    auto& pool = ThreadMemoryPool();
    pool.PurgeIdle();
    std::array<Buffer*, 64> buffers{};
    for (auto& p : buffers) {
        p = Buffer::New();
        if (!p) return false;
        std::memset(p->data, 0x5a, Buffer::kSize);
        p->Produce(1);
    }
    const auto maps = pool.GetFootprint().mapped_bytes;
    auto* freed = buffers.back();
    Buffer::Free(freed);
    buffers.back() = Buffer::New();
    if (buffers.back() != freed || freed->Len() || freed->HasUDP() ||
        pool.GetFootprint().mapped_bytes != maps || pool.GetFootprint().direct_bytes) return false;
    for (auto* p : buffers) {
        if (p != freed && !Intact(p->data, Buffer::kSize, 0x5a)) return false;
        Buffer::Free(p);
    }
    pool.PurgeIdle();
    return !pool.GetFootprint().mapped_bytes;
}

bool RunSharedAllocation() {
    struct alignas(64) SharedObject final
        : ThreadAllocated, std::enable_shared_from_this<SharedObject> {
        SharedObject(std::unique_ptr<int> payload, int& destroyed)
            : payload(std::move(payload)), destroyed(destroyed) {}
        ~SharedObject() { ++destroyed; }
        std::unique_ptr<int> payload;
        int& destroyed;
    };
    struct ThrowingObject final : ThreadAllocated {
        ThrowingObject() { throw std::runtime_error("construction failed"); }
    };

    Pool pool;
    auto* previous = std::pmr::set_default_resource(&pool);
    int destroyed = 0;
    bool passed = true;
    std::weak_ptr<SharedObject> weak;
    {
        auto object = AllocateShared<SharedObject>(std::make_unique<int>(42), destroyed);
        weak = object;
        passed &= *object->payload == 42 &&
            reinterpret_cast<uintptr_t>(object.get()) % alignof(SharedObject) == 0 &&
            object->shared_from_this() == object && pool.GetFootprint().mapped_bytes != 0;
    }
    passed &= destroyed == 1 && weak.expired();
    pool.PurgeIdle();
    passed &= pool.GetFootprint().mapped_bytes != 0;
    weak.reset();
    pool.PurgeIdle();
    passed &= pool.GetFootprint().mapped_bytes == 0;

    bool threw = false;
    try {
        (void)AllocateShared<ThrowingObject>();
    } catch (const std::runtime_error&) {
        threw = true;
    }
    pool.PurgeIdle();
    passed &= threw && pool.GetFootprint().mapped_bytes == 0;
    std::pmr::set_default_resource(previous);
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

bool RunLargeBlockCache() {
    CountingResource upstream;
    {
        worker_memory pool(upstream, {.retained_block_bytes_ = 2 * 36864});
        auto* resource = pool.resource();
        // 40000 and 38000 both round to the same 40 KiB class in the block cache.
        void* first = resource->allocate(40000, 16);
        std::memset(first, 0x33, 40000);
        resource->deallocate(first, 40000, 16);
        const auto allocs_after_free = upstream.allocations;
        void* second = resource->allocate(38000, 16);
        if (second != first || upstream.allocations != allocs_after_free) return false;
        resource->deallocate(second, 38000, 16);
        pool.PurgeIdle();
        if (upstream.live != 0 || upstream.live_bytes != 0) return false;

        // Retention budget keeps 2 blocks of 32 KiB class and returns the 3rd immediately.
        std::array<void*, 3> blocks{};
        for (auto& b : blocks) b = resource->allocate(30000, 16);
        for (auto* b : blocks) resource->deallocate(b, 30000, 16);
        if (upstream.live != 2) return false;
        pool.PurgeIdle();
        if (upstream.live != 0) return false;
    }
    return upstream.live == 0 && upstream.allocations == upstream.returns;
}

bool RunRequestArenaAndContext() {
    CountingResource upstream;
    {
        worker_memory worker(upstream, {.request_initial_buffer_bytes_ = 512});
        std::array<std::byte, 256> initial{};
        request_memory parent(worker, initial);
        const auto before = upstream.allocations;
        void* in_place = parent.resource()->allocate(128, 16);
        std::memset(in_place, 0x5a, 128);
        if (upstream.allocations != before || parent.upstream_resource() != worker.resource()) {
            return false;
        }

        auto* prev = std::pmr::set_default_resource(worker.resource());
        {
            ::session::Context ctx;
            if (ctx.inbound.tag.get_allocator().resource() != worker.resource() ||
                ctx.content.protocol.get_allocator().resource() != worker.resource()) {
                std::pmr::set_default_resource(prev);
                return false;
            }
            ctx.inbound.tag = "panel/multi-tier-arena-test/node-100/vless/443";
            ctx.inbound.user_email = "arena-user-with-long-identifier@example.com";
            request_memory stage(worker);
            std::pmr::vector<int> arena_vec(stage.allocator<int>());
            arena_vec.resize(64, 99);
            if (arena_vec.back() != 99 || stage.upstream_resource() != worker.resource()) {
                std::pmr::set_default_resource(prev);
                return false;
            }
        }
        {
            worker_memory deque_pool(upstream);
            ThreadLocalDeque<int> idle_deque(deque_pool.resource());
            if (deque_pool.GetFootprint().mapped_bytes != 0 || idle_deque.capacity() != 0) {
                std::pmr::set_default_resource(prev);
                return false;
            }
            for (int i = 0; i < 16; ++i) idle_deque.push_back(i);
            for (int i = 0; i < 16; ++i) {
                if (idle_deque.front() != i) {
                    std::pmr::set_default_resource(prev);
                    return false;
                }
                idle_deque.pop_front();
            }
            if (!idle_deque.empty() || idle_deque.capacity() != 0 ||
                deque_pool.GetFootprint().idle_bytes != deque_pool.GetFootprint().mapped_bytes) {
                std::pmr::set_default_resource(prev);
                return false;
            }
        }
        std::pmr::set_default_resource(prev);
    }
    return upstream.live == 0 && upstream.allocations == upstream.returns;
}

template <class Action>
bool RejectsLeaseViolation(Action action) {
    const auto child = ::fork();
    if (child < 0) return false;
    if (child == 0) {
        std::set_terminate([] { std::_Exit(73); });
        action();
        std::_Exit(0);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 73;
}

bool RunDomainMigration() {
    struct Payload : ThreadAllocated {
        explicit Payload(domain_memory_resource& memory) : arena(memory) {}
        ThreadLocalVector<int> vector{1, 2, 3};
        ThreadLocalString string = ThreadLocalString(80, 's');
        ThreadLocalDeque<int> queue;
        ThreadLocalUnorderedMap<int, ThreadLocalString> map;
        ::buf::MultiBuffer buffers;
        std::shared_ptr<int> shared = AllocateShared<int>(42);
        request_memory arena;
    };
    AllocationDomain domain;
    Payload* payload = nullptr;
    std::pmr::memory_resource* original = nullptr;
    {
        ScopedAllocationDomain lease(domain);
        original = domain.resource();
        payload = new Payload(domain.memory());
        payload->queue.push_back(9);
        payload->map.try_emplace(1, 80, 'm');
        for (int i = 0; i != 12; ++i) {
            ::buf::BufferGuard buffer(::buf::Buffer::New());
            if (!buffer) return false;
            buffer->Tail()[0] = static_cast<uint8_t>(i);
            buffer->Produce(1);
            payload->buffers.push_back(std::move(buffer));
        }
        (void)payload->arena.resource()->allocate(9000, 16);
        if (payload->vector.get_allocator().resource() != original ||
            payload->string.get_allocator().resource() != original ||
            payload->map.get_allocator().resource() != original ||
            payload->map.at(1).get_allocator().resource() != original)
            return false;
        {
            ScopedAllocationDomain nested(domain);
            if (CurrentAllocationDomain() != &domain) return false;
        }
    }
    bool intact = false;
    std::thread migrated([&] {
        ScopedAllocationDomain lease(domain);
        intact = ThreadMemoryPool().resource() != original &&
            payload->vector.back() == 3 && payload->string.size() == 80 &&
            payload->queue.front() == 9 && *payload->shared == 42 &&
            payload->buffers.byte_size() == 12;
        payload->vector.resize(1024, 8);
        payload->string.append(120, 't');
        (void)payload->arena.resource()->allocate(12000, 16);
        delete payload;
        intact = intact && domain.OutstandingAllocations() == 0;
    });
    migrated.join();
    ThreadMemoryPool().PurgeIdle();
    return intact && ThreadMemoryPool().GetFootprint().mapped_bytes == 0 &&
        CurrentAllocationDomain() == nullptr;
}

bool RunLeaseRejection() {
    const bool no_lease = RejectsLeaseViolation([] {
        AllocationDomain domain;
        (void)domain.resource()->allocate(32, 16);
    });
    const bool other_domain = RejectsLeaseViolation([] {
        AllocationDomain first, second;
        ::buf::Buffer* buffer;
        { ScopedAllocationDomain lease(first); buffer = ::buf::Buffer::New(); }
        ScopedAllocationDomain wrong(second);
        ::buf::Buffer::Free(buffer);
    });
    const bool concurrent = RejectsLeaseViolation([] {
        AllocationDomain domain;
        ScopedAllocationDomain lease(domain);
        std::thread intruder([&] { ScopedAllocationDomain forbidden(domain); });
        intruder.join();
    });
    const bool arena_bypass = RejectsLeaseViolation([] {
        AllocationDomain first, second;
        ScopedAllocationDomain lease(first);
        std::array<std::byte, 512> initial;
        request_memory arena(first.memory(), initial);
        ScopedAllocationDomain wrong(second);
        (void)arena.resource()->allocate(16, 8);
    });
    return no_lease && other_domain && concurrent && arena_bypass;
}

bool RunJoinedDomainBorrow() {
    auto first = std::make_unique<AllocationDomain>();
    AllocationDomain second;
    auto group = std::make_shared<int>(0);
    auto shares = +[](const void* left, const void* right) noexcept { return left == right; };
    first->SetLeaseGroup(group, shares);
    second.SetLeaseGroup(group, shares);
    auto* resource = first->resource();
    std::weak_ptr<void> arena = first->memory().Lifetime();
    struct Raw : ThreadAllocated { int value = 17; };
    Raw* raw;
    ::buf::Buffer* buffer;
    ThreadLocalVector<int>* vector;
    ThreadLocalVector<int>* empty;
    ThreadLocalDeque<int>* empty_queue;
    {
        ScopedAllocationDomain lease(*first);
        buffer = ::buf::Buffer::New();
        if (!buffer) return false;
        buffer->Produce(1);
        vector = new ThreadLocalVector<int>(32, 7);
        empty = new ThreadLocalVector<int>;
        empty_queue = new ThreadLocalDeque<int>;
        raw = new Raw;
    }
    first.reset(); // Drop the physical host before borrowed payload/containers.
    if (arena.expired()) return false;
    bool intact = false;
    std::thread migrated([&] {
        ScopedAllocationDomain lease(second);
        {
            ThreadLocalVector<int> moved;
            moved = std::move(*vector);
            intact = buffer->Len() == 1 && moved.get_allocator().resource() == resource &&
                raw->value == 17;
            moved.resize(10000, 8);
            ::buf::Buffer::Free(buffer);
            delete raw;
        }
        // Empty containers do not pin a retired physical connection arena.
        intact = intact && arena.expired();
        vector->push_back(31);
        intact = intact && vector->get_allocator().resource() == second.resource() &&
            vector->front() == 31;
        delete vector;
        {
            ThreadLocalDeque<ThreadLocalString> nested_deque;
            nested_deque.emplace_back(64, 'q');
            const auto& self_alias = nested_deque;
            nested_deque = self_alias;
            intact = intact && nested_deque.size() == 1 &&
                nested_deque.front().size() == 64 &&
                nested_deque.front().find_first_not_of('q') == ThreadLocalString::npos &&
                nested_deque.front().get_allocator().resource() == second.resource();
            nested_deque.clear();
            for (int i = 0; i < 8; ++i) {
                nested_deque.emplace_back(32, static_cast<char>('a' + i));
                nested_deque.push_back(nested_deque.front());
                nested_deque.push_front(nested_deque.back());
            }
            nested_deque.clear();
        }
        empty->push_back(31);
        intact = intact && empty->get_allocator().resource() == second.resource();
        delete empty;
        empty_queue->push_back(42);
        intact = intact && empty_queue->get_allocator().resource() == second.resource();
        delete empty_queue;
    });
    migrated.join();
    return intact;
}

bool RunWorkerSharedDomainPacking() {
    constexpr std::array<std::size_t, 13> strides{
        64, 80, 96, 112, 128, 144, 160, 176, 192, 448, 512, 640, 1792};
    constexpr std::size_t domains_count = 1000;
    std::vector<std::unique_ptr<AllocationDomain>> domains;
    std::vector<std::array<void*, strides.size()>> blocks(domains_count);
    domains.reserve(domains_count);
    ThreadMemoryPool().PurgeIdle();
    const auto before = ThreadMemoryPool().GetFootprint().mapped_bytes;
    std::size_t live_stride_bytes = 0;
    for (const auto stride : strides) live_stride_bytes += stride * domains_count;

    for (std::size_t index = 0; index < domains_count; ++index) {
        auto domain = std::make_unique<AllocationDomain>();
        {
            ScopedAllocationDomain lease(*domain);
            for (std::size_t slot = 0; slot < strides.size(); ++slot) {
                blocks[index][slot] =
                    domain->resource()->allocate(strides[slot] - 16, 16);
            }
        }
        domains.push_back(std::move(domain));
    }
    const auto mapped =
        ThreadMemoryPool().GetFootprint().mapped_bytes - before;
    if (sizeof(AllocationDomain) > 64 ||
        sizeof(domain_memory_resource) > 128 ||
        mapped > live_stride_bytes * 2) return false;

    std::printf(
        "worker-shared domain packing: domains=%zu live-stride=%zu mapped=%zu "
        "domain=%zu resource=%zu\n",
        domains_count, live_stride_bytes, mapped, sizeof(AllocationDomain),
        sizeof(domain_memory_resource));
    for (std::size_t index = 0; index < domains_count; ++index) {
        ScopedAllocationDomain lease(*domains[index]);
        for (std::size_t slot = 0; slot < strides.size(); ++slot) {
            domains[index]->resource()->deallocate(
                blocks[index][slot], strides[slot] - 16, 16);
        }
        if (domains[index]->OutstandingAllocations() != 0) return false;
    }
    domains.clear();
    ThreadMemoryPool().PurgeIdle();
    return ThreadMemoryPool().GetFootprint().mapped_bytes == before;
}

bool RunAll() {
    struct Case { const char* name; bool (*run)(); };
    for (const auto& test : std::array{
        Case{"boundaries/alignment/overflow", RunBoundaries}, Case{"geometry", RunGeometry},
        Case{"fragmented/mixed alignment", RunFragmented}, Case{"mixed lifetime", RunMixed},
        Case{"pinned chunks", RunPinnedChunks}, Case{"idle FIFO", RunIdleQueue},
        Case{"ownership/PMR/OOM", RunOwnershipAndPmr}, Case{"Buffer", RunBuffer},
        Case{"shared allocation/alignment/exception", RunSharedAllocation},
        Case{"large block cache", RunLargeBlockCache},
        Case{"request arena and session context", RunRequestArenaAndContext},
        Case{"domain migration/RAII", RunDomainMigration},
        Case{"lease violations", RunLeaseRejection},
        Case{"joined domains release empty resource ownership", RunJoinedDomainBorrow},
        Case{"Worker-shared domains compact sparse objects", RunWorkerSharedDomainPacking}}) {
        if (!test.run()) {
            std::fprintf(stderr, "pool case failed: %s\n", test.name);
            return false;
        }
    }
    return true;
}
} // namespace

TEST(ThreadMemoryPool, Contract) {
    bool worker = false;
    std::thread thread([&] { worker = RunAll(); });
    thread.join();
    const bool main = RunAll();
    std::printf("unified pool layout/ownership/reuse/purge: %s\n", worker && main ? "PASS" : "FAIL");
    { ASSERT_TRUE(worker && main); return; }
}

TEST(ThreadMemoryPool, NestedDequeMovePreservesDescendantsAndResourceOwnership) {
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

TEST(ThreadMemoryPool, AllocatorAwareDequeGrowthPreservesPayloadsAcrossAllocationFailures) {
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

TEST(ThreadMemoryPool, AllocatorAwareDequeShrinkPreservesPayloadsAndReclaimsStorage) {
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

TEST(ThreadMemoryPool, AllocatorAwareDequeInsertionKeepsDestinationResource) {
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

TEST(ThreadMemoryPool, ByteVectorInsertPreservesReservedAndGrowingPrefixes) {
    memory::AllocationDomain domain;
    memory::ScopedAllocationDomain lease(domain);
    {
        memory::ThreadLocalVector<uint8_t> bytes;
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
            EXPECT_EQ(bytes.get_allocator().resource(), domain.resource());
        }
        bytes.clear();
        bytes.insert(bytes.end(), expected.begin(), expected.end());
        EXPECT_TRUE(std::equal(expected.begin(), expected.end(), bytes.begin(), bytes.end()));
    }
    EXPECT_EQ(domain.OutstandingAllocations(), 0u);
}

TEST(ThreadMemoryPool, VectorPairAndMapConstructionPropagatesNestedAllocators) {
    CountingResource destination;
    {
        // The destination differs from CurrentResource(), so default construction
        // cannot accidentally satisfy the propagation checks.
        memory::ThreadLocalVector<AllocatorAwareEntry> entries{
            memory::ThreadLocalAllocator<AllocatorAwareEntry>(&destination)};
        for (int value = 0; value < 20; ++value) entries.emplace_back(value);
        for (int value = 0; value < 20; ++value) {
            ASSERT_EQ(entries[value].payload.size(), 1u);
            EXPECT_EQ(entries[value].payload.front(), value);
            EXPECT_EQ(entries[value].payload.get_allocator().resource(), &destination);
        }

        using Strings = memory::ThreadLocalVector<memory::ThreadLocalString>;
        using Pair = std::pair<memory::ThreadLocalString, Strings>;
        memory::ThreadLocalVector<Pair> pairs{memory::ThreadLocalAllocator<Pair>(&destination)};
        pairs.emplace_back(std::piecewise_construct,
            std::forward_as_tuple(80, 'p'), std::tuple<>{});
        pairs.front().second.emplace_back(90, 'v');
        pairs.push_back(pairs.front());
        for (const auto& pair : pairs) {
            EXPECT_EQ(pair.first, memory::ThreadLocalString(80, 'p'));
            EXPECT_EQ(pair.first.get_allocator().resource(), &destination);
            EXPECT_EQ(pair.second.get_allocator().resource(), &destination);
            ASSERT_EQ(pair.second.size(), 1u);
            EXPECT_EQ(pair.second.front(), memory::ThreadLocalString(90, 'v'));
            EXPECT_EQ(pair.second.front().get_allocator().resource(), &destination);
        }

        using Map = memory::ThreadLocalMap<memory::ThreadLocalString, Strings>;
        Map map{Map::allocator_type(&destination)};
        map.try_emplace(memory::ThreadLocalString(100, 'k')).first->second.emplace_back(110, 'x');
        map.emplace(std::piecewise_construct,
            std::forward_as_tuple(120, 'm'), std::tuple<>{}).first->second.emplace_back(130, 'y');
        ASSERT_EQ(map.size(), 2u);
        for (const auto& [key, values] : map) {
            EXPECT_EQ(key.get_allocator().resource(), &destination);
            EXPECT_EQ(values.get_allocator().resource(), &destination);
            ASSERT_EQ(values.size(), 1u);
            EXPECT_EQ(values.front().get_allocator().resource(), &destination);
            const bool first = key.front() == 'k';
            EXPECT_EQ(key, memory::ThreadLocalString(first ? 100 : 120, first ? 'k' : 'm'));
            EXPECT_EQ(values.front(), memory::ThreadLocalString(first ? 110 : 130, first ? 'x' : 'y'));
        }
    }
    EXPECT_EQ(destination.live, 0u);
    EXPECT_EQ(destination.allocations, destination.returns);
}

TEST(ThreadMemoryPool, TrivialCopyStillUsesAllocatorExtendedConstruction) {
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
        memory::ThreadLocalVector<Entry> entries{memory::ThreadLocalAllocator<Entry>(&destination)};
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

TEST(ThreadMemoryPool, RetiredAllocatorRebindsForNestedPairConstructionWithoutAllocate) {
    using Pair = std::pair<memory::ThreadLocalString, memory::ThreadLocalString>;
    auto retired = std::make_unique<memory::AllocationDomain>();
    memory::ThreadLocalAllocator<Pair> allocator(retired->resource());
    std::weak_ptr<void> lifetime = retired->memory().Lifetime();
    retired.reset();
    ASSERT_TRUE(lifetime.expired());

    memory::AllocationDomain current;
    memory::ScopedAllocationDomain lease(current);
    {
        // Stack storage avoids allocate()/resource() rebinding the allocator
        // before construct() gets the chance to resolve the retired resource.
        alignas(Pair) std::byte storage[sizeof(Pair)];
        auto* pointer = reinterpret_cast<Pair*>(storage);
        allocator.construct(pointer, std::piecewise_construct,
            std::forward_as_tuple(80, 'a'), std::forward_as_tuple(90, 'b'));
        auto destroy = [](Pair* pair) { std::destroy_at(pair); };
        std::unique_ptr<Pair, decltype(destroy)> pair(pointer, destroy);
        EXPECT_EQ(pair->first.get_allocator().resource(), current.resource());
        EXPECT_EQ(pair->second.get_allocator().resource(), current.resource());
        EXPECT_EQ(pair->first, memory::ThreadLocalString(80, 'a'));
        EXPECT_EQ(pair->second, memory::ThreadLocalString(90, 'b'));
    }
    EXPECT_EQ(current.OutstandingAllocations(), 0u);
}

TEST(ThreadMemoryPool, DrainedBorrowedQueueReleasesRetiredDomainAndRebinds) {
    auto retired = std::make_unique<memory::AllocationDomain>();
    memory::AllocationDomain current;
    auto group = std::make_shared<int>(0);
    auto shares = +[](const void* left, const void* right) noexcept { return left == right; };
    retired->SetLeaseGroup(group, shares);
    current.SetLeaseGroup(group, shares);
    std::weak_ptr<void> lifetime = retired->memory().Lifetime();
    memory::RingDeque<int> queue(retired->resource());
    {
        memory::ScopedAllocationDomain lease(*retired);
        queue.push_back(42);
    }
    retired.reset();
    ASSERT_FALSE(lifetime.expired());
    bool intact = false;
    std::thread migrated([&] {
        memory::ScopedAllocationDomain lease(current);
        intact = queue.front() == 42;
        queue.pop_front();
        intact = intact && lifetime.expired() && queue.capacity() == 0;
        queue.push_back(73);
        intact = intact && queue.front() == 73 &&
            queue.get_allocator().resource() == current.resource();
        queue.pop_front();
        intact = intact && current.OutstandingAllocations() == 0;
    });
    migrated.join();
    EXPECT_TRUE(intact);
    EXPECT_TRUE(lifetime.expired());
    memory::ThreadMemoryPool().PurgeIdle();
}

TEST(ThreadMemoryPool, BorrowedQueueConstructsNestedPayloadsAfterHostRetirement) {
    auto retired = std::make_unique<memory::AllocationDomain>();
    memory::AllocationDomain current;
    auto group = std::make_shared<int>(0);
    auto shares = +[](const void* left, const void* right) noexcept { return left == right; };
    retired->SetLeaseGroup(group, shares);
    current.SetLeaseGroup(group, shares);
    auto* original = retired->resource();
    std::weak_ptr<void> lifetime = retired->memory().Lifetime();
    memory::RingDeque<memory::ThreadLocalString> queue(original);
    {
        memory::ScopedAllocationDomain lease(*retired);
        queue.emplace_back(80, 'a');
    }
    retired.reset();
    ASSERT_FALSE(lifetime.expired());
    bool intact = false;
    std::thread migrated([&] {
        memory::ScopedAllocationDomain lease(current);
        queue.emplace_back(96, 'b');
        queue.emplace_front(112, 'c');
        queue.emplace_back(128, 'd');
        queue.emplace_front(144, 'e');
        constexpr std::array sizes{144u, 112u, 80u, 96u, 128u};
        constexpr std::array values{'e', 'c', 'a', 'b', 'd'};
        intact = queue.size() == sizes.size();
        for (std::size_t index = 0; index < queue.size(); ++index) {
            const auto& value = queue[index];
            intact = intact && value.size() == sizes[index] &&
                value.find_first_not_of(values[index]) == memory::ThreadLocalString::npos &&
                value.get_allocator().resource() == original;
        }
        queue.clear();
        intact = intact && lifetime.expired();
        queue.emplace_back(80, 'f');
        intact = intact && queue.front().get_allocator().resource() == current.resource() &&
            queue.front().size() == 80 &&
            queue.front().find_first_not_of('f') == memory::ThreadLocalString::npos;
        queue.clear();
        intact = intact && current.OutstandingAllocations() == 0;
    });
    migrated.join();
    EXPECT_TRUE(intact);
    EXPECT_TRUE(lifetime.expired());
    memory::ThreadMemoryPool().PurgeIdle();
}

TEST(ThreadMemoryPool, RemoteBatchExpiresOldIdleChunksAndRetainsNewReturns) {
    memory::worker_memory pool;
    auto* expired = pool.Allocate(64, 16);
    auto* small = pool.Allocate(256, 16);
    auto* large = pool.Allocate(32768, 16);
    ASSERT_NE(expired, nullptr);
    ASSERT_NE(small, nullptr);
    ASSERT_NE(large, nullptr);
    pool.Deallocate(expired);
    const auto expired_deadline = pool.NextPurgeDeadline();
    std::this_thread::sleep_until(expired_deadline + std::chrono::milliseconds(5));
    std::thread remote([&] {
        pool.Deallocate(small);
        pool.Deallocate(large);
    });
    remote.join();
    const auto footprint = pool.GetFootprint();
    const auto retained = memory::worker_memory::Describe(256, 16).map_bytes +
        memory::worker_memory::Describe(32768, 16).map_bytes;
    EXPECT_EQ(footprint.mapped_bytes, retained);
    EXPECT_EQ(footprint.idle_bytes, retained);
    EXPECT_EQ(footprint.chunks, 2u);
    EXPECT_GT(pool.NextPurgeDeadline(), expired_deadline);
    pool.PurgeIdle();
    EXPECT_EQ(pool.GetFootprint().mapped_bytes, 0u);
}

TEST(ThreadMemoryPool, ConcurrentRemoteReturnsPreserveLiveBlocksAndReclaimStorage) {
    memory::worker_memory pool;
    constexpr size_t returners = 4;
    constexpr size_t rounds = 16;
    constexpr size_t batch_size = 64;
    constexpr size_t bytes = 256;
    auto* pinned = pool.Allocate(bytes, 16);
    ASSERT_NE(pinned, nullptr);
    std::memset(pinned, 0x5a, bytes);
    const auto pinned_bytes = memory::worker_memory::Describe(bytes, 16).map_bytes;
    std::array<std::array<void*, batch_size>, returners> batches{};
    std::barrier phase(static_cast<std::ptrdiff_t>(returners + 1));
    std::array<std::thread, returners> threads;
    for (size_t index = 0; index < returners; ++index) {
        threads[index] = std::thread([&, index] {
            for (size_t round = 0; round < rounds; ++round) {
                phase.arrive_and_wait();
                for (auto* block : batches[index]) pool.Deallocate(block);
                phase.arrive_and_wait();
            }
        });
    }
    for (size_t round = 0; round < rounds; ++round) {
        for (auto& batch : batches) {
            for (auto& block : batch) {
                block = pool.Allocate(bytes, 16);
                EXPECT_NE(block, nullptr);
            }
        }
        // First drain an empty queue, then race local borrowing with remote returns.
        pool.PurgeIdle();
        phase.arrive_and_wait();
        for (size_t index = 0; index < batch_size; ++index) {
            auto* local = pool.Allocate(bytes, 16);
            EXPECT_NE(local, nullptr);
            if (local) std::memset(local, 0xa5, bytes);
            pool.Deallocate(local);
        }
        phase.arrive_and_wait();
        pool.PurgeIdle();
        EXPECT_TRUE(Intact(pinned, bytes, 0x5a));
        EXPECT_EQ(pool.GetFootprint().mapped_bytes, pinned_bytes);
        EXPECT_EQ(pool.GetFootprint().idle_bytes, 0u);
    }
    for (auto& thread : threads) thread.join();
    pool.Deallocate(pinned);
    pool.PurgeIdle();
    EXPECT_EQ(pool.GetFootprint().mapped_bytes, 0u);
}
