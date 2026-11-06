#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/session.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <thread>
#include <vector>
#include <cstdlib>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using namespace acpp::memory;
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
    using acpp::buf::Buffer;
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

private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
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
            acpp::session::Context ctx;
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
        acpp::buf::MultiBuffer buffers;
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
            acpp::buf::BufferGuard buffer(acpp::buf::Buffer::New());
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
        acpp::buf::Buffer* buffer;
        { ScopedAllocationDomain lease(first); buffer = acpp::buf::Buffer::New(); }
        ScopedAllocationDomain wrong(second);
        acpp::buf::Buffer::Free(buffer);
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
    acpp::buf::Buffer* buffer;
    ThreadLocalVector<int>* vector;
    ThreadLocalVector<int>* empty;
    ThreadLocalDeque<int>* empty_queue;
    {
        ScopedAllocationDomain lease(*first);
        buffer = acpp::buf::Buffer::New();
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
            acpp::buf::Buffer::Free(buffer);
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
            nested_deque = nested_deque;
            intact = intact && nested_deque.size() == 1 &&
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

int main() {
    bool worker = false;
    std::thread thread([&] { worker = RunAll(); });
    thread.join();
    const bool main = RunAll();
    std::printf("unified pool layout/ownership/reuse/purge: %s\n", worker && main ? "PASS" : "FAIL");
    return worker && main ? 0 : 1;
}
