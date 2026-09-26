#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <thread>
#include <vector>

namespace {
using namespace acpp::memory;
using Pool = ReturningThreadPool;
using namespace std::chrono_literals;

bool Intact(void* p, size_t bytes, uint8_t pattern) {
    const auto* data = static_cast<const uint8_t*>(p);
    for (size_t i = 0; i < bytes; ++i) if (data[i] != pattern) return false;
    return true;
}

bool RunBoundaries() {
    Pool pool;
    for (size_t bytes = 0; bytes <= kThreadPoolMaxClass + 32; ++bytes) {
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
    if (Pool::Describe(224, 8).slot_bytes != 256 ||
        Pool::Describe(632, 8).slot_bytes != 704 ||
        Pool::Describe(8296, 8).slot_bytes != 8448 ||
        Pool::Describe(17408, 8).slot_bytes != 17664) return false;
    size_t last_stride = 0;
    for (size_t bytes = 1; bytes <= kThreadPoolMaxClass - 32; ++bytes) {
        const auto layout = Pool::Describe(bytes, 8, 4);
        if (layout.slot_bytes == last_stride) continue;
        last_stride = layout.slot_bytes;
        Pool pool;
        std::vector<void*> blocks;
        size_t expected_maps = 0;
        for (size_t depth = 0; depth < 5; ++depth) {
            const auto tier = Pool::Describe(bytes, 16, depth);
            if (!tier.slots || tier.direct || tier.map_bytes % kAllocationPageBytes ||
                tier.slot_bytes % 16 || tier.map_bytes > std::max(kAllocationPageBytes, kThreadPoolTargetBytes))
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
        if (pool.GetFootprint().mapped_bytes > 8 * kThreadPoolTargetBytes) return false;
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
    void* reused = pool.Allocate(608, 16);
    if (reused != first) return false;
    std::memset(reused, 0xa5, 608);
    pool.Deallocate(reused);
    void* larger = pool.Allocate(609, 8);
    if (!larger || larger == first) return false;
    std::memset(larger, 0xa7, 609);
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
    constexpr size_t bytes = 17408;
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
    std::this_thread::sleep_for(kThreadPoolPurgeDelay + 5ms);
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
    int wakeups = 0;
    if (!pool.BindIdleWakeup(&wakeups, [](void* owner) noexcept { ++*static_cast<int*>(owner); })) return false;
    int other = 0;
    if (pool.BindIdleWakeup(&other, [](void*) noexcept {})) return false;
    std::array<void*, 3> blocks{};
    constexpr std::array<size_t, 3> sizes{64, 256, 8192};
    size_t idle_bytes = 0;
    for (size_t i = 0; i < 3; ++i) {
        blocks[i] = pool.Allocate(sizes[i], 16);
        if (!blocks[i]) return false;
        idle_bytes += Pool::Describe(sizes[i], 16).map_bytes;
    }
    for (auto* p : blocks) pool.Deallocate(p);
    if (wakeups != 1 || pool.GetFootprint().idle_bytes != idle_bytes) return false;
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
    std::this_thread::sleep_until(pool.NextPurgeDeadline() + kThreadPoolPurgeDelay);
    pool.Purge();
    if (pool.GetFootprint().chunks || pool.GetFootprint().idle_bytes) return false;
    pool.UnbindIdleWakeup(&wakeups);
    // A scheduling-OOM fallback may immediately destroy the just-freed chunk.
    if (!pool.BindIdleWakeup(&pool, [](void* p) noexcept { static_cast<Pool*>(p)->PurgeIdle(); })) return false;
    void* p = pool.Allocate(256, 16);
    if (!p) return false;
    pool.Deallocate(p);
    return !pool.GetFootprint().mapped_bytes;
}

bool RunOwnershipAndPmr() {
    auto& pool = ThreadPool();
    pool.PurgeIdle();
    void* p = AllocatePmr(8192, 16);
    if (!p) return false;
    std::memset(p, 0xa5, 8192);
    const auto before = pool.GetFootprint().mapped_bytes;
    const auto rejects = CrossThreadFreeCount();
    std::thread wrong([p] { DeallocatePmr(p); });
    wrong.join();
    if (CrossThreadFreeCount() != rejects + 1 || pool.GetFootprint().mapped_bytes != before ||
        !Intact(p, 8192, 0xa5)) return false;
    Pool foreign;
    foreign.Deallocate(p);
    if (pool.GetFootprint().mapped_bytes != before) return false;
    DeallocatePmr(p);
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
    auto& pool = ThreadPool();
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

bool RunAll() {
    struct Case { const char* name; bool (*run)(); };
    for (const auto& test : std::array{
        Case{"boundaries/alignment/overflow", RunBoundaries}, Case{"geometry", RunGeometry},
        Case{"fragmented/mixed alignment", RunFragmented}, Case{"mixed lifetime", RunMixed},
        Case{"pinned chunks", RunPinnedChunks}, Case{"idle FIFO", RunIdleQueue},
        Case{"ownership/PMR/OOM", RunOwnershipAndPmr}, Case{"Buffer", RunBuffer}}) {
        if (!test.run()) { std::fprintf(stderr, "pool case failed: %s\n", test.name); return false; }
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
