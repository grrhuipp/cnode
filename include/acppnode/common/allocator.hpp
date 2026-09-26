#pragma once

#include "acppnode/common/memory_stats.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <memory_resource>
#include <new>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#elif defined(_WIN32)
extern "C" {
__declspec(dllimport) void* __stdcall VirtualAlloc(
    void* address, std::size_t size, unsigned long type, unsigned long protect);
__declspec(dllimport) int __stdcall VirtualFree(
    void* address, std::size_t size, unsigned long type);
}
#endif
#if defined(__GLIBC__)
#include <malloc.h>
#endif

namespace acpp::memory {

inline constexpr bool kAllocatorCollects = true;
inline constexpr int kGlibcArenaMax = 2;
inline constexpr int kGlibcTrimThreshold = 64 * 1024;
inline constexpr int kGlibcMmapThreshold = 64 * 1024;
inline constexpr std::size_t kThreadPoolTargetBytes = 64 * 1024;
inline constexpr std::size_t kThreadPoolMaxClass = 32 * 1024;
inline constexpr std::chrono::milliseconds kThreadPoolPurgeDelay{10};

// Initialized before Workers start, then read-only. Windows supported targets
// use 4 KiB committed pages; reservation granularity is not committed memory.
inline const std::size_t kAllocationPageBytes = []() noexcept -> std::size_t {
#if defined(__linux__)
    const long page = ::sysconf(_SC_PAGESIZE);
    if (page > 0 && (page & (page - 1)) == 0)
        return static_cast<std::size_t>(page);
#endif
    return 4096;
}();

inline void DisableTransparentHugePages() noexcept {
#if defined(__linux__) && defined(PR_SET_THP_DISABLE)
    (void)::prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
#endif
}
inline void ConfigureProcessGlibc() noexcept {
#if defined(__GLIBC__)
    (void)::mallopt(M_ARENA_MAX, kGlibcArenaMax);
    (void)::mallopt(M_TRIM_THRESHOLD, kGlibcTrimThreshold);
    (void)::mallopt(M_MMAP_THRESHOLD, kGlibcMmapThreshold);
#endif
}
[[nodiscard]] inline void* OsMap(std::size_t bytes) noexcept {
#if defined(__linux__)
    void* mapped = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return mapped == MAP_FAILED ? nullptr : mapped;
#elif defined(_WIN32)
    return ::VirtualAlloc(nullptr, bytes, 0x1000u | 0x2000u, 0x04u);
#else
    return ::operator new(bytes, std::nothrow);
#endif
}
inline void OsUnmap(void* address, std::size_t bytes) noexcept {
#if defined(__linux__)
    if (address) ::munmap(address, bytes);
#elif defined(_WIN32)
    (void)bytes;
    if (address) ::VirtualFree(address, 0, 0x8000u);
#else
    ::operator delete(address);
    (void)bytes;
#endif
}
[[nodiscard]] inline constexpr std::size_t RoundUp(
    std::size_t value, std::size_t unit) noexcept {
    return (value + unit - 1) & ~(unit - 1);
}

class ReturningThreadPool final : public std::pmr::memory_resource {
public:
    using Clock = std::chrono::steady_clock;
    using IdleWakeup = void (*)(void*) noexcept;
    struct Footprint {
        std::size_t mapped_bytes = 0;
        std::size_t direct_bytes = 0;
        std::size_t idle_bytes = 0;
        std::size_t chunks = 0;
    };
    struct Layout {
        std::size_t slot_bytes = 0;
        std::size_t map_bytes = 0;
        std::size_t slots = 0;
        bool direct = false;
    };

    ReturningThreadPool() = default;
    ReturningThreadPool(const ReturningThreadPool&) = delete;
    ReturningThreadPool& operator=(const ReturningThreadPool&) = delete;
    ~ReturningThreadPool() override {
        for (Chunk* chunk = all_; chunk;) {
            Chunk* next = chunk->all_next;
            OsUnmap(chunk, chunk->map_bytes);
            chunk = next;
        }
    }

    [[nodiscard]] Footprint GetFootprint() const noexcept { return footprint_; }
    void Purge() noexcept {
        if (!idle_head_) return;
        const auto now = Clock::now();
        while (idle_head_ && now - idle_head_->idle_at >= kThreadPoolPurgeDelay)
            ReleaseChunk(*idle_head_);
    }
    // Allocation-free fallback if the owning scheduler cannot arm a wakeup.
    void PurgeIdle() noexcept {
        while (idle_head_) ReleaseChunk(*idle_head_);
    }
    [[nodiscard]] Clock::time_point NextPurgeDeadline() const noexcept {
        return idle_head_ ? idle_head_->idle_at + kThreadPoolPurgeDelay
                          : Clock::time_point::max();
    }
    [[nodiscard]] bool BindIdleWakeup(void* owner, IdleWakeup wakeup) noexcept {
        if (wakeup_ && wakeup_owner_ != owner) return false;
        wakeup_owner_ = owner;
        wakeup_ = wakeup;
        if (idle_head_ && wakeup_) wakeup_(wakeup_owner_);
        return true;
    }
    void UnbindIdleWakeup(void* owner) noexcept {
        if (wakeup_owner_ == owner) {
            wakeup_ = nullptr;
            wakeup_owner_ = nullptr;
        }
    }

    // Same geometry used for mappings and layout regression tests. Depth is
    // the number of extant chunks in this class, not an allocation counter.
    [[nodiscard]] static Layout Describe(
        std::size_t bytes, std::size_t alignment, std::size_t depth = 0) noexcept {
        if (!ValidAlignment(alignment)) return {};
        bytes = std::max(bytes, std::size_t{1});
        if (alignment > kSlotAlignment || bytes > kThreadPoolMaxClass - sizeof(SlotHeader)) {
            alignment = std::max(alignment, kSlotAlignment);
            constexpr auto limit = std::numeric_limits<std::size_t>::max();
            const auto overhead = sizeof(Chunk) + sizeof(SlotHeader);
            if (alignment - 1 > limit - overhead ||
                bytes > limit - overhead - (alignment - 1)) return {};
            const auto needed = overhead + alignment - 1 + bytes;
            if (needed > limit - (kAllocationPageBytes - 1)) return {};
            return {bytes, RoundUp(needed, kAllocationPageBytes), 1, true};
        }
        return PooledLayout(Stride(bytes), depth);
    }

    [[nodiscard]] void* Allocate(std::size_t bytes, std::size_t alignment) noexcept {
        if (!ValidAlignment(alignment)) return nullptr;
        bytes = std::max(bytes, std::size_t{1});
        Purge();
        if (alignment > kSlotAlignment || bytes > kThreadPoolMaxClass - sizeof(SlotHeader))
            return AllocateDirect(bytes, alignment);
        const auto stride = Stride(bytes);
        auto& cls = classes_[ClassIndex(stride)];
        if (Chunk* chunk = cls.recyclable) {
            auto* node = chunk->free_head;
            chunk->free_head = node->next_free;
            if (!chunk->free_head) UnlinkRecyclable(*chunk);
            ++chunk->live;
            return node + 1;
        }
        if (cls.current && CanCarve(*cls.current)) return Carve(*cls.current);
        if (cls.idle) {
            cls.current = cls.idle;
            return Carve(*cls.current);
        }
        auto* chunk = MapRegion(PooledLayout(stride, cls.chunks), ClassIndex(stride));
        if (!chunk) return nullptr;
        ++cls.chunks;
        cls.current = chunk;
        return Carve(*chunk);
    }

    void Deallocate(void* pointer, std::size_t bytes = 0,
                    std::size_t alignment = 0) noexcept {
        if (!pointer) return;
        auto* header = reinterpret_cast<SlotHeader*>(pointer) - 1;
        // Check the immutable slot owner before touching any foreign pool state.
        if (header->owner != std::this_thread::get_id()) {
            OnCrossThreadFree();
            return;
        }
        auto* chunk = header->chunk;
        if (!chunk || chunk->pool != this || chunk->live == 0 ||
            bytes > header->capacity ||
            (alignment && (!ValidAlignment(alignment) ||
             reinterpret_cast<std::uintptr_t>(pointer) % alignment != 0))) return;
        --chunk->live;
        if (chunk->live == 0) {
            if (chunk->direct) {
                ReleaseChunk(*chunk);
            } else {
                UnlinkRecyclable(*chunk);
                chunk->free_head = nullptr;
                chunk->bump = reinterpret_cast<std::byte*>(chunk) + ChunkLead();
                const bool first_idle = idle_head_ == nullptr;
                MarkIdle(*chunk);
                Purge();
                // The callback may purge this mapping on scheduling failure.
                // Never access chunk after notifying; no per-free callback chain.
                if (first_idle && wakeup_) wakeup_(wakeup_owner_);
            }
            return;
        }
        header->next_free = chunk->free_head;
        chunk->free_head = header;
        if (!chunk->in_recyclable) {
            auto& cls = classes_[chunk->class_index];
            chunk->in_recyclable = true;
            chunk->rec_next = cls.recyclable;
            if (chunk->rec_next) chunk->rec_next->rec_prev = chunk;
            cls.recyclable = chunk;
        }
    }

protected:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
        if (void* pointer = Allocate(bytes, alignment)) return pointer;
        throw std::bad_alloc();
    }
    void do_deallocate(void* p, std::size_t bytes, std::size_t alignment) override {
        Deallocate(p, bytes, alignment);
    }
    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }

private:
    static constexpr std::size_t kSlotAlignment = 16;
    static constexpr std::size_t kClassCount = 25 + (kThreadPoolMaxClass - 1024) / 256;
    struct Chunk;
    struct alignas(kSlotAlignment) SlotHeader {
        Chunk* chunk = nullptr;
        std::thread::id owner{};
        std::size_t capacity = 0;
        SlotHeader* next_free = nullptr;
    };
    struct Chunk {
        ReturningThreadPool* pool = nullptr;
        Chunk* all_next = nullptr;
        Chunk* all_prev = nullptr;
        Chunk* rec_next = nullptr;
        Chunk* rec_prev = nullptr;
        Chunk* idle_next = nullptr;
        Chunk* idle_prev = nullptr;
        Chunk* class_idle_next = nullptr;
        Chunk* class_idle_prev = nullptr;
        std::size_t map_bytes = 0;
        std::size_t stride = 0;
        std::size_t class_index = 0;
        std::size_t live = 0;
        Clock::time_point idle_at{};
        SlotHeader* free_head = nullptr;
        std::byte* bump = nullptr;
        std::byte* end = nullptr;
        bool direct = false;
        bool idle = false;
        bool in_recyclable = false;
    };
    struct Class {
        Chunk* current = nullptr;
        Chunk* recyclable = nullptr;
        Chunk* idle = nullptr;
        std::size_t chunks = 0;
    };
    [[nodiscard]] static bool ValidAlignment(std::size_t alignment) noexcept {
        return alignment && (alignment & (alignment - 1)) == 0;
    }
    [[nodiscard]] static constexpr std::size_t ChunkLead() noexcept {
        return RoundUp(sizeof(Chunk), kSlotAlignment);
    }
    [[nodiscard]] static std::size_t Stride(std::size_t bytes) noexcept {
        const auto required = std::max(std::size_t{64}, bytes + sizeof(SlotHeader));
        return RoundUp(required, required <= 256 ? 16 : required <= 1024 ? 64 : 256);
    }
    [[nodiscard]] static std::size_t ClassIndex(std::size_t stride) noexcept {
        if (stride <= 256) return (stride - 64) / 16;
        if (stride <= 1024) return 13 + (stride - 320) / 64;
        return 25 + (stride - 1280) / 256;
    }
    [[nodiscard]] static Layout PooledLayout(std::size_t stride, std::size_t depth) noexcept {
        // Sparse classes start at one page. Busy classes grow to a 64 KiB
        // budget. Select the best packing within that budget, not one chunk
        // constant for every class. Only a mapping miss runs this bounded search.
        const auto page = kAllocationPageBytes;
        const auto target = std::max(page, kThreadPoolTargetBytes);
        const auto pages = std::min(std::size_t{1} << std::min(depth, std::size_t{4}), target / page);
        Layout best{stride, RoundUp(ChunkLead() + stride, page), 1, false};
        for (std::size_t n = 1; n <= pages; ++n) {
            const auto map_bytes = n * page;
            if (map_bytes < ChunkLead() + stride) continue;
            const auto slots = (map_bytes - ChunkLead()) / stride;
            if (map_bytes * best.slots < best.map_bytes * slots)
                best = {stride, map_bytes, slots, false};
        }
        return best;
    }
    [[nodiscard]] static bool CanCarve(const Chunk& chunk) noexcept {
        return static_cast<std::size_t>(chunk.end - chunk.bump) >= chunk.stride;
    }
    [[nodiscard]] void* Carve(Chunk& chunk) noexcept {
        auto* header = new (chunk.bump) SlotHeader{
            &chunk, std::this_thread::get_id(), chunk.stride - sizeof(SlotHeader)};
        chunk.bump += chunk.stride;
        if (chunk.idle) MarkUsed(chunk);
        ++chunk.live;
        return header + 1;
    }
    [[nodiscard]] void* AllocateDirect(std::size_t bytes, std::size_t alignment) noexcept {
        const auto layout = Describe(bytes, alignment);
        if (!layout.slots) return nullptr;
        auto* chunk = MapRegion(layout, 0);
        if (!chunk) return nullptr;
        const auto address = RoundUp(reinterpret_cast<std::uintptr_t>(chunk) +
            sizeof(Chunk) + sizeof(SlotHeader), std::max(alignment, kSlotAlignment));
        auto* header = new (reinterpret_cast<SlotHeader*>(address) - 1) SlotHeader{
            chunk, std::this_thread::get_id(), bytes};
        chunk->live = 1;
        return header + 1;
    }
    [[nodiscard]] Chunk* MapRegion(Layout layout, std::size_t class_index) noexcept {
        void* mapped = OsMap(layout.map_bytes);
        if (!mapped) return nullptr;
        auto* chunk = new (mapped) Chunk;
        chunk->pool = this;
        chunk->map_bytes = layout.map_bytes;
        chunk->stride = layout.slot_bytes;
        chunk->class_index = class_index;
        chunk->direct = layout.direct;
        chunk->bump = static_cast<std::byte*>(mapped) + ChunkLead();
        chunk->end = static_cast<std::byte*>(mapped) + layout.map_bytes;
        footprint_.mapped_bytes += layout.map_bytes;
        footprint_.direct_bytes += layout.direct ? layout.map_bytes : 0;
        ++footprint_.chunks;
        chunk->all_next = all_;
        if (all_) all_->all_prev = chunk;
        all_ = chunk;
        return chunk;
    }
    void ReleaseChunk(Chunk& chunk) noexcept {
        if (!chunk.direct) {
            auto& cls = classes_[chunk.class_index];
            if (cls.current == &chunk) cls.current = nullptr;
            UnlinkRecyclable(chunk);
            MarkUsed(chunk);
            --cls.chunks;
        }
        if (chunk.all_prev) chunk.all_prev->all_next = chunk.all_next;
        else all_ = chunk.all_next;
        if (chunk.all_next) chunk.all_next->all_prev = chunk.all_prev;
        footprint_.mapped_bytes -= chunk.map_bytes;
        footprint_.direct_bytes -= chunk.direct ? chunk.map_bytes : 0;
        --footprint_.chunks;
        const auto bytes = chunk.map_bytes;
        chunk.~Chunk();
        OsUnmap(&chunk, bytes);
    }
    void MarkIdle(Chunk& chunk) noexcept {
        chunk.idle = true;
        footprint_.idle_bytes += chunk.map_bytes;
        chunk.idle_at = Clock::now();
        chunk.idle_prev = idle_tail_;
        if (idle_tail_) idle_tail_->idle_next = &chunk;
        else idle_head_ = &chunk;
        idle_tail_ = &chunk;
        auto& cls = classes_[chunk.class_index];
        chunk.class_idle_next = cls.idle;
        if (cls.idle) cls.idle->class_idle_prev = &chunk;
        cls.idle = &chunk;
    }
    void MarkUsed(Chunk& chunk) noexcept {
        if (!chunk.idle) return;
        chunk.idle = false;
        footprint_.idle_bytes -= chunk.map_bytes;
        if (chunk.idle_prev) chunk.idle_prev->idle_next = chunk.idle_next;
        else idle_head_ = chunk.idle_next;
        if (chunk.idle_next) chunk.idle_next->idle_prev = chunk.idle_prev;
        else idle_tail_ = chunk.idle_prev;
        if (chunk.class_idle_prev) chunk.class_idle_prev->class_idle_next = chunk.class_idle_next;
        else classes_[chunk.class_index].idle = chunk.class_idle_next;
        if (chunk.class_idle_next) chunk.class_idle_next->class_idle_prev = chunk.class_idle_prev;
        chunk.idle_prev = chunk.idle_next = nullptr;
        chunk.class_idle_prev = chunk.class_idle_next = nullptr;
    }
    void UnlinkRecyclable(Chunk& chunk) noexcept {
        if (!chunk.in_recyclable) return;
        if (chunk.rec_prev) chunk.rec_prev->rec_next = chunk.rec_next;
        else classes_[chunk.class_index].recyclable = chunk.rec_next;
        if (chunk.rec_next) chunk.rec_next->rec_prev = chunk.rec_prev;
        chunk.rec_prev = chunk.rec_next = nullptr;
        chunk.in_recyclable = false;
    }

    std::array<Class, kClassCount> classes_{};
    Chunk* all_ = nullptr;
    Chunk* idle_head_ = nullptr;
    Chunk* idle_tail_ = nullptr;
    Footprint footprint_{};
    IdleWakeup wakeup_ = nullptr;
    void* wakeup_owner_ = nullptr;
};

[[nodiscard]] inline ReturningThreadPool& ThreadPool() noexcept {
    thread_local ReturningThreadPool pool;
    return pool;
}
#ifdef CNODE_TEST_ALLOCATOR_FAULT
inline thread_local bool reject_next_pmr_allocation = false;
inline thread_local size_t rejected_pmr_allocations = 0;
#endif
[[nodiscard]] inline void* AllocatePmr(
    size_t size, size_t alignment = alignof(std::max_align_t)) noexcept {
#ifdef CNODE_TEST_ALLOCATOR_FAULT
    if (reject_next_pmr_allocation) {
        reject_next_pmr_allocation = false;
        ++rejected_pmr_allocations;
        return nullptr;
    }
#endif
    return ThreadPool().Allocate(size, alignment);
}
inline void DeallocatePmr(void* p, size_t size = 0,
                          size_t alignment = 0) noexcept {
    if (p) ThreadPool().Deallocate(p, size, alignment);
}

// Objects created and destroyed on the same Worker thread only.
struct ThreadAllocated {
    static void* operator new(std::size_t size) {
        if (void* p = AllocatePmr(size)) return p;
        throw std::bad_alloc();
    }
    static void* operator new(std::size_t size, std::align_val_t alignment) {
        if (void* p = AllocatePmr(size, static_cast<std::size_t>(alignment))) return p;
        throw std::bad_alloc();
    }
    static void operator delete(void* p) noexcept { DeallocatePmr(p); }
    static void operator delete(void* p, std::size_t) noexcept { DeallocatePmr(p); }
    static void operator delete(void* p, std::align_val_t) noexcept { DeallocatePmr(p); }
    static void operator delete(void* p, std::size_t, std::align_val_t) noexcept { DeallocatePmr(p); }
};

// The process default resource routes to the calling thread; it never stores
// a Worker pool pointer. Control/data ownership rules remain with callers.
class ThreadPoolFacade final : public std::pmr::memory_resource {
protected:
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (void* p = AllocatePmr(bytes, alignment)) return p;
        throw std::bad_alloc();
    }
    void do_deallocate(void* p, size_t bytes, size_t alignment) override {
        DeallocatePmr(p, bytes, alignment);
    }
    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};
extern "C" void cnode_set_tls_buffer_allocator(
    void* (*alloc_fn)(std::size_t), void (*free_fn)(void*));
inline void* AllocateTlsReadWriteBuffer(std::size_t size) { return AllocatePmr(size); }
inline void FreeTlsReadWriteBuffer(void* p) { DeallocatePmr(p); }
inline void ConfigureProcessAllocator() noexcept {
    DisableTransparentHugePages();
    ConfigureProcessGlibc();
    cnode_set_tls_buffer_allocator(&AllocateTlsReadWriteBuffer, &FreeTlsReadWriteBuffer);
    static ThreadPoolFacade default_resource;
    std::pmr::set_default_resource(&default_resource);
}
inline void CollectSteady() noexcept {
    ThreadPool().Purge();
#if defined(__GLIBC__)
    (void)::malloc_trim(0);
#endif
}
inline void CollectBurst() noexcept {
    ThreadPool().Purge();
#if defined(__GLIBC__)
    (void)::malloc_trim(0);
#endif
}
template <class T>
using ThreadLocalAllocator = std::pmr::polymorphic_allocator<T>;
template <class T, class... Args>
[[nodiscard]] std::shared_ptr<T> AllocateShared(Args&&... args) {
    return std::allocate_shared<T>(ThreadLocalAllocator<T>{}, std::forward<Args>(args)...);
}
template <class T> using ThreadLocalVector = std::pmr::vector<T>;
template <class T> using ThreadLocalDeque = std::pmr::deque<T>;
template <class T> using ThreadLocalList = std::pmr::list<T>;
template <class Key, class Value, class Compare = std::less<Key>>
using ThreadLocalMap = std::pmr::map<Key, Value, Compare>;
template <class Key, class Value, class Hash = std::hash<Key>, class Eq = std::equal_to<Key>>
using ThreadLocalUnorderedMap = std::pmr::unordered_map<Key, Value, Hash, Eq>;
template <class Key, class Hash = std::hash<Key>, class Eq = std::equal_to<Key>>
using ThreadLocalUnorderedSet = std::pmr::unordered_set<Key, Hash, Eq>;
using ThreadLocalString = std::pmr::string;
using ByteVector = ThreadLocalVector<uint8_t>;

} // namespace acpp::memory
