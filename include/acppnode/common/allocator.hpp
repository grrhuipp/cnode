#pragma once

#include "acppnode/common/memory_stats.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <atomic>
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
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <sys/prctl.h>
#include <unistd.h>
#if defined(CNODE_USE_MIMALLOC) && !defined(__SANITIZE_ADDRESS__)
#include <mimalloc.h>
#endif

namespace acpp::memory {

inline constexpr std::size_t kThreadMemoryPoolTargetBytes = 64 * 1024;
inline constexpr std::size_t kThreadMemoryPoolMaxClass = 16 * 1024;
inline constexpr std::size_t kLargeBlockGranularity = 4 * 1024;
inline constexpr std::size_t kMaxCachedBlockBytes = 1024 * 1024;
inline constexpr std::size_t kMaxCachedBlockAlignment = 64;
inline constexpr std::size_t request_arena_initial_bytes = std::size_t{4} * 1024;
inline constexpr std::size_t default_retained_block_bytes = std::size_t{8} * 1024 * 1024;
inline constexpr std::size_t max_retained_block_bytes = static_cast<std::size_t>(PTRDIFF_MAX);
inline constexpr std::chrono::milliseconds kThreadMemoryPoolPurgeDelay{10};

inline const std::size_t kAllocationPageBytes = []() noexcept -> std::size_t {
    const long page = ::sysconf(_SC_PAGESIZE);
    if (page > 0 && (page & (page - 1)) == 0)
        return static_cast<std::size_t>(page);
    return 4096;
}();

inline void DisableTransparentHugePages() noexcept {
    (void)::prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
}

[[nodiscard]] inline constexpr bool ValidAlignment(std::size_t alignment) noexcept {
    return alignment != 0 && (alignment & (alignment - 1)) == 0;
}
[[nodiscard]] inline constexpr std::size_t RoundUp(
    std::size_t value, std::size_t unit) noexcept {
    return (value + unit - 1) & ~(unit - 1);
}

class AllocationDomain;

#ifdef CNODE_TEST_ALLOCATOR_FAULT
inline thread_local bool reject_next_process_allocation = false;
inline thread_local size_t rejected_process_allocations = 0;
#endif

namespace detail {
inline thread_local AllocationDomain* current_allocation_domain = nullptr;

[[nodiscard]] inline std::uintptr_t CurrentThreadToken() noexcept {
    thread_local std::uint8_t anchor = 0;
    return reinterpret_cast<std::uintptr_t>(&anchor);
}


[[nodiscard]] inline void* AllocateProcessRaw(std::size_t bytes_value, std::size_t alignment) {
#ifdef CNODE_TEST_ALLOCATOR_FAULT
    if (reject_next_process_allocation) {
        reject_next_process_allocation = false;
        ++rejected_process_allocations;
        throw std::bad_alloc();
    }
#endif
    if (!ValidAlignment(alignment)) {
        throw std::bad_alloc();
    }
    const std::size_t actual_bytes = bytes_value == 0 ? 1 : bytes_value;
#if defined(CNODE_USE_MIMALLOC) && !defined(__SANITIZE_ADDRESS__)
    if (void* block = mi_malloc_aligned(actual_bytes, alignment)) {
        return block;
    }
    throw std::bad_alloc();
#else
    return std::pmr::new_delete_resource()->allocate(actual_bytes, alignment);
#endif
}

inline void DeallocateProcessRaw(
    void* block, std::size_t bytes_value, std::size_t alignment) noexcept {
    if (!block) return;
#if defined(CNODE_USE_MIMALLOC) && !defined(__SANITIZE_ADDRESS__)
    if (bytes_value != 0 && ValidAlignment(alignment)) {
        mi_free_size_aligned(block, bytes_value, alignment);
    } else if (bytes_value != 0) {
        mi_free_size(block, bytes_value);
    } else {
        mi_free(block);
    }
#else
    const std::size_t actual_bytes = bytes_value == 0 ? 1 : bytes_value;
    std::pmr::new_delete_resource()->deallocate(
        block, actual_bytes, alignment ? alignment : alignof(std::max_align_t));
#endif
}

class process_memory_resource final : public std::pmr::memory_resource {
private:
    void* do_allocate(std::size_t bytes_value, std::size_t alignment) override {
        return AllocateProcessRaw(bytes_value, alignment);
    }
    void do_deallocate(void* block, std::size_t bytes_value, std::size_t alignment) override {
        DeallocateProcessRaw(block, bytes_value, alignment);
    }
    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

} // namespace detail

// Process-lifetime, thread-safe resource backed by thread-local heaps without a
// shared pooling layer.
[[nodiscard]] inline std::pmr::memory_resource* process_resource() noexcept {
    alignas(detail::process_memory_resource) static std::byte
        storage[sizeof(detail::process_memory_resource)];
    static auto* const resource = ::new (storage) detail::process_memory_resource;
    return resource;
}

struct memory_pool_config {
    std::size_t request_initial_buffer_bytes_{request_arena_initial_bytes};
    std::size_t retained_block_bytes_{default_retained_block_bytes};
};

inline void validate_memory_pool_config(const memory_pool_config& config) {
    if (config.request_initial_buffer_bytes_ == 0) {
        throw std::invalid_argument(
            "memory pool request initial buffer size must be greater than zero");
    }
    if (config.retained_block_bytes_ > max_retained_block_bytes) {
        throw std::invalid_argument(
            "memory pool retained block bytes exceed the addressable maximum");
    }
}

// Two-tier Worker-local memory pool:
// - Tier 1 (<= 16 KiB): size-class slabs with baseline 16-byte slot alignment.
// - Tier 2 (16 KiB < size <= 1 MiB, alignment <= 64): 4 KiB-rounded LIFO block
//   cache bounded by retained_block_bytes_.
// - Larger or over-aligned blocks pass straight through to upstream_.
class worker_memory final : public std::pmr::memory_resource {
public:
    using Clock = std::chrono::steady_clock;

    class IdleWakeup {
    protected:
        IdleWakeup() = default;
        ~IdleWakeup() = default;
        virtual void OnPoolIdle() noexcept = 0;
    private:
        friend class worker_memory;
    };

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

    explicit worker_memory(const memory_pool_config& config = {})
        : worker_memory(*process_resource(), config) {}

    explicit worker_memory(std::pmr::memory_resource& upstream,
                           const memory_pool_config& config = {})
        : upstream_((validate_memory_pool_config(config), &upstream))
        , request_initial_buffer_bytes_(config.request_initial_buffer_bytes_)
        , retained_block_bytes_(config.retained_block_bytes_) {}

    worker_memory(const worker_memory&) = delete;
    worker_memory& operator=(const worker_memory&) = delete;
    worker_memory(std::pmr::memory_resource& upstream,
                  const memory_pool_config& config, bool domain_private)
        : worker_memory(upstream, config) {
        domain_private_ = domain_private;
    }

    void RequireLease() const noexcept;
    [[nodiscard]] std::shared_ptr<worker_memory> Lifetime() const noexcept {
        return lifetime_.lock();
    }
    [[nodiscard]] std::size_t OutstandingAllocations() const noexcept {
        RequireLease();
        return live_allocations_;
    }

    [[nodiscard]] static worker_memory& OwnerOf(const void* pointer) noexcept {
        return *(reinterpret_cast<const SlotHeader*>(pointer) - 1)->chunk->pool;
    }


    ~worker_memory() override {
        if (live_allocations_ != 0) std::terminate();
        while (all_) {
            ReleaseChunk(*all_);
        }
    }

    [[nodiscard]] Footprint GetFootprint() const noexcept {
        RequireLease();
        return footprint_;
    }

    void Purge() noexcept {
        RequireLease();
        if (!idle_head_) return;
        const auto now = Clock::now();
        while (idle_head_ && now - idle_head_->idle_at >= kThreadMemoryPoolPurgeDelay) {
            ReleaseChunk(*idle_head_);
        }
    }

    void PurgeIdle() noexcept {
        RequireLease();
        while (idle_head_) {
            ReleaseChunk(*idle_head_);
        }
    }

    [[nodiscard]] Clock::time_point NextPurgeDeadline() const noexcept {
        RequireLease();
        return idle_head_ ? idle_head_->idle_at + kThreadMemoryPoolPurgeDelay
                          : Clock::time_point::max();
    }

    [[nodiscard]] bool BindIdleWakeup(IdleWakeup& owner) noexcept {
        RequireLease();
        if (wakeup_ && wakeup_ != &owner) return false;
        wakeup_ = &owner;
        if (idle_head_) wakeup_->OnPoolIdle();
        return true;
    }

    void UnbindIdleWakeup(IdleWakeup& owner) noexcept {
        RequireLease();
        if (wakeup_ == &owner) wakeup_ = nullptr;
    }

    template <typename t_type = std::byte>
    [[nodiscard]] std::pmr::polymorphic_allocator<t_type> allocator() & noexcept {
        return std::pmr::polymorphic_allocator<t_type>(this);
    }
    template <typename t_type = std::byte>
    [[nodiscard]] std::pmr::polymorphic_allocator<t_type> allocator() && = delete;

    [[nodiscard]] std::pmr::memory_resource* resource() & noexcept { return this; }
    [[nodiscard]] std::pmr::memory_resource* resource() const& noexcept {
        return const_cast<worker_memory*>(this);
    }
    [[nodiscard]] std::pmr::memory_resource* resource() && = delete;
    [[nodiscard]] std::pmr::memory_resource* resource() const&& = delete;

    [[nodiscard]] std::size_t request_initial_buffer_bytes() const noexcept {
        return request_initial_buffer_bytes_;
    }

    [[nodiscard]] static Layout Describe(
        std::size_t bytes, std::size_t alignment, std::size_t depth = 0) noexcept {
        if (!ValidAlignment(alignment)) return {};
        bytes = std::max(bytes, std::size_t{1});
        if (alignment > kSlotAlignment || bytes > kThreadMemoryPoolMaxClass - sizeof(SlotHeader)) {
            const bool cacheable =
                alignment <= kMaxCachedBlockAlignment && bytes <= kMaxCachedBlockBytes;
            const std::size_t payload_bytes =
                cacheable ? RoundUp(bytes, kLargeBlockGranularity) : bytes;
            alignment = std::max(alignment, kSlotAlignment);
            constexpr auto limit = std::numeric_limits<std::size_t>::max();
            const auto overhead = sizeof(Chunk) + sizeof(SlotHeader);
            if (alignment - 1 > limit - overhead ||
                payload_bytes > limit - overhead - (alignment - 1)) return {};
            const auto needed = overhead + alignment - 1 + payload_bytes;
            if (needed > limit - (kAllocationPageBytes - 1)) return {};
            return {payload_bytes, RoundUp(needed, kAllocationPageBytes), 1, !cacheable};
        }
        return PooledLayout(Stride(bytes), depth);
    }

    [[nodiscard]] void* Allocate(std::size_t bytes, std::size_t alignment) noexcept {
        RequireLease();
        void* pointer = AllocateImpl(bytes, alignment);
        if (pointer && domain_private_ && live_allocations_++ == 0)
            live_lifetime_ = lifetime_.lock();
        return pointer;
    }

private:
    [[nodiscard]] void* AllocateImpl(std::size_t bytes, std::size_t alignment) noexcept {
        if (!ValidAlignment(alignment)) return nullptr;
        bytes = std::max(bytes, std::size_t{1});
        if (alignment > kSlotAlignment || bytes > kThreadMemoryPoolMaxClass - sizeof(SlotHeader)) {
            if (alignment <= kMaxCachedBlockAlignment && bytes <= kMaxCachedBlockBytes) {
                return AllocateLargeCached(bytes, alignment);
            }
            return AllocateDirect(bytes, alignment);
        }
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
        auto* chunk = MapRegion(
            PooledLayout(stride, cls.chunks), ClassIndex(stride), kSlotAlignment, false);
        if (!chunk) return nullptr;
        ++cls.chunks;
        cls.current = chunk;
        return Carve(*chunk);
    }

public:
    void Deallocate(void* pointer, std::size_t bytes = 0,
                    std::size_t alignment = 0) noexcept {
        if (!pointer) return;
        RequireLease();
        auto* header = reinterpret_cast<SlotHeader*>(pointer) - 1;
        auto* chunk = header->chunk;
        if (!chunk) return;
        chunk->pool->RequireLease();
        if (!domain_private_ && chunk->owner != detail::CurrentThreadToken()) {
            OnCrossThreadFree();
            return;
        }
        if (chunk->pool != this || chunk->live == 0 ||
            bytes > chunk->slot_capacity ||
            (alignment && (!ValidAlignment(alignment) ||
             reinterpret_cast<std::uintptr_t>(pointer) % alignment != 0))) return;
        // Detach the self-reference only after the final allocation is
        // returned; this local keeps the pool alive through all bookkeeping.
        std::shared_ptr<worker_memory> retiring;
        if (domain_private_ && --live_allocations_ == 0)
            retiring = std::move(live_lifetime_);
        --chunk->live;
        if (chunk->live == 0) {
            if (chunk->direct) {
                ReleaseChunk(*chunk);
            } else if (chunk->large_cached) {
                if (chunk->stride > retained_block_bytes_ - cached_large_bytes_) {
                    ReleaseChunk(*chunk);
                } else {
                    const bool first_idle = idle_head_ == nullptr;
                    MarkLargeIdle(*chunk);
                    if (!first_idle) Purge();
                    if (first_idle && wakeup_) wakeup_->OnPoolIdle();
                }
            } else {
                auto& cls = classes_[chunk->class_index];
                if (cls.current == chunk) cls.current = nullptr;
                UnlinkRecyclable(*chunk);
                chunk->free_head = nullptr;
                chunk->bump = reinterpret_cast<std::byte*>(chunk) + ChunkLead();
                const bool first_idle = idle_head_ == nullptr;
                MarkIdle(*chunk);
                if (!first_idle) Purge();
                if (first_idle && wakeup_) wakeup_->OnPoolIdle();
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
    static constexpr std::size_t kClassCount = 25 + (kThreadMemoryPoolMaxClass - 1024) / 256;
    static constexpr std::size_t kLargeBinCount =
        kMaxCachedBlockBytes / kLargeBlockGranularity;

    struct Chunk;
    struct alignas(kSlotAlignment) SlotHeader {
        Chunk* chunk = nullptr;
        SlotHeader* next_free = nullptr;
    };
    struct Chunk {
        worker_memory* pool = nullptr;
        std::uintptr_t owner = 0;
        Chunk* all_next = nullptr;
        Chunk* all_prev = nullptr;
        Chunk* rec_next = nullptr;
        Chunk* rec_prev = nullptr;
        Chunk* idle_next = nullptr;
        Chunk* idle_prev = nullptr;
        Chunk* class_idle_next = nullptr;
        Chunk* class_idle_prev = nullptr;
        std::size_t map_bytes = 0;
        std::size_t map_alignment = kSlotAlignment;
        std::size_t stride = 0;
        std::size_t slot_capacity = 0;
        std::size_t class_index = 0;
        std::size_t live = 0;
        Clock::time_point idle_at{};
        SlotHeader* free_head = nullptr;
        void* large_user_ptr = nullptr;
        std::byte* bump = nullptr;
        std::byte* end = nullptr;
        bool direct = false;
        bool large_cached = false;
        bool idle = false;
        bool in_recyclable = false;
    };
    struct Class {
        Chunk* current = nullptr;
        Chunk* recyclable = nullptr;
        Chunk* idle = nullptr;
        std::size_t chunks = 0;
    };

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
    [[nodiscard]] static constexpr std::size_t LargeBinIndex(std::size_t class_bytes) noexcept {
        return class_bytes / kLargeBlockGranularity - 1;
    }
    [[nodiscard]] static Layout PooledLayout(std::size_t stride, std::size_t depth) noexcept {
        const auto page = kAllocationPageBytes;
        const auto target = std::max(page, kThreadMemoryPoolTargetBytes);
        const auto min_pages = RoundUp(ChunkLead() + stride, page) / page;
        const auto max_pages = std::max(
            min_pages,
            std::min(min_pages << std::min(depth, std::size_t{4}), target / page));
        Layout best{
            stride,
            min_pages * page,
            (min_pages * page - ChunkLead()) / stride,
            false};
        for (std::size_t n = min_pages; n <= max_pages; ++n) {
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
        auto* header = ::new (chunk.bump) SlotHeader{&chunk, nullptr};
        chunk.bump += chunk.stride;
        if (chunk.idle) MarkUsed(chunk);
        ++chunk.live;
        return header + 1;
    }
    [[nodiscard]] void* AllocateLargeCached(
        std::size_t bytes, std::size_t alignment) noexcept {
        const std::size_t class_bytes = RoundUp(bytes, kLargeBlockGranularity);
        const std::size_t bin = LargeBinIndex(class_bytes);
        const std::size_t eff_align = std::max(alignment, kSlotAlignment);
        for (Chunk* chunk = large_bins_[bin]; chunk; chunk = chunk->class_idle_next) {
            if (reinterpret_cast<std::uintptr_t>(chunk->large_user_ptr) % eff_align == 0) {
                MarkLargeUsed(*chunk);
                footprint_.direct_bytes += chunk->map_bytes;
                chunk->live = 1;
                return chunk->large_user_ptr;
            }
        }
        const auto layout = Describe(class_bytes, eff_align);
        if (!layout.slots) return nullptr;
        auto* chunk = MapRegion(layout, bin, eff_align, true);
        if (!chunk) return nullptr;
        const auto address = RoundUp(
            reinterpret_cast<std::uintptr_t>(chunk) + sizeof(Chunk) + sizeof(SlotHeader),
            eff_align);
        auto* header = ::new (reinterpret_cast<SlotHeader*>(address) - 1) SlotHeader{
            chunk, nullptr};
        chunk->slot_capacity = class_bytes;
        chunk->large_user_ptr = header + 1;
        chunk->live = 1;
        return chunk->large_user_ptr;
    }
    [[nodiscard]] void* AllocateDirect(
        std::size_t bytes, std::size_t alignment) noexcept {
        const std::size_t eff_align = std::max(alignment, kSlotAlignment);
        const auto layout = Describe(bytes, eff_align);
        if (!layout.slots) return nullptr;
        auto* chunk = MapRegion(layout, 0, eff_align, false);
        if (!chunk) return nullptr;
        const auto address = RoundUp(
            reinterpret_cast<std::uintptr_t>(chunk) + sizeof(Chunk) + sizeof(SlotHeader),
            eff_align);
        auto* header = ::new (reinterpret_cast<SlotHeader*>(address) - 1) SlotHeader{
            chunk, nullptr};
        chunk->slot_capacity = bytes;
        chunk->live = 1;
        return header + 1;
    }
    [[nodiscard]] Chunk* MapRegion(
        Layout layout, std::size_t class_index, std::size_t map_alignment,
        bool large_cached) noexcept {
        void* mapped = nullptr;
        try {
            mapped = upstream_->allocate(layout.map_bytes, map_alignment);
        } catch (...) {
            return nullptr;
        }
        if (!mapped) return nullptr;
        auto* chunk = ::new (mapped) Chunk;
        chunk->pool = this;
        chunk->owner = detail::CurrentThreadToken();
        chunk->map_bytes = layout.map_bytes;
        chunk->map_alignment = map_alignment;
        chunk->stride = layout.slot_bytes;
        chunk->slot_capacity = layout.slot_bytes >= sizeof(SlotHeader)
            ? layout.slot_bytes - sizeof(SlotHeader)
            : 0;
        chunk->class_index = class_index;
        chunk->direct = layout.direct && !large_cached;
        chunk->large_cached = large_cached;
        chunk->bump = static_cast<std::byte*>(mapped) + ChunkLead();
        chunk->end = static_cast<std::byte*>(mapped) + layout.map_bytes;
        footprint_.mapped_bytes += layout.map_bytes;
        footprint_.direct_bytes += (chunk->direct || chunk->large_cached) ? layout.map_bytes : 0;
        ++footprint_.chunks;
        chunk->all_next = all_;
        if (all_) all_->all_prev = chunk;
        all_ = chunk;
        return chunk;
    }
    void ReleaseChunk(Chunk& chunk) noexcept {
        const bool was_idle = chunk.idle;
        if (chunk.large_cached) {
            MarkLargeUsed(chunk);
        } else if (!chunk.direct) {
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
        if (chunk.direct || (chunk.large_cached && !was_idle)) {
            footprint_.direct_bytes -= chunk.map_bytes;
        }
        --footprint_.chunks;
        const auto bytes = chunk.map_bytes;
        const auto alignment = chunk.map_alignment;
        void* raw = &chunk;
        chunk.~Chunk();
        upstream_->deallocate(raw, bytes, alignment);
    }
    void LinkIdleQueue(Chunk& chunk) noexcept {
        chunk.idle = true;
        footprint_.idle_bytes += chunk.map_bytes;
        chunk.idle_at = Clock::now();
        chunk.idle_prev = idle_tail_;
        if (idle_tail_) idle_tail_->idle_next = &chunk;
        else idle_head_ = &chunk;
        idle_tail_ = &chunk;
    }
    void UnlinkIdleQueue(Chunk& chunk) noexcept {
        chunk.idle = false;
        footprint_.idle_bytes -= chunk.map_bytes;
        if (chunk.idle_prev) chunk.idle_prev->idle_next = chunk.idle_next;
        else idle_head_ = chunk.idle_next;
        if (chunk.idle_next) chunk.idle_next->idle_prev = chunk.idle_prev;
        else idle_tail_ = chunk.idle_prev;
        chunk.idle_prev = chunk.idle_next = nullptr;
    }
    void MarkIdle(Chunk& chunk) noexcept {
        LinkIdleQueue(chunk);
        auto& cls = classes_[chunk.class_index];
        chunk.class_idle_next = cls.idle;
        if (cls.idle) cls.idle->class_idle_prev = &chunk;
        cls.idle = &chunk;
    }
    void MarkUsed(Chunk& chunk) noexcept {
        if (!chunk.idle) return;
        UnlinkIdleQueue(chunk);
        if (chunk.class_idle_prev) chunk.class_idle_prev->class_idle_next = chunk.class_idle_next;
        else classes_[chunk.class_index].idle = chunk.class_idle_next;
        if (chunk.class_idle_next) chunk.class_idle_next->class_idle_prev = chunk.class_idle_prev;
        chunk.class_idle_prev = chunk.class_idle_next = nullptr;
    }
    void MarkLargeIdle(Chunk& chunk) noexcept {
        footprint_.direct_bytes -= chunk.map_bytes;
        LinkIdleQueue(chunk);
        cached_large_bytes_ += chunk.stride;
        auto*& head = large_bins_[chunk.class_index];
        chunk.class_idle_next = head;
        if (head) head->class_idle_prev = &chunk;
        head = &chunk;
    }
    void MarkLargeUsed(Chunk& chunk) noexcept {
        if (!chunk.idle) return;
        UnlinkIdleQueue(chunk);
        cached_large_bytes_ -= chunk.stride;
        if (chunk.class_idle_prev) chunk.class_idle_prev->class_idle_next = chunk.class_idle_next;
        else large_bins_[chunk.class_index] = chunk.class_idle_next;
        if (chunk.class_idle_next) chunk.class_idle_next->class_idle_prev = chunk.class_idle_prev;
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

    std::pmr::memory_resource* upstream_;
    friend class AllocationDomain;
    using SharesLeaseGroup = bool (*)(const void*, const void*) noexcept;
    bool domain_private_ = false;
    std::weak_ptr<worker_memory> lifetime_;
    std::shared_ptr<worker_memory> live_lifetime_;
    std::size_t live_allocations_ = 0;
    std::shared_ptr<const void> group_identity_;
    SharesLeaseGroup shares_group_ = nullptr;
    std::size_t request_initial_buffer_bytes_;
    std::size_t retained_block_bytes_;
    std::size_t cached_large_bytes_ = 0;
    std::array<Class, kClassCount> classes_{};
    std::array<Chunk*, kLargeBinCount> large_bins_{};
    Chunk* all_ = nullptr;
    Chunk* idle_head_ = nullptr;
    Chunk* idle_tail_ = nullptr;
    Footprint footprint_{};
    IdleWakeup* wakeup_ = nullptr;
};
// The root is callback-owned; the independent arena survives that root while
// borrowed allocations or container allocators remain in the merged group.
// No arena reference retains a session host or its transport stack.
class AllocationDomain final {
public:
    explicit AllocationDomain(const memory_pool_config& config = {})
        : pool_(std::make_shared<worker_memory>(*process_resource(), config, true)) {
        pool_->lifetime_ = pool_;
    }
    AllocationDomain(const AllocationDomain&) = delete;
    AllocationDomain& operator=(const AllocationDomain&) = delete;
    ~AllocationDomain() {
        if (lease_.load(std::memory_order_relaxed) != 0) std::terminate();
    }
    [[nodiscard]] worker_memory& pool() noexcept { return *pool_; }
    [[nodiscard]] std::pmr::memory_resource* resource() noexcept { return pool_.get(); }
    using SharesLeaseGroup = bool (*)(const void*, const void*) noexcept;
    // The identity is a stable scheduler group node, never a session pointer.
    void SetLeaseGroup(std::shared_ptr<const void> identity, SharesLeaseGroup shares_group) noexcept {
        pool_->group_identity_ = std::move(identity);
        pool_->shares_group_ = shares_group;
    }
    [[nodiscard]] std::size_t OutstandingAllocations() const noexcept {
        return pool_->OutstandingAllocations();
    }

private:
    friend class ScopedAllocationDomain;
    std::atomic<std::uintptr_t> lease_{0};
    std::shared_ptr<worker_memory> pool_;
};

inline void worker_memory::RequireLease() const noexcept {
    if (!domain_private_) return;
    const auto* current = detail::current_allocation_domain;
    if (!current) std::terminate();
    const auto& active = const_cast<AllocationDomain*>(current)->pool();
    if (&active == this) return;
    if (!shares_group_ || shares_group_ != active.shares_group_ ||
        !group_identity_ || !active.group_identity_ ||
        !shares_group_(group_identity_.get(), active.group_identity_.get()))
        std::terminate();
}

[[nodiscard]] inline std::shared_ptr<worker_memory> RetainResource(
    std::pmr::memory_resource* resource) noexcept {
    if (auto* pool = dynamic_cast<worker_memory*>(resource)) return pool->Lifetime();
    return {};
}

class ScopedAllocationDomain final {
public:
    explicit ScopedAllocationDomain(AllocationDomain& domain) noexcept
        : domain_(domain), previous_(detail::current_allocation_domain) {
        const auto token = detail::CurrentThreadToken();
        auto expected = std::uintptr_t{0};
        acquired_ = domain_.lease_.compare_exchange_strong(
            expected, token, std::memory_order_acquire);
        if (!acquired_ && expected != token) std::terminate();
        detail::current_allocation_domain = &domain_;
    }
    ~ScopedAllocationDomain() {
        if (detail::current_allocation_domain != &domain_) std::terminate();
        detail::current_allocation_domain = previous_;
        if (acquired_) domain_.lease_.store(0, std::memory_order_release);
    }
    ScopedAllocationDomain(const ScopedAllocationDomain&) = delete;
    ScopedAllocationDomain& operator=(const ScopedAllocationDomain&) = delete;

private:
    AllocationDomain& domain_;
    AllocationDomain* previous_;
    bool acquired_ = false;
};

[[nodiscard]] inline AllocationDomain* CurrentAllocationDomain() noexcept {
    return detail::current_allocation_domain;
}

[[nodiscard]] inline std::pmr::memory_resource* CurrentResource() noexcept {
    if (auto* domain = CurrentAllocationDomain()) return domain->resource();
    return std::pmr::get_default_resource();
}



// Request/handshake lifetime monotonic arena borrowing its worker_memory and
// optional initial buffer. Individual deallocation is a no-op; destruction
// returns overflow blocks to the worker_memory pool.
class request_memory final : private std::pmr::memory_resource {
public:
    explicit request_memory(worker_memory& worker_value)
        : owner_(worker_value)
        , arena_(worker_value.request_initial_buffer_bytes(), worker_value.resource()) {}

    request_memory(worker_memory& worker_value, std::span<std::byte> initial_buffer)
        : owner_(worker_value)
        , arena_(initial_buffer.data(), initial_buffer.size(), worker_value.resource()) {}

    request_memory(const request_memory&) = delete;
    request_memory& operator=(const request_memory&) = delete;
    ~request_memory() override { owner_.RequireLease(); }

    template <typename t_type = std::byte>
    [[nodiscard]] std::pmr::polymorphic_allocator<t_type> allocator() & noexcept {
        return std::pmr::polymorphic_allocator<t_type>(this);
    }
    template <typename t_type = std::byte>
    [[nodiscard]] std::pmr::polymorphic_allocator<t_type> allocator() && = delete;

    [[nodiscard]] std::pmr::memory_resource* resource() & noexcept { return this; }
    [[nodiscard]] std::pmr::memory_resource* resource() const& noexcept {
        return const_cast<request_memory*>(this);
    }
    [[nodiscard]] std::pmr::memory_resource* resource() && = delete;
    [[nodiscard]] std::pmr::memory_resource* resource() const&& = delete;

    [[nodiscard]] std::pmr::memory_resource* upstream_resource() & noexcept {
        return arena_.upstream_resource();
    }
    [[nodiscard]] std::pmr::memory_resource* upstream_resource() const& noexcept {
        return arena_.upstream_resource();
    }
    [[nodiscard]] std::pmr::memory_resource* upstream_resource() && = delete;
    [[nodiscard]] std::pmr::memory_resource* upstream_resource() const&& = delete;

private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
        owner_.RequireLease();
        return arena_.allocate(bytes, alignment);
    }
    void do_deallocate(void*, std::size_t, std::size_t) override {
        owner_.RequireLease();
    }
    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
    worker_memory& owner_;
    std::shared_ptr<worker_memory> owner_lifetime_{owner_.Lifetime()};
    mutable std::pmr::monotonic_buffer_resource arena_;
};

[[nodiscard]] inline worker_memory& ThreadMemoryPool() noexcept {
    if (auto* domain = CurrentAllocationDomain()) return domain->pool();
    thread_local worker_memory pool;
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
    return ThreadMemoryPool().Allocate(size, alignment);
}

inline void DeallocatePmr(void* p, size_t size = 0,
                          size_t alignment = 0) noexcept {
    if (p) worker_memory::OwnerOf(p).Deallocate(p, size, alignment);
}

inline void RequireAllocationLease(const void* pointer) noexcept {
    if (pointer) worker_memory::OwnerOf(pointer).RequireLease();
}

// Native Asio operation storage can be allocated, delivered, cancelled, or
// destroyed by different reactor threads. It never belongs to a session pool.
template <class T>
class ProcessAllocator : public std::pmr::polymorphic_allocator<T> {
public:
    ProcessAllocator() noexcept : std::pmr::polymorphic_allocator<T>(process_resource()) {}
    template <class U>
    ProcessAllocator(const ProcessAllocator<U>&) noexcept : ProcessAllocator() {}
    template <class U> struct rebind { using other = ProcessAllocator<U>; };
};

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

class ThreadMemoryResource final : public std::pmr::memory_resource {
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

inline void ConfigureProcessAllocator() noexcept {
    DisableTransparentHugePages();
#if defined(CNODE_USE_MIMALLOC) && !defined(__SANITIZE_ADDRESS__)
    mi_option_set(mi_option_allow_thp, 0);
    mi_option_set(mi_option_purge_delay, 10);
#endif
    static ThreadMemoryResource default_resource;
    std::pmr::set_default_resource(&default_resource);
}

inline void CollectSteady() noexcept {
    ThreadMemoryPool().Purge();
#if defined(CNODE_USE_MIMALLOC) && !defined(__SANITIZE_ADDRESS__)
    mi_collect(false);
#endif
}

inline void CollectBurst() noexcept {
    ThreadMemoryPool().PurgeIdle();
#if defined(CNODE_USE_MIMALLOC) && !defined(__SANITIZE_ADDRESS__)
    mi_collect(true);
#endif
}

template <class T>
class ThreadLocalAllocator {
public:
    using value_type = T;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    ThreadLocalAllocator() noexcept : ThreadLocalAllocator(CurrentResource()) {}
    ThreadLocalAllocator(std::pmr::memory_resource* resource) noexcept
        : resource_(resource), lifetime_(RetainResource(resource)) {}
    ThreadLocalAllocator(const ThreadLocalAllocator&) noexcept = default;
    ThreadLocalAllocator& operator=(const ThreadLocalAllocator&) noexcept = default;
    ThreadLocalAllocator(ThreadLocalAllocator&& other) noexcept
        : resource_(other.resource_), lifetime_(other.lifetime_) {}
    ThreadLocalAllocator& operator=(ThreadLocalAllocator&& other) noexcept {
        if (this != &other) {
            resource_ = other.resource_;
            lifetime_ = other.lifetime_;
        }
        return *this;
    }
    template <class U>
    ThreadLocalAllocator(const ThreadLocalAllocator<U>& other) noexcept
        : resource_(other.resource()), lifetime_(other.lifetime_) {}
    template <class U>
    ThreadLocalAllocator(ThreadLocalAllocator<U>&& other) noexcept
        : resource_(other.resource()), lifetime_(other.lifetime_) {}
    template <class U>
    ThreadLocalAllocator(const std::pmr::polymorphic_allocator<U>& other) noexcept
        : ThreadLocalAllocator(other.resource()) {}
    template <class U> struct rebind { using other = ThreadLocalAllocator<U>; };
    [[nodiscard]] ThreadLocalAllocator select_on_container_copy_construction() const noexcept {
        return {};
    }
    [[nodiscard]] std::pmr::memory_resource* resource() const noexcept { return resource_; }
    [[nodiscard]] T* allocate(std::size_t count) {
        return std::pmr::polymorphic_allocator<T>(resource_).allocate(count);
    }
    void deallocate(T* pointer, std::size_t count) noexcept {
        std::pmr::polymorphic_allocator<T>(resource_).deallocate(pointer, count);
    }
    template <class U, class... Args>
    void construct(U* pointer, Args&&... args) {
        // Preserve uses-allocator construction for nested strings/containers.
        std::pmr::polymorphic_allocator<T>(resource_).construct(
            pointer, std::forward<Args>(args)...);
    }
    template <class U>
    [[nodiscard]] bool operator==(const ThreadLocalAllocator<U>& other) const noexcept {
        return resource_->is_equal(*other.resource());
    }

private:
    template <class> friend class ThreadLocalAllocator;
    std::pmr::memory_resource* resource_;
    std::shared_ptr<worker_memory> lifetime_;
};
template <class T, class... Args>
[[nodiscard]] std::shared_ptr<T> AllocateShared(Args&&... args) {
    return std::allocate_shared<T>(ThreadLocalAllocator<T>{}, std::forward<Args>(args)...);
}
template <class T> using ThreadLocalVector = std::vector<T, ThreadLocalAllocator<T>>;

// Zero-allocation-when-empty PMR ring deque. Allocates a contiguous power-of-2
// array from its memory_resource on demand and returns it immediately when the
// queue drains to empty, so idle sessions/substreams retain 0 bytes.
template <class T>
class RingDeque {
public:
    using value_type = T;
    using allocator_type = ThreadLocalAllocator<T>;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using reference = T&;
    using const_reference = const T&;

    RingDeque() noexcept : resource_(CurrentResource()) {}
    explicit RingDeque(std::pmr::memory_resource* resource) noexcept
        : resource_(resource ? resource : CurrentResource()) {}
    explicit RingDeque(const allocator_type& alloc) noexcept
        : resource_(alloc.resource() ? alloc.resource() : CurrentResource()) {}

    RingDeque(const RingDeque& other)
        : resource_(CurrentResource()) {
        if (!other.empty()) {
            Reserve(other.size_);
            try {
                for (std::size_t i = 0; i < other.size_; ++i) {
                    ConstructAt(data_ + size_, other[i]);
                    ++size_;
                }
            } catch (...) {
                clear();
                throw;
            }
        }
    }

    RingDeque(RingDeque&& other) noexcept
        : resource_(other.resource_)
        , resource_lifetime_(other.resource_lifetime_)
        , data_(std::exchange(other.data_, nullptr))
        , head_(std::exchange(other.head_, 0))
        , size_(std::exchange(other.size_, 0))
        , capacity_(std::exchange(other.capacity_, 0)) {}

    RingDeque& operator=(const RingDeque& other) {
        if (this != &other) {
            RingDeque tmp(resource_);
            if (!other.empty()) {
                tmp.Reserve(other.size_);
                for (std::size_t i = 0; i < other.size_; ++i) {
                    tmp.ConstructAt(tmp.data_ + tmp.size_, other[i]);
                    ++tmp.size_;
                }
            }
            clear();
            data_ = std::exchange(tmp.data_, nullptr);
            head_ = std::exchange(tmp.head_, 0);
            size_ = std::exchange(tmp.size_, 0);
            capacity_ = std::exchange(tmp.capacity_, 0);
        }
        return *this;
    }

    RingDeque& operator=(RingDeque&& other) noexcept {
        if (this != &other) {
            clear();
            resource_ = other.resource_;
            resource_lifetime_ = other.resource_lifetime_;
            data_ = std::exchange(other.data_, nullptr);
            head_ = std::exchange(other.head_, 0);
            size_ = std::exchange(other.size_, 0);
            capacity_ = std::exchange(other.capacity_, 0);
        }
        return *this;
    }

    ~RingDeque() noexcept {
        clear();
    }

    [[nodiscard]] allocator_type get_allocator() const noexcept {
        return allocator_type(resource_);
    }

    [[nodiscard]] bool empty() const noexcept { return size_ == 0; }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] std::size_t capacity() const noexcept { return capacity_; }

    [[nodiscard]] T& front() noexcept { return data_[head_]; }
    [[nodiscard]] const T& front() const noexcept { return data_[head_]; }

    [[nodiscard]] T& back() noexcept {
        return data_[(head_ + size_ - 1) & (capacity_ - 1)];
    }
    [[nodiscard]] const T& back() const noexcept {
        return data_[(head_ + size_ - 1) & (capacity_ - 1)];
    }

    [[nodiscard]] T& operator[](std::size_t index) noexcept {
        return data_[(head_ + index) & (capacity_ - 1)];
    }
    [[nodiscard]] const T& operator[](std::size_t index) const noexcept {
        return data_[(head_ + index) & (capacity_ - 1)];
    }

    template <typename... Args>
    T& emplace_back(Args&&... args) {
        if (size_ == capacity_) {
            return GrowEmplace(true, std::forward<Args>(args)...);
        }
        const std::size_t idx = (head_ + size_) & (capacity_ - 1);
        T* ptr = data_ + idx;
        ConstructAt(ptr, std::forward<Args>(args)...);
        ++size_;
        return *ptr;
    }

    void push_back(const T& value) { (void)emplace_back(value); }
    void push_back(T&& value) { (void)emplace_back(std::move(value)); }

    template <typename... Args>
    T& emplace_front(Args&&... args) {
        if (size_ == capacity_) {
            return GrowEmplace(false, std::forward<Args>(args)...);
        }
        const std::size_t next_head = (head_ + capacity_ - 1) & (capacity_ - 1);
        T* ptr = data_ + next_head;
        ConstructAt(ptr, std::forward<Args>(args)...);
        head_ = next_head;
        ++size_;
        return *ptr;
    }

    void push_front(const T& value) { (void)emplace_front(value); }
    void push_front(T&& value) { (void)emplace_front(std::move(value)); }

    void pop_front() noexcept {
        std::destroy_at(data_ + head_);
        head_ = (head_ + 1) & (capacity_ - 1);
        if (--size_ == 0) {
            ReleaseStorage();
        }
    }

    void pop_back() noexcept {
        const std::size_t idx = (head_ + size_ - 1) & (capacity_ - 1);
        std::destroy_at(data_ + idx);
        if (--size_ == 0) {
            ReleaseStorage();
        }
    }

    void clear() noexcept {
        for (std::size_t i = 0; i < size_; ++i) {
            std::destroy_at(data_ + ((head_ + i) & (capacity_ - 1)));
        }
        size_ = 0;
        ReleaseStorage();
    }

    void shrink_to_fit() noexcept {
        if (size_ == 0) {
            ReleaseStorage();
        }
    }

    void swap(RingDeque& other) noexcept {
        if (this == &other) return;
        std::swap(resource_, other.resource_);
        std::swap(resource_lifetime_, other.resource_lifetime_);
        std::swap(data_, other.data_);
        std::swap(head_, other.head_);
        std::swap(size_, other.size_);
        std::swap(capacity_, other.capacity_);
    }

private:
    template <class... Args>
    void ConstructAt(T* ptr, Args&&... args) {
        allocator_type(resource_).construct(ptr, std::forward<Args>(args)...);
    }

    void ReleaseStorage() noexcept {
        if (data_) {
            resource_->deallocate(data_, capacity_ * sizeof(T), alignof(T));
            data_ = nullptr;
            capacity_ = 0;
        }
        head_ = 0;
    }

    void Reserve(std::size_t min_cap) {
        if (min_cap > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
            throw std::bad_alloc();
        }
        std::size_t next_cap = capacity_ ? capacity_ : 4;
        while (next_cap < min_cap) {
            if (next_cap > (std::numeric_limits<std::size_t>::max() / sizeof(T)) / 2) {
                throw std::bad_alloc();
            }
            next_cap *= 2;
        }
        if (next_cap <= capacity_) return;
        T* next_data = static_cast<T*>(
            resource_->allocate(next_cap * sizeof(T), alignof(T)));
        std::size_t constructed = 0;
        try {
            for (; constructed < size_; ++constructed) {
                ConstructAt(
                    next_data + constructed,
                    std::move_if_noexcept(data_[(head_ + constructed) & (capacity_ - 1)]));
            }
        } catch (...) {
            for (std::size_t i = 0; i < constructed; ++i) {
                std::destroy_at(next_data + i);
            }
            resource_->deallocate(next_data, next_cap * sizeof(T), alignof(T));
            throw;
        }
        for (std::size_t i = 0; i < size_; ++i) {
            std::destroy_at(data_ + ((head_ + i) & (capacity_ - 1)));
        }
        if (data_) {
            resource_->deallocate(data_, capacity_ * sizeof(T), alignof(T));
        }
        data_ = next_data;
        head_ = 0;
        capacity_ = next_cap;
    }

    template <typename... Args>
    T& GrowEmplace(bool at_back, Args&&... args) {
        if (capacity_ > (std::numeric_limits<std::size_t>::max() / sizeof(T)) / 2) {
            throw std::bad_alloc();
        }
        const std::size_t next_cap = capacity_ ? capacity_ * 2 : 4;
        if (next_cap > std::numeric_limits<std::size_t>::max() / sizeof(T)) {
            throw std::bad_alloc();
        }
        T* next_data = static_cast<T*>(
            resource_->allocate(next_cap * sizeof(T), alignof(T)));
        T* new_elem = next_data + (at_back ? size_ : 0);
        const std::size_t old_offset = at_back ? 0 : 1;
        bool new_constructed = false;
        std::size_t constructed = 0;
        try {
            ConstructAt(new_elem, std::forward<Args>(args)...);
            new_constructed = true;
            for (; constructed < size_; ++constructed) {
                ConstructAt(
                    next_data + old_offset + constructed,
                    std::move_if_noexcept(data_[(head_ + constructed) & (capacity_ - 1)]));
            }
        } catch (...) {
            for (std::size_t i = 0; i < constructed; ++i) {
                std::destroy_at(next_data + old_offset + i);
            }
            if (new_constructed) {
                std::destroy_at(new_elem);
            }
            resource_->deallocate(next_data, next_cap * sizeof(T), alignof(T));
            throw;
        }
        for (std::size_t i = 0; i < size_; ++i) {
            std::destroy_at(data_ + ((head_ + i) & (capacity_ - 1)));
        }
        if (data_) {
            resource_->deallocate(data_, capacity_ * sizeof(T), alignof(T));
        }
        data_ = next_data;
        capacity_ = next_cap;
        head_ = 0;
        ++size_;
        return *new_elem;
    }

    std::pmr::memory_resource* resource_;
    std::shared_ptr<worker_memory> resource_lifetime_{RetainResource(resource_)};
    T* data_ = nullptr;
    std::size_t head_ = 0;
    std::size_t size_ = 0;
    std::size_t capacity_ = 0;
};

template <class T> using ThreadLocalDeque = RingDeque<T>;
template <class T> using ThreadLocalList = std::list<T, ThreadLocalAllocator<T>>;
template <class Key, class Value, class Compare = std::less<Key>>
using ThreadLocalMap = std::map<Key, Value, Compare, ThreadLocalAllocator<std::pair<const Key, Value>>>;
template <class Key, class Value, class Hash = std::hash<Key>, class Eq = std::equal_to<Key>>
using ThreadLocalUnorderedMap = std::unordered_map<Key, Value, Hash, Eq,
    ThreadLocalAllocator<std::pair<const Key, Value>>>;
template <class Key, class Hash = std::hash<Key>, class Eq = std::equal_to<Key>>
using ThreadLocalUnorderedSet = std::unordered_set<Key, Hash, Eq, ThreadLocalAllocator<Key>>;
using ThreadLocalString = std::basic_string<char, std::char_traits<char>, ThreadLocalAllocator<char>>;
using ByteVector = ThreadLocalVector<uint8_t>;

} // namespace acpp::memory
