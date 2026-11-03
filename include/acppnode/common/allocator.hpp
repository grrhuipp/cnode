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
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <sys/prctl.h>
#include <unistd.h>
#endif
#if defined(__GLIBC__)
#include <malloc.h>
#endif
#if defined(CNODE_USE_MIMALLOC) && !defined(__SANITIZE_ADDRESS__)
#include <mimalloc.h>
#endif

namespace acpp::memory {

inline constexpr bool kAllocatorCollects = true;
inline constexpr int kGlibcArenaMax = 2;
inline constexpr int kGlibcTrimThreshold = 64 * 1024;
inline constexpr int kGlibcMmapThreshold = 64 * 1024;
inline constexpr std::size_t kThreadPoolTargetBytes = 64 * 1024;
inline constexpr std::size_t kThreadPoolMaxClass = 16 * 1024;
inline constexpr std::size_t kLargeBlockGranularity = 4 * 1024;
inline constexpr std::size_t kMaxCachedBlockBytes = 1024 * 1024;
inline constexpr std::size_t kMaxCachedBlockAlignment = 64;
inline constexpr std::size_t request_arena_initial_bytes = std::size_t{4} * 1024;
inline constexpr std::size_t default_retained_block_bytes = std::size_t{8} * 1024 * 1024;
inline constexpr std::size_t max_retained_block_bytes = static_cast<std::size_t>(PTRDIFF_MAX);
inline constexpr std::chrono::milliseconds kThreadPoolPurgeDelay{10};

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

[[nodiscard]] inline constexpr bool ValidAlignment(std::size_t alignment) noexcept {
    return alignment != 0 && (alignment & (alignment - 1)) == 0;
}
[[nodiscard]] inline constexpr std::size_t RoundUp(
    std::size_t value, std::size_t unit) noexcept {
    return (value + unit - 1) & ~(unit - 1);
}

namespace detail {

[[nodiscard]] inline void* AllocateProcessRaw(std::size_t bytes_value, std::size_t alignment) {
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
    (void)bytes_value;
    (void)alignment;
    mi_free(block);
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

struct resolved_pmr_resource_tag final {};

[[nodiscard]] inline std::pmr::memory_resource* pmr_resource_or_default(
    std::pmr::memory_resource* resource) noexcept {
    return resource == nullptr ? process_resource() : resource;
}

template <typename t_type, typename... args_type>
[[nodiscard]] t_type* construct_pmr_object(
    resolved_pmr_resource_tag, std::pmr::memory_resource* resource, args_type&&... args) {
    auto* storage = resource->allocate(sizeof(t_type), alignof(t_type));
    try {
        return std::construct_at(static_cast<t_type*>(storage), std::forward<args_type>(args)...);
    } catch (...) {
        resource->deallocate(storage, sizeof(t_type), alignof(t_type));
        throw;
    }
}

template <typename t_type, typename... args_type>
[[nodiscard]] t_type* construct_pmr_object(
    std::pmr::memory_resource* resource, args_type&&... args) {
    return construct_pmr_object<t_type>(
        resolved_pmr_resource_tag{}, pmr_resource_or_default(resource),
        std::forward<args_type>(args)...);
}

template <typename t_type>
void destroy_pmr_object(
    resolved_pmr_resource_tag, t_type* value, std::pmr::memory_resource* resource) noexcept {
    if (value == nullptr) {
        return;
    }
    std::destroy_at(value);
    resource->deallocate(value, sizeof(t_type), alignof(t_type));
}

template <typename t_type>
void destroy_pmr_object(t_type* value, std::pmr::memory_resource* resource) noexcept {
    destroy_pmr_object(resolved_pmr_resource_tag{}, value, pmr_resource_or_default(resource));
}

template <typename t_type>
struct pmr_object_deleter final {
    std::pmr::memory_resource* resource_{nullptr};

    void operator()(t_type* value) const noexcept {
        destroy_pmr_object(value, resource_);
    }
};

template <typename t_type, typename... args_type>
[[nodiscard]] std::unique_ptr<t_type, pmr_object_deleter<t_type>> make_pmr_object(
    std::pmr::memory_resource* resource, args_type&&... args) {
    auto* memory_resource = pmr_resource_or_default(resource);
    return std::unique_ptr<t_type, pmr_object_deleter<t_type>>(
        construct_pmr_object<t_type>(
            resolved_pmr_resource_tag{}, memory_resource, std::forward<args_type>(args)...),
        pmr_object_deleter<t_type>{memory_resource});
}

namespace detail {

inline constexpr std::size_t task_frame_cache_granularity = 128;
inline constexpr std::size_t task_frame_cache_max_block_bytes = 16 * 1024;
inline constexpr std::size_t task_frame_cache_budget_bytes = 512 * 1024;
inline constexpr std::size_t task_frame_cache_bin_count =
    task_frame_cache_max_block_bytes / task_frame_cache_granularity;

[[nodiscard]] inline constexpr std::size_t task_frame_class_bytes(std::size_t bytes_value) noexcept {
    if (bytes_value > task_frame_cache_max_block_bytes) {
        return bytes_value;
    }
    return (bytes_value + task_frame_cache_granularity - 1) & ~(task_frame_cache_granularity - 1);
}

inline thread_local bool task_frame_cache_destroyed = false;

class task_frame_cache final {
public:
    task_frame_cache() noexcept = default;
    task_frame_cache(const task_frame_cache&) = delete;
    task_frame_cache& operator=(const task_frame_cache&) = delete;

    ~task_frame_cache() {
        task_frame_cache_destroyed = true;
        release_all();
    }

    void release_all() noexcept {
        for (std::size_t idx = 0; idx < bins_.size(); ++idx) {
            const std::size_t class_bytes = (idx + 1) * task_frame_cache_granularity;
            void*& head = bins_[idx];
            while (head != nullptr) {
                void* next_value = *static_cast<void**>(head);
                DeallocateProcessRaw(head, class_bytes, alignof(std::max_align_t));
                head = next_value;
            }
        }
        cached_bytes_ = 0;
    }

    [[nodiscard]] std::size_t cached_bytes() const noexcept {
        return cached_bytes_;
    }

    [[nodiscard]] void* take_block(std::size_t class_bytes) noexcept {
        void*& head = bins_[bin_index(class_bytes)];
        void* block = head;
        if (block != nullptr) {
            head = *static_cast<void**>(block);
            cached_bytes_ -= class_bytes;
        }
        return block;
    }

    [[nodiscard]] bool store_block(void* block, std::size_t class_bytes) noexcept {
        if (cached_bytes_ + class_bytes > task_frame_cache_budget_bytes) {
            return false;
        }
        void*& head = bins_[bin_index(class_bytes)];
        *static_cast<void**>(block) = head;
        head = block;
        cached_bytes_ += class_bytes;
        return true;
    }

private:
    [[nodiscard]] static constexpr std::size_t bin_index(std::size_t class_bytes) noexcept {
        return class_bytes / task_frame_cache_granularity - 1;
    }

    std::array<void*, task_frame_cache_bin_count> bins_{};
    std::size_t cached_bytes_{0};
};

inline thread_local task_frame_cache g_task_frame_cache;

[[nodiscard]] inline void* task_frame_allocate(std::size_t bytes_value) {
    const std::size_t class_bytes = task_frame_class_bytes(bytes_value == 0 ? 1 : bytes_value);
    if (!task_frame_cache_destroyed && class_bytes <= task_frame_cache_max_block_bytes) {
        if (void* cached = g_task_frame_cache.take_block(class_bytes)) {
            return cached;
        }
    }
    return AllocateProcessRaw(class_bytes, alignof(std::max_align_t));
}

inline void task_frame_deallocate_sized(void* pointer, std::size_t bytes_value) noexcept {
    if (!pointer) return;
    const std::size_t class_bytes = task_frame_class_bytes(bytes_value == 0 ? 1 : bytes_value);
    if (!task_frame_cache_destroyed && class_bytes <= task_frame_cache_max_block_bytes &&
        g_task_frame_cache.store_block(pointer, class_bytes)) {
        return;
    }
    DeallocateProcessRaw(pointer, class_bytes, alignof(std::max_align_t));
}

[[nodiscard]] inline void* task_frame_allocate_aligned(std::size_t bytes_value, std::size_t alignment) {
    return AllocateProcessRaw(bytes_value, alignment);
}

inline void task_frame_deallocate_aligned(
    void* pointer, std::size_t bytes_value = 0, std::size_t alignment = alignof(std::max_align_t)) noexcept {
    DeallocateProcessRaw(pointer, bytes_value, alignment);
}

[[nodiscard]] inline std::size_t task_frame_cached_bytes() noexcept {
    return task_frame_cache_destroyed ? 0 : g_task_frame_cache.cached_bytes();
}

inline void task_frame_cache_release() noexcept {
    if (!task_frame_cache_destroyed) {
        g_task_frame_cache.release_all();
    }
}

} // namespace detail

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
        , retained_block_bytes_(config.retained_block_bytes_)
        , owner_thread_(std::this_thread::get_id()) {}

    worker_memory(const worker_memory&) = delete;
    worker_memory& operator=(const worker_memory&) = delete;

    ~worker_memory() override {
        while (all_) {
            ReleaseChunk(*all_);
        }
    }

    [[nodiscard]] Footprint GetFootprint() const noexcept { return footprint_; }

    void Purge() noexcept {
        if (!idle_head_) return;
        const auto now = Clock::now();
        while (idle_head_ && now - idle_head_->idle_at >= kThreadPoolPurgeDelay) {
            ReleaseChunk(*idle_head_);
        }
    }

    void PurgeIdle() noexcept {
        while (idle_head_) {
            ReleaseChunk(*idle_head_);
        }
        detail::task_frame_cache_release();
    }

    // Releases cached blocks and drains the calling thread's coroutine frame
    // cache on the bound owner thread.
    void trim() {
        const auto caller = std::this_thread::get_id();
        if (trimmed_owner_ != std::thread::id{} && caller != trimmed_owner_) {
            throw std::logic_error("worker memory trim must run on its owner worker");
        }
        trimmed_owner_ = caller;
        PurgeIdle();
#if defined(CNODE_USE_MIMALLOC) && !defined(__SANITIZE_ADDRESS__)
        mi_collect(false);
#endif
    }

    [[nodiscard]] Clock::time_point NextPurgeDeadline() const noexcept {
        return idle_head_ ? idle_head_->idle_at + kThreadPoolPurgeDelay
                          : Clock::time_point::max();
    }

    [[nodiscard]] bool BindIdleWakeup(IdleWakeup& owner) noexcept {
        if (wakeup_ && wakeup_ != &owner) return false;
        wakeup_ = &owner;
        if (idle_head_) wakeup_->OnPoolIdle();
        return true;
    }

    void UnbindIdleWakeup(IdleWakeup& owner) noexcept {
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

    [[nodiscard]] std::pmr::memory_resource* upstream_resource() const noexcept {
        return upstream_;
    }

    [[nodiscard]] std::size_t request_initial_buffer_bytes() const noexcept {
        return request_initial_buffer_bytes_;
    }

    [[nodiscard]] std::size_t retained_block_bytes() const noexcept {
        return retained_block_bytes_;
    }

    [[nodiscard]] static Layout Describe(
        std::size_t bytes, std::size_t alignment, std::size_t depth = 0) noexcept {
        if (!ValidAlignment(alignment)) return {};
        bytes = std::max(bytes, std::size_t{1});
        if (alignment > kSlotAlignment || bytes > kThreadPoolMaxClass - sizeof(SlotHeader)) {
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
        if (!ValidAlignment(alignment)) return nullptr;
        bytes = std::max(bytes, std::size_t{1});
        if (alignment > kSlotAlignment || bytes > kThreadPoolMaxClass - sizeof(SlotHeader)) {
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

    void Deallocate(void* pointer, std::size_t bytes = 0,
                    std::size_t alignment = 0) noexcept {
        if (!pointer) return;
        auto* header = reinterpret_cast<SlotHeader*>(pointer) - 1;
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
            } else if (chunk->large_cached) {
                if (chunk->stride > retained_block_bytes_ - cached_large_bytes_) {
                    ReleaseChunk(*chunk);
                } else {
                    const bool first_idle = idle_head_ == nullptr;
                    MarkLargeIdle(*chunk);
                    Purge();
                    if (first_idle && wakeup_) wakeup_->OnPoolIdle();
                }
            } else {
                UnlinkRecyclable(*chunk);
                chunk->free_head = nullptr;
                chunk->bump = reinterpret_cast<std::byte*>(chunk) + ChunkLead();
                const bool first_idle = idle_head_ == nullptr;
                MarkIdle(*chunk);
                Purge();
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
    static constexpr std::size_t kClassCount = 25 + (kThreadPoolMaxClass - 1024) / 256;
    static constexpr std::size_t kLargeBinCount =
        kMaxCachedBlockBytes / kLargeBlockGranularity;

    struct Chunk;
    struct alignas(kSlotAlignment) SlotHeader {
        Chunk* chunk = nullptr;
        std::thread::id owner{};
        std::size_t capacity = 0;
        SlotHeader* next_free = nullptr;
    };
    struct Chunk {
        worker_memory* pool = nullptr;
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
        const auto target = std::max(page, kThreadPoolTargetBytes);
        const auto pages = std::min(
            std::size_t{1} << std::min(depth, std::size_t{4}), target / page);
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
        auto* header = ::new (chunk.bump) SlotHeader{
            &chunk, owner_thread_, chunk.stride - sizeof(SlotHeader)};
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
            chunk, owner_thread_, class_bytes};
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
            chunk, owner_thread_, bytes};
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
        owner_thread_ = std::this_thread::get_id();
        auto* chunk = ::new (mapped) Chunk;
        chunk->pool = this;
        chunk->map_bytes = layout.map_bytes;
        chunk->map_alignment = map_alignment;
        chunk->stride = layout.slot_bytes;
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
    std::size_t request_initial_buffer_bytes_;
    std::size_t retained_block_bytes_;
    std::size_t cached_large_bytes_ = 0;
    std::thread::id owner_thread_{};
    std::thread::id trimmed_owner_{};
    std::array<Class, kClassCount> classes_{};
    std::array<Chunk*, kLargeBinCount> large_bins_{};
    Chunk* all_ = nullptr;
    Chunk* idle_head_ = nullptr;
    Chunk* idle_tail_ = nullptr;
    Footprint footprint_{};
    IdleWakeup* wakeup_ = nullptr;
};


// Request/handshake lifetime monotonic arena borrowing its worker_memory and
// optional initial buffer. Individual deallocation is a no-op; destruction
// returns overflow blocks to the worker_memory pool.
class request_memory final {
public:
    explicit request_memory(worker_memory& worker_value)
        : request_memory(worker_value.request_initial_buffer_bytes(), worker_value.resource()) {}

    request_memory(worker_memory& worker_value, std::span<std::byte> initial_buffer)
        : arena_(initial_buffer.data(), initial_buffer.size(), worker_value.resource())
        , initial_bytes_(worker_value.request_initial_buffer_bytes()) {}

    request_memory(std::size_t initial_bytes, std::pmr::memory_resource* upstream)
        : arena_(initial_bytes, pmr_resource_or_default(upstream))
        , initial_bytes_(initial_bytes) {}

    ~request_memory() = default;

    request_memory(const request_memory&) = delete;
    request_memory& operator=(const request_memory&) = delete;

    [[nodiscard]] request_memory fork() const& {
        return request_memory(initial_bytes_, arena_.upstream_resource());
    }
    request_memory fork() const&& = delete;

    template <typename t_type = std::byte>
    [[nodiscard]] std::pmr::polymorphic_allocator<t_type> allocator() & noexcept {
        return std::pmr::polymorphic_allocator<t_type>(&arena_);
    }
    template <typename t_type = std::byte>
    [[nodiscard]] std::pmr::polymorphic_allocator<t_type> allocator() && = delete;

    [[nodiscard]] std::pmr::memory_resource* resource() & noexcept { return &arena_; }
    [[nodiscard]] std::pmr::memory_resource* resource() const& noexcept { return &arena_; }
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
    mutable std::pmr::monotonic_buffer_resource arena_;
    std::size_t initial_bytes_;
};

[[nodiscard]] inline worker_memory& ThreadPool() noexcept {
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
    return ThreadPool().Allocate(size, alignment);
}

inline void DeallocatePmr(void* p, size_t size = 0,
                          size_t alignment = 0) noexcept {
    if (p) ThreadPool().Deallocate(p, size, alignment);
}

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

inline void ConfigureProcessAllocator() noexcept {
    DisableTransparentHugePages();
    ConfigureProcessGlibc();
    static ThreadPoolFacade default_resource;
    std::pmr::set_default_resource(&default_resource);
}

inline void CollectSteady() noexcept {
    ThreadPool().Purge();
    detail::task_frame_cache_release();
#if defined(CNODE_USE_MIMALLOC) && !defined(__SANITIZE_ADDRESS__)
    mi_collect(false);
#elif defined(__GLIBC__)
    (void)::malloc_trim(0);
#endif
}

inline void CollectBurst() noexcept {
    ThreadPool().PurgeIdle();
#if defined(CNODE_USE_MIMALLOC) && !defined(__SANITIZE_ADDRESS__)
    mi_collect(true);
#elif defined(__GLIBC__)
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
