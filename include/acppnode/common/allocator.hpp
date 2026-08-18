#pragma once

#include "acppnode/common/memory_stats.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <new>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

#if defined(__GLIBC__)
#include <malloc.h>
#endif

namespace acpp::memory {

inline void DisableTransparentHugePages() noexcept {
#if defined(__linux__) && defined(PR_SET_THP_DISABLE)
    // VPS kernels often run THP in "always" mode. Proxy workloads churn many
    // small objects, and 2MB anonymous huge pages amplify RSS retention.
    (void)::prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
#endif
}

inline constexpr bool kAllocatorCollects =
#if defined(__GLIBC__)
    true;
#else
    false;
#endif

inline constexpr int kGlibcArenaMax = 2;
inline constexpr int kGlibcTrimThreshold = 64 * 1024;
inline constexpr int kGlibcMmapThreshold = 64 * 1024;

inline void ConfigureProcessAllocator() noexcept {
    DisableTransparentHugePages();
#if defined(__GLIBC__)
    (void)::mallopt(M_ARENA_MAX, kGlibcArenaMax);
    (void)::mallopt(M_TRIM_THRESHOLD, kGlibcTrimThreshold);
    (void)::mallopt(M_MMAP_THRESHOLD, kGlibcMmapThreshold);
#endif
}

inline void* AllocateRaw(size_t size,
                         size_t alignment = alignof(std::max_align_t)) noexcept {
    if (alignment > alignof(std::max_align_t)) {
        return ::operator new(size, std::align_val_t{alignment}, std::nothrow);
    }
    return ::operator new(size, std::nothrow);
}

inline void DeallocateRaw(void* p,
                          size_t /*size*/ = 0,
                          size_t alignment = alignof(std::max_align_t)) noexcept {
    if (!p) {
        return;
    }
    if (alignment > alignof(std::max_align_t)) {
        ::operator delete(p, std::align_val_t{alignment});
        return;
    }
    ::operator delete(p);
}

namespace detail {

inline constexpr size_t kSmallAllocMinClass = 16;
inline constexpr size_t kSmallAllocMaxClass = 4096;
inline constexpr size_t kSmallAllocClassCount = 9;
inline constexpr size_t kSmallAllocBinCap = 64;
inline constexpr size_t kSmallAllocSteadyBinCap = 16;

struct SmallFreeBlock {
    SmallFreeBlock* next = nullptr;
};

struct SmallAllocBin {
    SmallFreeBlock* head = nullptr;
    size_t count = 0;
};

[[nodiscard]] constexpr size_t SmallClassFor(size_t size) noexcept {
    size_t klass = kSmallAllocMinClass;
    while (klass < size && klass < kSmallAllocMaxClass) {
        klass <<= 1;
    }
    return klass;
}

[[nodiscard]] constexpr size_t SmallClassIndex(size_t klass) noexcept {
    size_t index = 0;
    size_t cur = kSmallAllocMinClass;
    while (cur < klass && index + 1 < kSmallAllocClassCount) {
        cur <<= 1;
        ++index;
    }
    return index;
}

[[nodiscard]] constexpr bool CanUseSmallCache(size_t size,
                                              size_t alignment) noexcept {
    return size > 0 &&
           size <= kSmallAllocMaxClass &&
           alignment <= alignof(std::max_align_t);
}

struct SmallAllocCache {
    SmallAllocBin bins[kSmallAllocClassCount];

#ifdef CNODE_MEMORY_STATS
    uint64_t current_depth = 0;
    uint64_t high_water = 0;
    uint64_t pop_hits = 0;
    uint64_t pop_misses = 0;
    uint64_t push_hits = 0;
    uint64_t push_drops = 0;
    uint64_t trim_frees = 0;
#endif

    SmallAllocCache() noexcept = default;
    SmallAllocCache(const SmallAllocCache&) = delete;
    SmallAllocCache& operator=(const SmallAllocCache&) = delete;

    ~SmallAllocCache() {
        for (size_t i = 0; i < kSmallAllocClassCount; ++i) {
            const size_t klass = kSmallAllocMinClass << i;
            auto* block = bins[i].head;
            while (block) {
                auto* next = block->next;
                DeallocateRaw(block, klass);
                block = next;
            }
        }
    }
};

inline SmallAllocCache& TlsSmallAllocCache() noexcept {
    thread_local SmallAllocCache cache;
    return cache;
}

[[nodiscard]] inline uint64_t SmallCacheDepth(const SmallAllocCache& cache) noexcept {
    uint64_t total = 0;
    for (size_t i = 0; i < kSmallAllocClassCount; ++i) {
        total += cache.bins[i].count;
    }
    return total;
}

[[nodiscard]] inline void* AllocateSmallCached(size_t size,
                                               size_t alignment) noexcept {
    if (!CanUseSmallCache(size, alignment)) {
        return AllocateRaw(size, alignment);
    }

    const size_t klass = SmallClassFor(size);
    auto& cache = TlsSmallAllocCache();
    auto& bin = cache.bins[SmallClassIndex(klass)];
    if (bin.head) {
        SmallFreeBlock* block = bin.head;
        bin.head = block->next;
        --bin.count;
#ifdef CNODE_MEMORY_STATS
        --cache.current_depth;
        ++cache.pop_hits;
#endif
        return block;
    }
#ifdef CNODE_MEMORY_STATS
    ++cache.pop_misses;
#endif
    return AllocateRaw(klass);
}

inline void DeallocateSmallCached(void* p,
                                  size_t size,
                                  size_t alignment) noexcept {
    if (!p) {
        return;
    }
    if (!CanUseSmallCache(size, alignment)) {
        DeallocateRaw(p, size, alignment);
        return;
    }

    const size_t klass = SmallClassFor(size);
    auto& cache = TlsSmallAllocCache();
    auto& bin = cache.bins[SmallClassIndex(klass)];
    if (bin.count >= kSmallAllocBinCap) {
#ifdef CNODE_MEMORY_STATS
        ++cache.push_drops;
#endif
        DeallocateRaw(p, klass);
        return;
    }

    auto* block = static_cast<SmallFreeBlock*>(p);
    block->next = bin.head;
    bin.head = block;
    ++bin.count;
#ifdef CNODE_MEMORY_STATS
    ++cache.current_depth;
    ++cache.push_hits;
    if (cache.current_depth > cache.high_water) {
        cache.high_water = cache.current_depth;
    }
#endif
}

inline void TrimSmallAllocCache(bool force) noexcept {
    auto& cache = TlsSmallAllocCache();
    const size_t target = force ? 0 : kSmallAllocSteadyBinCap;
    for (size_t i = 0; i < kSmallAllocClassCount; ++i) {
        const size_t klass = kSmallAllocMinClass << i;
        auto& bin = cache.bins[i];
        while (bin.count > target && bin.head) {
            auto* block = bin.head;
            bin.head = block->next;
            --bin.count;
#ifdef CNODE_MEMORY_STATS
            --cache.current_depth;
            ++cache.trim_frees;
#endif
            DeallocateRaw(block, klass);
        }
    }
}

[[nodiscard]] inline SmallAllocCacheStats SnapshotSmallAllocCacheStats() noexcept {
    auto& cache = TlsSmallAllocCache();
    SmallAllocCacheStats stats;
#ifdef CNODE_MEMORY_STATS
    stats.cache_depth = cache.current_depth;
#else
    stats.cache_depth = SmallCacheDepth(cache);
#endif
    stats.cache_capacity = kSmallAllocClassCount * kSmallAllocBinCap;
#ifdef CNODE_MEMORY_STATS
    stats.cache_high_water = cache.high_water;
    stats.pop_hits = cache.pop_hits;
    stats.pop_misses = cache.pop_misses;
    stats.push_hits = cache.push_hits;
    stats.push_drops = cache.push_drops;
    stats.trim_frees = cache.trim_frees;
#endif
    return stats;
}

}  // namespace detail

inline void* AllocateSmallRaw(size_t size,
                              size_t alignment = alignof(std::max_align_t)) noexcept {
    return detail::AllocateSmallCached(size, alignment);
}

inline void DeallocateSmallRaw(void* p,
                               size_t size,
                               size_t alignment = alignof(std::max_align_t)) noexcept {
    detail::DeallocateSmallCached(p, size, alignment);
}

inline void CollectCurrentThread(bool force) noexcept {
    detail::TrimSmallAllocCache(force);
}

[[nodiscard]] inline SmallAllocCacheStats SnapshotThreadSmallAllocCacheStats() noexcept {
    return detail::SnapshotSmallAllocCacheStats();
}

inline void CollectSteady() noexcept {
#if defined(__GLIBC__)
    (void)::malloc_trim(0);
#endif
}

inline void CollectBurst() noexcept {
#if defined(__GLIBC__)
    (void)::malloc_trim(0);
#endif
}

inline void MarkThreadPoolThread() noexcept {}

class ThreadScope final {
public:
    ThreadScope() noexcept = default;
    ThreadScope(const ThreadScope&) = delete;
    ThreadScope& operator=(const ThreadScope&) = delete;
};

template <class T>
class ThreadLocalAllocator {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;
    using is_always_equal = std::true_type;

    ThreadLocalAllocator() noexcept = default;

    template <class U>
    ThreadLocalAllocator(const ThreadLocalAllocator<U>&) noexcept {}

    template <class U>
    struct rebind {
        using other = ThreadLocalAllocator<U>;
    };

    [[nodiscard]] T* allocate(size_type n) {
        if (n > max_size()) {
            throw std::bad_array_new_length();
        }
        size_t bytes = n * sizeof(T);
        if (bytes == 0) {
            bytes = 1;
        }

        void* raw = bytes <= detail::kSmallAllocMaxClass
            ? AllocateSmallRaw(bytes, alignof(T))
            : AllocateRaw(bytes, alignof(T));
        if (!raw) {
            throw std::bad_alloc();
        }
        return static_cast<T*>(raw);
    }

    void deallocate(T* p, size_type n) noexcept {
        size_t bytes = n * sizeof(T);
        if (bytes == 0) {
            bytes = 1;
        }
        if (bytes <= detail::kSmallAllocMaxClass) {
            DeallocateSmallRaw(p, bytes, alignof(T));
            return;
        }
        DeallocateRaw(p, bytes, alignof(T));
    }

    [[nodiscard]] constexpr size_type max_size() const noexcept {
        return std::numeric_limits<size_type>::max() / sizeof(T);
    }
};

template <class T, class U>
[[nodiscard]] constexpr bool operator==(const ThreadLocalAllocator<T>&,
                                        const ThreadLocalAllocator<U>&) noexcept {
    return true;
}

template <class T, class U>
[[nodiscard]] constexpr bool operator!=(const ThreadLocalAllocator<T>&,
                                        const ThreadLocalAllocator<U>&) noexcept {
    return false;
}

template <class T>
using ThreadLocalVector = std::vector<T, ThreadLocalAllocator<T>>;

template <class T>
using ThreadLocalDeque = std::deque<T, ThreadLocalAllocator<T>>;

template <class T>
using ThreadLocalList = std::list<T, ThreadLocalAllocator<T>>;

template <class Key,
          class Value,
          class Compare = std::less<Key>>
using ThreadLocalMap =
    std::map<Key, Value, Compare,
             ThreadLocalAllocator<std::pair<const Key, Value>>>;

template <class Key, class Value,
          class Hash = std::hash<Key>,
          class Eq = std::equal_to<Key>>
using ThreadLocalUnorderedMap =
    std::unordered_map<Key, Value, Hash, Eq,
                       ThreadLocalAllocator<std::pair<const Key, Value>>>;

template <class Key,
          class Hash = std::hash<Key>,
          class Eq = std::equal_to<Key>>
using ThreadLocalUnorderedSet =
    std::unordered_set<Key, Hash, Eq, ThreadLocalAllocator<Key>>;

using ThreadLocalString =
    std::basic_string<char, std::char_traits<char>, ThreadLocalAllocator<char>>;

using ByteVector = ThreadLocalVector<uint8_t>;

}  // namespace acpp::memory
