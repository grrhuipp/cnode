#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <list>
#include <memory>
#include <memory_resource>
#include <new>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

#if !defined(USE_MIMALLOC) && defined(__GLIBC__)
#include <malloc.h>
#endif

#ifdef USE_MIMALLOC
#include <mimalloc.h>
#endif

namespace acpp::memory {

inline void DisableTransparentHugePages() noexcept {
#if defined(__linux__) && defined(PR_SET_THP_DISABLE)
    // VPS kernels often run THP in "always" mode. Proxy workloads churn many
    // small objects, and 2MB anonymous huge pages amplify RSS retention.
    (void)::prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
#endif
}

#ifdef USE_MIMALLOC

inline constexpr long kMimallocPurgeDelayMs = 50;
inline constexpr long kMimallocMinimalPurgeSizeKiB = 16;
inline constexpr bool kAllocatorCollects = true;

namespace detail {

inline thread_local mi_heap_t* g_thread_heap = nullptr;
inline thread_local uint32_t g_thread_scope_depth = 0;

}  // namespace detail

inline mi_heap_t* CurrentThreadHeap() noexcept {
    return detail::g_thread_heap;
}

inline void* AllocateRaw(size_t size,
                         size_t alignment = alignof(std::max_align_t)) noexcept;
inline void DeallocateRaw(void* p,
                          size_t size = 0,
                          size_t alignment = alignof(std::max_align_t)) noexcept;

class ThreadLocalHeapResource final : public std::pmr::memory_resource {
private:
    void* do_allocate(size_t bytes, size_t alignment) override {
        if (void* p = AllocateRaw(bytes, alignment)) {
            return p;
        }
        throw std::bad_alloc();
    }

    void do_deallocate(void* p, size_t bytes, size_t alignment) override {
        DeallocateRaw(p, bytes, alignment);
    }

    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

inline std::pmr::memory_resource* GetThreadLocalHeapResource() noexcept {
    static ThreadLocalHeapResource resource;
    return &resource;
}

inline void ConfigureProcessAllocator() noexcept {
    DisableTransparentHugePages();

    // RSS matters more than virtual retention for long-running proxy workloads.
    // Allow purged pages to be decommitted so connection churn returns memory to
    // the OS instead of keeping it resident in worker heaps.
    mi_option_set_enabled(mi_option_purge_decommits, true);

    const long purge_delay = mi_option_get(mi_option_purge_delay);
    if (purge_delay < 0 || purge_delay > kMimallocPurgeDelayMs) {
        mi_option_set(mi_option_purge_delay, kMimallocPurgeDelayMs);
    }

#if !defined(MI_MALLOC_VERSION) || MI_MALLOC_VERSION < 300
    const long minimal_purge = mi_option_get(mi_option_minimal_purge_size);
    if (minimal_purge <= 0 || minimal_purge > kMimallocMinimalPurgeSizeKiB) {
        mi_option_set(mi_option_minimal_purge_size, kMimallocMinimalPurgeSizeKiB);
    }
#endif

    std::pmr::set_default_resource(GetThreadLocalHeapResource());
}

inline void* AllocateRaw(size_t size,
                         size_t alignment) noexcept {
    mi_heap_t* heap = CurrentThreadHeap();

    if (alignment > alignof(std::max_align_t)) {
        return heap ? mi_heap_malloc_aligned(heap, size, alignment)
                    : mi_malloc_aligned(alignment, size);
    }

    return heap ? mi_heap_malloc(heap, size) : mi_malloc(size);
}

inline void* AllocateSmallRaw(size_t size,
                              size_t alignment = alignof(std::max_align_t)) noexcept {
    if (alignment > alignof(std::max_align_t)) {
        return AllocateRaw(size, alignment);
    }

    mi_heap_t* heap = CurrentThreadHeap();
    return heap ? mi_heap_malloc_small(heap, size) : mi_malloc_small(size);
}

inline void* AllocateArrayRaw(size_t count,
                              size_t elem_size,
                              size_t alignment = alignof(std::max_align_t)) noexcept {
    if (count == 0 || elem_size == 0) {
        count = 1;
        elem_size = 1;
    }

    if (count > std::numeric_limits<size_t>::max() / elem_size) {
        return nullptr;
    }

    const size_t total = count * elem_size;
    mi_heap_t* heap = CurrentThreadHeap();

    if (alignment > alignof(std::max_align_t)) {
        return heap ? mi_heap_malloc_aligned(heap, total, alignment)
                    : mi_malloc_aligned(alignment, total);
    }

    return heap ? mi_heap_mallocn(heap, count, elem_size)
                : mi_mallocn(count, elem_size);
}

inline void DeallocateRaw(void* p,
                          size_t size,
                          size_t alignment) noexcept {
    if (!p) {
        return;
    }

    if (alignment > alignof(std::max_align_t)) {
        if (size != 0) {
            mi_free_size_aligned(p, size, alignment);
        } else {
            mi_free_aligned(p, alignment);
        }
        return;
    }

    if (size != 0) {
        mi_free_size(p, size);
    } else {
        mi_free(p);
    }
}

inline void CollectCurrentThread(bool force) noexcept {
    if (auto* heap = CurrentThreadHeap()) {
        mi_heap_collect(heap, force);
    }
}

inline void CollectSteady() noexcept {
    CollectCurrentThread(false);
    mi_collect(false);
}

inline void CollectBurst() noexcept {
    CollectCurrentThread(true);
    mi_collect(true);
}

inline void MarkThreadPoolThread() noexcept {
#if !defined(MI_MALLOC_VERSION) || MI_MALLOC_VERSION < 300
    mi_thread_set_in_threadpool();
#endif
}

class ThreadScope final {
public:
    ThreadScope() noexcept {
        if (detail::g_thread_scope_depth++ == 0) {
            mi_thread_init();
            detail::g_thread_heap = mi_heap_new();
        }
    }

    ~ThreadScope() noexcept {
        if (detail::g_thread_scope_depth == 0) {
            return;
        }

        if (--detail::g_thread_scope_depth == 0) {
            if (auto* heap = detail::g_thread_heap) {
                mi_heap_collect(heap, true);
                mi_heap_delete(heap);
                detail::g_thread_heap = nullptr;
            }
            mi_collect(true);
            mi_thread_done();
        }
    }

    ThreadScope(const ThreadScope&) = delete;
    ThreadScope& operator=(const ThreadScope&) = delete;
};

template <class T>
class ThreadLocalAllocator {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using propagate_on_container_copy_assignment = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    using is_always_equal = std::true_type;

    ThreadLocalAllocator() noexcept = default;

    template <class U>
    ThreadLocalAllocator(const ThreadLocalAllocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(size_type count) {
        if (count > max_size()) {
            throw std::bad_array_new_length();
        }

        void* raw = AllocateArrayRaw(count, sizeof(T), alignof(T));
        if (!raw) {
            throw std::bad_alloc();
        }
        return static_cast<T*>(raw);
    }

    void deallocate(T* p, size_type count) noexcept {
        size_t bytes = 0;
        if (count != 0 && count <= std::numeric_limits<size_t>::max() / sizeof(T)) {
            bytes = count * sizeof(T);
        }
        DeallocateRaw(p, bytes, alignof(T));
    }

    [[nodiscard]] size_type max_size() const noexcept {
        return std::numeric_limits<size_type>::max() / sizeof(T);
    }

    template <class U>
    struct rebind {
        using other = ThreadLocalAllocator<U>;
    };
};

template <class T, class U>
inline bool operator==(const ThreadLocalAllocator<T>&,
                       const ThreadLocalAllocator<U>&) noexcept {
    return true;
}

template <class T, class U>
inline bool operator!=(const ThreadLocalAllocator<T>&,
                       const ThreadLocalAllocator<U>&) noexcept {
    return false;
}

template <class T>
using ThreadLocalVector = std::vector<T, ThreadLocalAllocator<T>>;

template <class T>
using ThreadLocalDeque = std::deque<T, ThreadLocalAllocator<T>>;

template <class T>
using ThreadLocalList = std::list<T, ThreadLocalAllocator<T>>;

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

#else

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
                         size_t /*alignment*/ = alignof(std::max_align_t)) noexcept {
    return ::operator new(size, std::nothrow);
}
inline void* AllocateSmallRaw(size_t size,
                              size_t /*alignment*/ = alignof(std::max_align_t)) noexcept {
    return ::operator new(size, std::nothrow);
}
inline void* AllocateArrayRaw(size_t count,
                              size_t elem_size,
                              size_t /*alignment*/ = alignof(std::max_align_t)) noexcept {
    if (count == 0 || elem_size == 0) {
        count = 1;
        elem_size = 1;
    }
    if (count > std::numeric_limits<size_t>::max() / elem_size) {
        return nullptr;
    }
    return ::operator new(count * elem_size, std::nothrow);
}
inline void DeallocateRaw(void* p,
                          size_t /*size*/ = 0,
                          size_t /*alignment*/ = alignof(std::max_align_t)) noexcept {
    ::operator delete(p);
}
inline void CollectCurrentThread(bool /*force*/) noexcept {}
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
using ThreadLocalAllocator = std::allocator<T>;

template <class T>
using ThreadLocalVector = std::vector<T, ThreadLocalAllocator<T>>;

template <class T>
using ThreadLocalDeque = std::deque<T, ThreadLocalAllocator<T>>;

template <class T>
using ThreadLocalList = std::list<T, ThreadLocalAllocator<T>>;

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

#endif

}  // namespace acpp::memory
