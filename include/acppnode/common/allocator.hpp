#pragma once

#include "acppnode/common/memory_stats.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <list>
#include <map>
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

inline void ConfigureProcessGlibc() noexcept {
#if defined(__GLIBC__)
    (void)::mallopt(M_ARENA_MAX, kGlibcArenaMax);
    (void)::mallopt(M_TRIM_THRESHOLD, kGlibcTrimThreshold);
    (void)::mallopt(M_MMAP_THRESHOLD, kGlibcMmapThreshold);
#endif
}

[[nodiscard]] inline void* AllocatePmr(
    size_t size,
    size_t alignment = alignof(std::max_align_t)) noexcept {
    if (size == 0) {
        size = 1;
    }
    if (alignment > alignof(std::max_align_t)) {
        return ::operator new(size, std::align_val_t{alignment}, std::nothrow);
    }
    return ::operator new(size, std::nothrow);
}

inline void DeallocatePmr(
    void* p,
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

// Per-thread PMR identity: ::operator new, no pool. Default resource uses
// the same allocate path; set_default_resource needs a process-stable object.
class ThreadNewResource final : public std::pmr::memory_resource {
protected:
    void* do_allocate(size_t bytes, size_t alignment) override {
        void* p = AllocatePmr(bytes, alignment);
        if (!p) {
            throw std::bad_alloc();
        }
        return p;
    }

    void do_deallocate(void* p, size_t, size_t alignment) override {
        DeallocatePmr(p, 0, alignment);
    }

    [[nodiscard]] bool do_is_equal(
        const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

inline std::pmr::memory_resource& ThreadMemoryResource() noexcept {
    thread_local ThreadNewResource resource;
    return resource;
}

inline void ConfigureProcessAllocator() noexcept {
    DisableTransparentHugePages();
    ConfigureProcessGlibc();
    static ThreadNewResource default_resource;
    std::pmr::set_default_resource(&default_resource);
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

template <class T>
using ThreadLocalAllocator = std::pmr::polymorphic_allocator<T>;

template <class T>
using ThreadLocalVector = std::pmr::vector<T>;

template <class T>
using ThreadLocalDeque = std::pmr::deque<T>;

template <class T>
using ThreadLocalList = std::pmr::list<T>;

template <class Key,
          class Value,
          class Compare = std::less<Key>>
using ThreadLocalMap = std::pmr::map<Key, Value, Compare>;

template <class Key, class Value,
          class Hash = std::hash<Key>,
          class Eq = std::equal_to<Key>>
using ThreadLocalUnorderedMap = std::pmr::unordered_map<Key, Value, Hash, Eq>;

template <class Key,
          class Hash = std::hash<Key>,
          class Eq = std::equal_to<Key>>
using ThreadLocalUnorderedSet = std::pmr::unordered_set<Key, Hash, Eq>;

using ThreadLocalString = std::pmr::string;

using ByteVector = ThreadLocalVector<uint8_t>;

}  // namespace acpp::memory
