#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <limits>
#include <list>
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

inline void* AllocateSmallRaw(size_t size,
                              size_t alignment = alignof(std::max_align_t)) noexcept {
    return AllocateRaw(size, alignment);
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
    return AllocateRaw(count * elem_size, alignment);
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

}  // namespace acpp::memory
