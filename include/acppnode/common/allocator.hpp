#pragma once

#include "acppnode/common/memory_stats.hpp"

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
#include <vector>

#if defined(__linux__)
#include <sys/mman.h>
#include <sys/prctl.h>
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

inline void DisableTransparentHugePages() noexcept {
#if defined(__linux__) && defined(PR_SET_THP_DISABLE)
    (void)::prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
#endif
}

// Every platform must periodically purge idle Worker-local mappings, even
// when a Worker stops allocating after its last connection closes.
inline constexpr bool kAllocatorCollects = true;

inline constexpr int kGlibcArenaMax = 2;
inline constexpr int kGlibcTrimThreshold = 64 * 1024;
inline constexpr int kGlibcMmapThreshold = 64 * 1024;
inline constexpr std::size_t kThreadPoolChunkBytes = 64 * 1024;
inline constexpr std::size_t kThreadPoolMaxClass = 32 * 1024;
inline constexpr std::chrono::milliseconds kThreadPoolPurgeDelay{10};

inline void ConfigureProcessGlibc() noexcept {
#if defined(__GLIBC__)
    (void)::mallopt(M_ARENA_MAX, kGlibcArenaMax);
    (void)::mallopt(M_TRIM_THRESHOLD, kGlibcTrimThreshold);
    (void)::mallopt(M_MMAP_THRESHOLD, kGlibcMmapThreshold);
#endif
}

struct BlockPrefix {
    std::size_t bytes = 0;
    std::size_t alignment = 0;
    std::thread::id owner{};
};

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
    if (address) {
        ::munmap(address, bytes);
    }
#elif defined(_WIN32)
    if (address) {
        ::VirtualFree(address, 0, 0x8000u);
    }
#else
    ::operator delete(address);
    (void)bytes;
#endif
}

[[nodiscard]] inline std::size_t RoundUp(std::size_t value, std::size_t unit) noexcept {
    return (value + unit - 1) & ~(unit - 1);
}

[[nodiscard]] inline std::size_t PowerOfTwoAtLeast(std::size_t value) noexcept {
    std::size_t power = 1;
    while (power < value && power <= (std::numeric_limits<std::size_t>::max() / 2)) {
        power *= 2;
    }
    return power < value ? 0 : power;
}

class ReturningThreadPool final : public std::pmr::memory_resource {
public:
    struct Footprint {
        std::size_t mapped_bytes = 0;
        std::size_t direct_bytes = 0;
        std::size_t idle_bytes = 0;
        std::size_t chunks = 0;
    };

    ReturningThreadPool() = default;
    ReturningThreadPool(const ReturningThreadPool&) = delete;
    ReturningThreadPool& operator=(const ReturningThreadPool&) = delete;

    void Purge() noexcept {
        next_purge_ = {};
        PurgeExpired();
    }

    [[nodiscard]] Footprint GetFootprint() const noexcept { return footprint_; }

    ~ReturningThreadPool() override {
        Chunk* chunk = all_;
        while (chunk) {
            Chunk* next = chunk->all_next;
            OsUnmap(chunk->map_base, chunk->map_bytes);
            chunk = next;
        }
    }

    [[nodiscard]] void* Allocate(std::size_t bytes, std::size_t alignment) noexcept {
        PurgeExpired();
        if (alignment == 0 || (alignment & (alignment - 1)) != 0) {
            return nullptr;
        }
        const std::size_t stride = Stride(bytes, alignment);
        if (stride == 0) {
            return nullptr;
        }
        if (stride > kThreadPoolMaxClass) {
            return AllocateDirect(bytes, alignment);
        }
        const std::size_t class_index = ClassIndex(stride);
        if (class_index >= classes_.size()) {
            return AllocateDirect(bytes, alignment);
        }
        // These mappings contain one allocation and are released directly;
        // looking for reusable chunks would scan every live connection.
        if (stride >= 4096) {
            Chunk* chunk = MapChunk(stride, class_index, alignment);
            if (!chunk) {
                return nullptr;
            }
            void* result = Carve(*chunk, stride, alignment);
            if (!result) {
                ReleaseChunk(*chunk);
            }
            return result;
        }
        Class& cls = classes_[class_index];
        if (void* reused = TakeFree(cls, bytes, alignment)) {
            return reused;
        }
        if (cls.current && CanCarve(*cls.current, stride, alignment)) {
            return Carve(*cls.current, stride, alignment);
        }
        if (Chunk* idle = FindIdle(class_index, stride)) {
            cls.current = idle;
            return Carve(*idle, stride, alignment);
        }
        Chunk* chunk = MapChunk(stride, class_index, alignment);
        if (!chunk) {
            return nullptr;
        }
        cls.current = chunk;
        return Carve(*chunk, stride, alignment);
    }

    void Deallocate(void* pointer, std::size_t bytes = 0,
                    std::size_t alignment = 0) noexcept {
        if (!pointer) {
            return;
        }
        auto* header = reinterpret_cast<SlotHeader*>(
            static_cast<std::byte*>(pointer) - sizeof(SlotHeader));
        auto* chunk = header->chunk;
        if (!chunk || chunk->magic != kChunkMagic ||
            chunk->map_base == nullptr || chunk->live == 0) {
            return;
        }
        const auto address = reinterpret_cast<std::uintptr_t>(pointer);
        const auto base = reinterpret_cast<std::uintptr_t>(chunk->map_base);
        if (address < base || address >= base + chunk->map_bytes) {
            return;
        }
        --chunk->live;
        if (chunk->live == 0) {
            if (chunk->direct) {
                ReleaseChunk(*chunk);
            } else {
                UnlinkRecyclable(*chunk);
                chunk->free_head = nullptr;
                chunk->bump = static_cast<std::byte*>(chunk->map_base) + sizeof(Chunk);
                MarkIdle(*chunk);
                PurgeExpired();
            }
            return;
        }
        // Capacity belongs to the physical slot, not to the last request's
        // alignment. Recomputing it after reuse could enlarge a shorter slot
        // and overwrite the next live allocation.
        if (chunk->direct || header->capacity < sizeof(FreeNode) ||
            bytes > header->capacity ||
            (alignment != 0 &&
             ((alignment & (alignment - 1)) != 0 ||
              address % alignment != 0))) {
            return;
        }
        auto* node = static_cast<FreeNode*>(pointer);
        node->capacity = header->capacity;
        node->next = chunk->free_head;
        chunk->free_head = node;
        if (!chunk->in_recyclable) {
            chunk->in_recyclable = true;
            chunk->rec_prev = nullptr;
            chunk->rec_next = classes_[chunk->class_index].recyclable;
            if (chunk->rec_next) {
                chunk->rec_next->rec_prev = chunk;
            }
            classes_[chunk->class_index].recyclable = chunk;
        }
    }

protected:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
        void* pointer = Allocate(bytes, alignment);
        if (!pointer) {
            throw std::bad_alloc();
        }
        return pointer;
    }

    void do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment) override {
        Deallocate(pointer, bytes, alignment);
    }

    [[nodiscard]] bool do_is_equal(
        const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }

private:
    struct FreeNode {
        FreeNode* next = nullptr;
        std::size_t capacity = 0;
    };

    static constexpr std::uint32_t kChunkMagic = 0xC0DEC0DEu;

    struct Chunk;
    struct SlotHeader {
        std::size_t capacity = 0;
        Chunk* chunk = nullptr;
    };

    struct Chunk {
        std::uint32_t magic = kChunkMagic;
        Chunk* all_next = nullptr;
        Chunk* all_prev = nullptr;
        Chunk* rec_next = nullptr;
        Chunk* rec_prev = nullptr;
        void* map_base = nullptr;
        std::size_t map_bytes = 0;
        std::size_t stride = 0;
        std::uint32_t live = 0;
        std::uint32_t class_index = 0;
        bool direct = false;
        bool idle = false;
        std::chrono::steady_clock::time_point idle_at{};
        bool in_recyclable = false;
        FreeNode* free_head = nullptr;
        std::byte* bump = nullptr;
        std::byte* end = nullptr;
    };

    struct Class {
        Chunk* current = nullptr;
        Chunk* recyclable = nullptr;
    };

    [[nodiscard]] static std::size_t Lead(std::size_t alignment) noexcept {
        return RoundUp(sizeof(SlotHeader), alignment);
    }

    [[nodiscard]] static std::size_t Stride(
        std::size_t bytes, std::size_t alignment) noexcept {
        const std::size_t lead = Lead(alignment);
        if (lead == 0 || bytes > std::numeric_limits<std::size_t>::max() - lead) {
            return 0;
        }
        return PowerOfTwoAtLeast(std::max(lead + bytes, std::size_t{64}));
    }

    [[nodiscard]] static std::size_t ClassIndex(std::size_t stride) noexcept {
        std::size_t index = 0;
        for (std::size_t size = 64; size < stride; size *= 2) {
            ++index;
        }
        return index;
    }

    [[nodiscard]] static bool CanCarve(
        const Chunk& chunk, std::size_t stride, std::size_t alignment) noexcept {
        const auto start = RoundUp(
            reinterpret_cast<std::uintptr_t>(chunk.bump), alignment);
        return start + stride <= reinterpret_cast<std::uintptr_t>(chunk.end);
    }

    [[nodiscard]] Chunk* FindIdle(std::size_t class_index, std::size_t stride) noexcept {
        for (Chunk* chunk = all_; chunk; chunk = chunk->all_next) {
            if (chunk->idle && !chunk->direct &&
                chunk->class_index == class_index && chunk->stride == stride) {
                if (std::chrono::steady_clock::now() - chunk->idle_at >=
                    kThreadPoolPurgeDelay) {
                    ReleaseChunk(*chunk);
                    return nullptr;
                }
                return chunk;
            }
        }
        return nullptr;
    }

    [[nodiscard]] void* TakeFree(
        Class& cls, std::size_t bytes, std::size_t alignment) noexcept {
        for (Chunk* chunk = cls.recyclable; chunk; chunk = chunk->rec_next) {
            FreeNode** link = &chunk->free_head;
            while (*link) {
                FreeNode* node = *link;
                if (node->capacity >= bytes &&
                    reinterpret_cast<std::uintptr_t>(node) % alignment == 0) {
                    *link = node->next;
                    if (!chunk->free_head) {
                        UnlinkRecyclable(*chunk);
                    }
                    ++chunk->live;
                    return node;
                }
                link = &node->next;
            }
        }
        return nullptr;
    }

    [[nodiscard]] void* Carve(
        Chunk& chunk, std::size_t stride, std::size_t alignment) noexcept {
        const auto start = RoundUp(
            reinterpret_cast<std::uintptr_t>(chunk.bump), alignment);
        if (start + stride > reinterpret_cast<std::uintptr_t>(chunk.end)) {
            return nullptr;
        }
        auto* user = reinterpret_cast<std::byte*>(start) + Lead(alignment);
        auto* header = reinterpret_cast<SlotHeader*>(user - sizeof(SlotHeader));
        header->capacity = stride - Lead(alignment);
        header->chunk = &chunk;
        chunk.bump = reinterpret_cast<std::byte*>(start + stride);
        if (chunk.live == 0) {
            MarkUsed(chunk);
        }
        ++chunk.live;
        return user;
    }

    [[nodiscard]] void* AllocateDirect(
        std::size_t bytes, std::size_t alignment) noexcept {
        const std::size_t lead = Lead(alignment);
        if (alignment > std::numeric_limits<std::size_t>::max() - sizeof(Chunk) ||
            lead > std::numeric_limits<std::size_t>::max() - sizeof(Chunk) - alignment ||
            bytes > std::numeric_limits<std::size_t>::max() - sizeof(Chunk) - alignment - lead) {
            return nullptr;
        }
        const std::size_t usable = sizeof(Chunk) + alignment + lead + bytes;
        Chunk* chunk = MapRegion(usable, bytes, 0, true);
        if (!chunk) {
            return nullptr;
        }
        const auto start = RoundUp(
            reinterpret_cast<std::uintptr_t>(chunk->bump), alignment);
        auto* user = reinterpret_cast<std::byte*>(start) + lead;
        if (reinterpret_cast<std::uintptr_t>(user) + bytes >
            reinterpret_cast<std::uintptr_t>(chunk->end)) {
            ReleaseChunk(*chunk);
            return nullptr;
        }
        auto* header = reinterpret_cast<SlotHeader*>(user - sizeof(SlotHeader));
        header->capacity = bytes;
        header->chunk = chunk;
        chunk->bump = user + bytes;
        ++chunk->live;
        return user;
    }

    void MarkIdle(Chunk& chunk) noexcept {
        if (chunk.idle || chunk.direct) {
            return;
        }
        chunk.idle = true;
        footprint_.idle_bytes += chunk.map_bytes;
        chunk.idle_at = std::chrono::steady_clock::now();
    }

    void MarkUsed(Chunk& chunk) noexcept {
        if (!chunk.idle) {
            return;
        }
        chunk.idle = false;
        footprint_.idle_bytes -= chunk.map_bytes;
    }

    void PurgeExpired() noexcept {
        const auto now = std::chrono::steady_clock::now();
        if (now < next_purge_) {
            return;
        }
        next_purge_ = now + kThreadPoolPurgeDelay;
        Chunk* chunk = all_;
        while (chunk) {
            Chunk* next = chunk->all_next;
            if (chunk->idle && !chunk->direct &&
                now - chunk->idle_at >= kThreadPoolPurgeDelay) {
                ReleaseChunk(*chunk);
            }
            chunk = next;
        }
    }

    [[nodiscard]] Chunk* MapChunk(
        std::size_t stride, std::size_t class_index, std::size_t alignment) noexcept {
        const bool alone = stride >= 4096;
        if (alone && (alignment > std::numeric_limits<std::size_t>::max() - sizeof(Chunk) ||
                      stride > std::numeric_limits<std::size_t>::max() - sizeof(Chunk) - alignment)) {
            return nullptr;
        }
        const std::size_t usable = alone
            ? sizeof(Chunk) + stride + alignment
            : kThreadPoolChunkBytes;
        return MapRegion(usable, stride, class_index, alone);
    }

    [[nodiscard]] Chunk* MapRegion(
        std::size_t usable,
        std::size_t stride,
        std::size_t class_index,
        bool direct) noexcept {
        const std::size_t page = 4096;
        if (usable > std::numeric_limits<std::size_t>::max() - (page - 1)) {
            return nullptr;
        }
        const std::size_t map_bytes = RoundUp(usable, page);
        void* mapped = OsMap(map_bytes);
        if (!mapped) {
            return nullptr;
        }
        auto* chunk = new (mapped) Chunk;
        chunk->magic = kChunkMagic;
        chunk->map_base = mapped;
        chunk->map_bytes = map_bytes;
        chunk->stride = stride;
        chunk->class_index = static_cast<std::uint32_t>(class_index);
        chunk->direct = direct;
        chunk->bump = static_cast<std::byte*>(mapped) + sizeof(Chunk);
        chunk->end = static_cast<std::byte*>(mapped) + map_bytes;
        footprint_.mapped_bytes += map_bytes;
        footprint_.direct_bytes += direct ? map_bytes : 0;
        ++footprint_.chunks;
        LinkAll(*chunk);
        return chunk;
    }

    void ReleaseChunk(Chunk& chunk) noexcept {
        Class& cls = classes_[chunk.class_index];
        if (cls.current == &chunk) {
            cls.current = nullptr;
        }
        UnlinkRecyclable(chunk);
        UnlinkAll(chunk);
        footprint_.mapped_bytes -= chunk.map_bytes;
        footprint_.direct_bytes -= chunk.direct ? chunk.map_bytes : 0;
        footprint_.idle_bytes -= chunk.idle ? chunk.map_bytes : 0;
        --footprint_.chunks;
        void* mapped = chunk.map_base;
        const std::size_t bytes = chunk.map_bytes;
        chunk.~Chunk();
        OsUnmap(mapped, bytes);
    }

    void LinkAll(Chunk& chunk) noexcept {
        chunk.all_prev = nullptr;
        chunk.all_next = all_;
        if (all_) {
            all_->all_prev = &chunk;
        }
        all_ = &chunk;
    }

    void UnlinkAll(Chunk& chunk) noexcept {
        if (chunk.all_prev) {
            chunk.all_prev->all_next = chunk.all_next;
        } else {
            all_ = chunk.all_next;
        }
        if (chunk.all_next) {
            chunk.all_next->all_prev = chunk.all_prev;
        }
        chunk.all_next = nullptr;
        chunk.all_prev = nullptr;
    }

    void UnlinkRecyclable(Chunk& chunk) noexcept {
        if (!chunk.in_recyclable) {
            return;
        }
        Class& cls = classes_[chunk.class_index];
        if (chunk.rec_prev) {
            chunk.rec_prev->rec_next = chunk.rec_next;
        } else {
            cls.recyclable = chunk.rec_next;
        }
        if (chunk.rec_next) {
            chunk.rec_next->rec_prev = chunk.rec_prev;
        }
        chunk.rec_next = nullptr;
        chunk.rec_prev = nullptr;
        chunk.in_recyclable = false;
    }

    std::array<Class, 10> classes_{};
    Chunk* all_ = nullptr;
    Footprint footprint_{};
    std::chrono::steady_clock::time_point next_purge_{};
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
    size_t size,
    size_t alignment = alignof(std::max_align_t)) noexcept {
#ifdef CNODE_TEST_ALLOCATOR_FAULT
    if (reject_next_pmr_allocation) {
        reject_next_pmr_allocation = false;
        ++rejected_pmr_allocations;
        return nullptr;
    }
#endif
    if (size == 0) {
        size = 1;
    }
    if (alignment < alignof(void*)) {
        alignment = alignof(void*);
    }

    const size_t prefix = sizeof(BlockPrefix);
    const size_t link = sizeof(void*);
    const size_t align = std::max(alignment, alignof(BlockPrefix));
    if (align > std::numeric_limits<size_t>::max() - prefix - link ||
        size > std::numeric_limits<size_t>::max() - prefix - link - align) {
        return nullptr;
    }
    const size_t bytes = prefix + align + link + size;
    void* raw = ThreadPool().Allocate(bytes, align);
    if (!raw) {
        return nullptr;
    }

    auto* base = static_cast<std::byte*>(raw);
    void* candidate = base + prefix + link;
    std::size_t space = bytes - prefix - link;
    if (!std::align(alignment, size, candidate, space)) {
        ThreadPool().Deallocate(raw, bytes, align);
        return nullptr;
    }

    auto* user = static_cast<std::byte*>(candidate);
    *reinterpret_cast<void**>(user - link) = raw;
    auto* header = new (raw) BlockPrefix;
    header->bytes = bytes;
    header->alignment = align;
    header->owner = std::this_thread::get_id();
    return user;
}

inline void DeallocatePmr(
    void* p,
    size_t /*size*/ = 0,
    size_t /*alignment*/ = alignof(std::max_align_t)) noexcept {
    if (!p) {
        return;
    }
    void* raw = *reinterpret_cast<void**>(static_cast<std::byte*>(p) - sizeof(void*));
    auto* header = static_cast<BlockPrefix*>(raw);
    if (header->owner != std::this_thread::get_id()) {
        // This violates Worker ownership; freeing on the wrong pool would
        // corrupt both threads, so record the rejected release for diagnosis.
        OnCrossThreadFree();
        return;
    }
    const auto bytes = header->bytes;
    const auto alignment = header->alignment;
    header->~BlockPrefix();
    ThreadPool().Deallocate(raw, bytes, alignment);
}

// 只用于在当前线程创建、并在同一线程销毁的对象。
struct ThreadAllocated {
    static void* operator new(std::size_t size) {
        if (void* pointer = AllocatePmr(size)) {
            return pointer;
        }
        throw std::bad_alloc();
    }

    static void* operator new(std::size_t size, std::align_val_t alignment) {
        if (void* pointer = AllocatePmr(size, static_cast<std::size_t>(alignment))) {
            return pointer;
        }
        throw std::bad_alloc();
    }

    static void operator delete(void* pointer) noexcept {
        DeallocatePmr(pointer);
    }

    static void operator delete(void* pointer, std::size_t) noexcept {
        DeallocatePmr(pointer);
    }

    static void operator delete(void* pointer, std::align_val_t) noexcept {
        DeallocatePmr(pointer);
    }

    static void operator delete(void* pointer, std::size_t, std::align_val_t) noexcept {
        DeallocatePmr(pointer);
    }
};

class ThreadPoolFacade final : public std::pmr::memory_resource {
protected:
    void* do_allocate(size_t bytes, size_t alignment) override {
        void* p = AllocatePmr(bytes, alignment);
        if (!p) {
            throw std::bad_alloc();
        }
        return p;
    }

    void do_deallocate(void* p, size_t bytes, size_t alignment) override {
        DeallocatePmr(p, bytes, alignment);
    }

    [[nodiscard]] bool do_is_equal(
        const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

inline std::pmr::memory_resource& ThreadMemoryResource() noexcept {
    return ThreadPool();
}

extern "C" void cnode_set_tls_buffer_allocator(
    void* (*alloc_fn)(std::size_t),
    void (*free_fn)(void*));

inline void* AllocateTlsReadWriteBuffer(std::size_t size) {
    return AllocatePmr(size);
}

inline void FreeTlsReadWriteBuffer(void* pointer) {
    DeallocatePmr(pointer);
}

inline void ConfigureProcessAllocator() noexcept {
    DisableTransparentHugePages();
    ConfigureProcessGlibc();
    cnode_set_tls_buffer_allocator(
        &AllocateTlsReadWriteBuffer,
        &FreeTlsReadWriteBuffer);
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
    return std::allocate_shared<T>(
        ThreadLocalAllocator<T>{},
        std::forward<Args>(args)...);
}

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
