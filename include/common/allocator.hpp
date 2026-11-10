#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <atomic>
#include <cstddef>
#include <cstdint>
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
#include <mimalloc.h>

namespace memory {

#ifdef CNODE_TEST_BUFFER_STATS
namespace detail {
inline thread_local uint64_t test_buffers_live = 0;
inline thread_local uint64_t test_buffers_peak = 0;
}
inline void OnBufferNew() noexcept {
    ++detail::test_buffers_live;
    if (detail::test_buffers_live > detail::test_buffers_peak)
        detail::test_buffers_peak = detail::test_buffers_live;
}
inline void OnBufferFree() noexcept { --detail::test_buffers_live; }
#else
inline void OnBufferNew() noexcept {}
inline void OnBufferFree() noexcept {}
#endif

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

class worker_memory;
[[nodiscard]] worker_memory& ThreadMemoryPool() noexcept;

#ifdef CNODE_TEST_ALLOCATOR_FAULT
inline thread_local bool reject_next_process_allocation = false;
inline thread_local size_t rejected_process_allocations = 0;
#endif

namespace detail {

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

// Worker-local pool: one mimalloc first-class heap. mimalloc keeps this heap's
// blocks in pages of their own (never shared with another heap), segregated by
// size class with page metadata outside the blocks. A page whose blocks are all
// free returns to the shared arena and is purged after mi_option_purge_delay;
// Collect() forces that for this heap's thread-local state.
//
// Single-thread ownership: the first allocation binds the owner thread and the
// heap's thread-bound theap. Allocation, release and Collect() on any other
// thread terminate, as does releasing a block this heap does not own.
class worker_memory final : public std::pmr::memory_resource {
public:
    // Page-level view of this heap; computed by visiting its pages.
    struct Footprint {
        std::size_t committed_bytes = 0;
        std::size_t used_bytes = 0;
        std::size_t pages = 0;
    };

    worker_memory() : heap_(mi_heap_new()) {
        if (!heap_) throw std::bad_alloc();
    }

    worker_memory(const worker_memory&) = delete;
    worker_memory& operator=(const worker_memory&) = delete;

    ~worker_memory() override {
        // The owner thread's mimalloc state may already be torn down at thread
        // exit; only the heap itself is touched here, never theap_.
        if (live_allocations_ != 0) std::terminate();
        mi_heap_delete(heap_);
    }

    // Visits every page of this heap: diagnostics and tests only, never on a
    // request path. Requires that no other thread uses this heap meanwhile.
    [[nodiscard]] Footprint GetFootprint() const noexcept {
        Footprint footprint;
        (void)mi_heap_visit_blocks(heap_, false, &AccumulateArea, &footprint);
        return footprint;
    }

    [[nodiscard]] std::size_t OutstandingAllocations() const noexcept {
        return live_allocations_;
    }

    // Returns this heap's empty pages to the arena and purges them now.
    void Collect() noexcept {
        if (!theap_) return;
        RequireOwnerThread();
        mi_theap_collect(theap_, true);
    }

    [[nodiscard]] std::pmr::memory_resource* resource() & noexcept { return this; }
    [[nodiscard]] std::pmr::memory_resource* resource() const& noexcept {
        return const_cast<worker_memory*>(this);
    }
    [[nodiscard]] std::pmr::memory_resource* resource() && = delete;
    [[nodiscard]] std::pmr::memory_resource* resource() const&& = delete;

    [[nodiscard]] void* Allocate(std::size_t bytes, std::size_t alignment) noexcept {
        const auto token = detail::CurrentThreadToken();
        if (owner_token_ != token) {
            if (owner_token_ != 0) std::terminate();
            owner_token_ = token;
        }
        if (!theap_ && !(theap_ = mi_heap_theap(heap_))) return nullptr;
        if (!ValidAlignment(alignment)) return nullptr;
        void* block = nullptr;
        if (alignment > kNaturalAlignment) {
            block = mi_theap_malloc_aligned(theap_, bytes, alignment);
        } else if (bytes <= std::numeric_limits<std::size_t>::max() - (alignment - 1)) {
            // A size class that is a multiple of the alignment starts every
            // block on that alignment, so no aligned slow path is needed.
            block = mi_theap_malloc(theap_, RoundUp(bytes, alignment));
        }
        if (block) ++live_allocations_;
        return block;
    }

    void Deallocate(void* pointer, std::size_t = 0, std::size_t = 0) noexcept {
        if (!pointer) return;
        RequireOwnerThread();
        if (mi_heap_of(pointer) != heap_) std::terminate();
        mi_free(pointer);
        --live_allocations_;
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
    // Every mimalloc page starts its first block on 16 bytes (MI_MAX_ALIGN_SIZE).
    static constexpr std::size_t kNaturalAlignment = 16;

    static bool AccumulateArea(const mi_heap_t*, const mi_heap_area_t* area, void*,
                               std::size_t, void* argument) noexcept {
        auto& footprint = *static_cast<Footprint*>(argument);
        footprint.committed_bytes += area->committed;
        footprint.used_bytes += area->used * area->full_block_size;
        ++footprint.pages;
        return true;
    }

    void RequireOwnerThread() const noexcept {
        if (owner_token_ != detail::CurrentThreadToken()) std::terminate();
    }

    mi_heap_t* const heap_;
    mi_theap_t* theap_ = nullptr;
    std::uintptr_t owner_token_ = 0;
    std::size_t live_allocations_ = 0;
};

[[nodiscard]] inline std::pmr::memory_resource* worker_pool_resource() noexcept;

[[nodiscard]] inline std::pmr::memory_resource* CurrentResource() noexcept {
    auto* default_resource = std::pmr::get_default_resource();
    return default_resource == std::pmr::new_delete_resource()
        ? worker_pool_resource()
        : default_resource;
}
[[nodiscard]] inline worker_memory& ThreadMemoryPool() noexcept {
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

// Releases a block of the calling thread's pool; a block of any other pool or
// thread terminates.
inline void DeallocatePmr(void* p, size_t size = 0,
                          size_t alignment = 0) noexcept {
    ThreadMemoryPool().Deallocate(p, size, alignment);
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
    static void* operator new(std::size_t, void* p) noexcept { return p; }
    static void operator delete(void*, void*) noexcept {}
    static void operator delete(void* p) noexcept { DeallocatePmr(p); }
    static void operator delete(void* p, std::size_t) noexcept { DeallocatePmr(p); }
    static void operator delete(void* p, std::align_val_t) noexcept { DeallocatePmr(p); }
    static void operator delete(void* p, std::size_t, std::align_val_t) noexcept { DeallocatePmr(p); }
};

class ThreadMemoryResource final : public std::pmr::memory_resource {
protected:
    void* do_allocate(size_t bytes, size_t alignment) override {
#ifdef CNODE_TEST_ALLOCATOR_FAULT
        if (reject_next_pmr_allocation) {
            reject_next_pmr_allocation = false;
            ++rejected_pmr_allocations;
            throw std::bad_alloc();
        }
#endif
        if (void* p = ThreadMemoryPool().Allocate(bytes, alignment)) return p;
        throw std::bad_alloc();
    }
    void do_deallocate(void* p, size_t bytes, size_t alignment) override {
        DeallocatePmr(p, bytes, alignment);
    }
    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

[[nodiscard]] inline std::pmr::memory_resource* worker_pool_resource() noexcept {
    static ThreadMemoryResource resource;
    return &resource;
}

inline void ConfigureProcessAllocator() noexcept {
    DisableTransparentHugePages();
    mi_option_set(mi_option_allow_thp, 0);
    mi_option_set(mi_option_purge_delay, 10);
    std::pmr::set_default_resource(worker_pool_resource());
}

inline void CollectBurst() noexcept {
    ThreadMemoryPool().Collect();
    mi_collect(true);
}

template <class T>
class ThreadLocalAllocator {
    template <class U>
    struct UsesAllocatorConstruction
        : std::uses_allocator<U, std::pmr::polymorphic_allocator<T>> {};
    // [allocator.uses.construction] propagates into pair members even though
    // uses_allocator<pair<...>> itself is false.
    template <class First, class Second>
    struct UsesAllocatorConstruction<std::pair<First, Second>> : std::true_type {};

public:
    using value_type = T;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    ThreadLocalAllocator() noexcept : ThreadLocalAllocator(CurrentResource()) {}
    ThreadLocalAllocator(std::pmr::memory_resource* resource) noexcept
        : resource_(resource ? resource : CurrentResource()) {}
    ThreadLocalAllocator(const ThreadLocalAllocator&) noexcept = default;
    ThreadLocalAllocator& operator=(const ThreadLocalAllocator&) noexcept = default;
    ThreadLocalAllocator(ThreadLocalAllocator&&) noexcept = default;
    ThreadLocalAllocator& operator=(ThreadLocalAllocator&&) noexcept = default;
    template <class U>
    ThreadLocalAllocator(const ThreadLocalAllocator<U>& other) noexcept
        : resource_(other.resource_) {}
    template <class U>
    ThreadLocalAllocator(const std::pmr::polymorphic_allocator<U>& other) noexcept
        : ThreadLocalAllocator(other.resource()) {}
    template <class U> struct rebind { using other = ThreadLocalAllocator<U>; };
    [[nodiscard]] ThreadLocalAllocator select_on_container_copy_construction() const noexcept {
        return {};
    }
    [[nodiscard]] std::pmr::memory_resource* resource() const noexcept {
        return resource_;
    }
    [[nodiscard]] T* allocate(std::size_t count) {
        return std::pmr::polymorphic_allocator<T>(resource_).allocate(count);
    }
    void deallocate(T* pointer, std::size_t count) noexcept {
        std::pmr::polymorphic_allocator<T>(resource_).deallocate(pointer, count);
    }
    template <class U, class... Args>
        requires (UsesAllocatorConstruction<std::remove_cv_t<U>>::value)
    void construct(U* pointer, Args&&... args) {
        std::pmr::polymorphic_allocator<T>(resource_).construct(
            pointer, std::forward<Args>(args)...);
    }
    template <class U>
    [[nodiscard]] bool operator==(const ThreadLocalAllocator<U>& other) const noexcept {
        return resource_ == other.resource_ || resource_->is_equal(*other.resource_);
    }

private:
    template <class> friend class ThreadLocalAllocator;

    std::pmr::memory_resource* resource_;
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

    RingDeque() noexcept : RingDeque(CurrentResource()) {}
    explicit RingDeque(std::pmr::memory_resource* resource) noexcept
        : resource_(resource ? resource : CurrentResource()) {}
    explicit RingDeque(const allocator_type& alloc) noexcept
        : RingDeque(alloc.resource()) {}
    RingDeque(const RingDeque& other)
        : RingDeque(CurrentResource()) {
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
            // 右值可能嵌在旧元素中；先接管其存储，再析构旧元素。
            RingDeque incoming(std::move(other));
            swap(incoming);
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
        } else if (capacity_ >= 64 && size_ <= capacity_ / 8) {
            shrink_to_fit();
        }
    }

    void pop_back() noexcept {
        const std::size_t idx = (head_ + size_ - 1) & (capacity_ - 1);
        std::destroy_at(data_ + idx);
        if (--size_ == 0) {
            ReleaseStorage();
        } else if (capacity_ >= 64 && size_ <= capacity_ / 8) {
            shrink_to_fit();
        }
    }

    void clear() noexcept {
        for (std::size_t i = 0; i < size_; ++i) {
            std::destroy_at(data_ + ((head_ + i) & (capacity_ - 1)));
        }
        size_ = 0;
        ReleaseStorage();
    }

    [[gnu::noinline]] void shrink_to_fit() noexcept {
        if (size_ == 0) {
            ReleaseStorage();
            return;
        }
        if constexpr (std::is_nothrow_move_constructible_v<T>) {
            if (capacity_ < 64 || size_ > capacity_ / 4) {
                return;
            }
            std::size_t target_cap = 4;
            while (target_cap < size_ * 2) {
                target_cap *= 2;
            }
            if (target_cap >= capacity_) {
                return;
            }
            try {
                T* next_data = static_cast<T*>(
                    resource_->allocate(target_cap * sizeof(T), alignof(T)));
                for (std::size_t i = 0; i < size_; ++i) {
                    const std::size_t idx = (head_ + i) & (capacity_ - 1);
                    ConstructRelocatedAt(next_data + i, data_[idx]);
                    std::destroy_at(data_ + idx);
                }
                resource_->deallocate(data_, capacity_ * sizeof(T), alignof(T));
                data_ = next_data;
                head_ = 0;
                capacity_ = target_cap;
            } catch (...) {
            }
        }
    }

    void swap(RingDeque& other) noexcept {
        if (this == &other) return;
        std::swap(resource_, other.resource_);
        std::swap(data_, other.data_);
        std::swap(head_, other.head_);
        std::swap(size_, other.size_);
        std::swap(capacity_, other.capacity_);
    }

private:
    template <class... Args>
    void ConstructAt(T* ptr, Args&&... args) {
        // The live backing allocation already retains its domain resource.
        std::pmr::polymorphic_allocator<T>(resource_).construct(
            ptr, std::forward<Args>(args)...);
    }

    void ConstructRelocatedAt(T* ptr, T& value)
        noexcept(std::is_nothrow_move_constructible_v<T>) {
        if constexpr (std::is_nothrow_move_constructible_v<T>) {
            // 同一队列内保留元素原有分配器，匹配已证明不抛异常的普通移动。
            std::construct_at(ptr, std::move(value));
        } else {
            ConstructAt(ptr, std::move_if_noexcept(value));
        }
    }

    // Keep the shared drain path out of callers to bound executable footprint.
    [[gnu::noinline]] void ReleaseStorage() noexcept {
        auto* data = std::exchange(data_, nullptr);
        const auto capacity = std::exchange(capacity_, 0);
        head_ = 0;
        if (data) {
            // Detach storage before releasing its last domain lifetime.
            resource_->deallocate(data, capacity * sizeof(T), alignof(T));
        }
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
                ConstructRelocatedAt(
                    next_data + constructed, data_[(head_ + constructed) & (capacity_ - 1)]);
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

    // Keep allocation and relocation out of the common insertion path.
    template <typename... Args>
    [[gnu::noinline]] T& GrowEmplace(bool at_back, Args&&... args) {
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
                ConstructRelocatedAt(
                    next_data + old_offset + constructed, data_[(head_ + constructed) & (capacity_ - 1)]);
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

} // namespace memory
