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

// CNODE_TEST_ALLOCATOR: test-only allocator instrumentation (fault injection
// and release-side ownership checks). It must be defined consistently for
// every translation unit of one binary.
#ifdef CNODE_TEST_ALLOCATOR
inline thread_local bool reject_next_process_allocation = false;
inline thread_local size_t rejected_process_allocations = 0;
inline thread_local bool reject_next_pmr_allocation = false;
inline thread_local size_t rejected_pmr_allocations = 0;
#endif

namespace detail {

[[nodiscard]] inline std::uintptr_t CurrentThreadToken() noexcept {
    thread_local std::uint8_t anchor = 0;
    return reinterpret_cast<std::uintptr_t>(&anchor);
}


[[nodiscard]] inline void* AllocateProcessRaw(std::size_t bytes_value, std::size_t alignment) {
#ifdef CNODE_TEST_ALLOCATOR
    if (reject_next_process_allocation) {
        reject_next_process_allocation = false;
        ++rejected_process_allocations;
        throw std::bad_alloc();
    }
#endif
    if (void* block = mi_malloc_aligned(bytes_value, alignment)) return block;
    throw std::bad_alloc();
}

class process_memory_resource final : public std::pmr::memory_resource {
private:
    void* do_allocate(std::size_t bytes_value, std::size_t alignment) override {
        return AllocateProcessRaw(bytes_value, alignment);
    }
    void do_deallocate(void* block, std::size_t, std::size_t) override {
        mi_free(block);
    }
    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};

} // namespace detail

// Process-lifetime, thread-safe resource backed by mimalloc's thread-local
// heaps without a shared pooling layer. The global default PMR resource is not
// replaced.
[[nodiscard]] inline std::pmr::memory_resource* process_resource() noexcept {
    alignas(detail::process_memory_resource) static std::byte
        storage[sizeof(detail::process_memory_resource)];
    static auto* const resource = ::new (storage) detail::process_memory_resource;
    return resource;
}

// Resolves a caller-supplied resource once at the ownership boundary: storage
// that names no resource lives in the process layer, never in a Worker pool
// chosen from thread state.
[[nodiscard]] inline std::pmr::memory_resource* ResourceOrProcess(
    std::pmr::memory_resource* resource) noexcept {
    return resource ? resource : process_resource();
}

// Worker-local pool: one mimalloc first-class heap. mimalloc keeps this heap's
// blocks in pages of their own (never shared with another heap), segregated by
// size class with page metadata outside the blocks. A page whose blocks are all
// free returns to the shared arena and is purged after mi_option_purge_delay;
// Collect() forces that for this heap's thread-local state.
//
// The pool is owned explicitly (a Worker member, or a test-local object) and
// passed to every allocation; nothing selects it from thread-local or default
// PMR state. The first allocation binds the owner thread and the heap's
// thread-bound theap, which only that thread may use: allocation and Collect()
// on any other thread terminate. Release on the owner thread is an invariant;
// mimalloc would accept a remote free, so the release-side thread and
// owning-pool checks run in CNODE_TEST_ALLOCATOR builds only, keeping the
// production free path to a single mi_free.
class worker_memory final : public std::pmr::memory_resource {
public:
    // Page-level view of this heap; computed by visiting its pages.
    struct Footprint {
        std::size_t committed_bytes = 0;
        std::size_t used_bytes = 0;
        std::size_t live_allocations = 0;
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
        if (GetFootprint().live_allocations != 0) std::terminate();
        mi_heap_delete(heap_);
    }

    // Visits every page of this heap: diagnostics and tests only, never on a
    // request path. Requires that no other thread uses this heap meanwhile.
    [[nodiscard]] Footprint GetFootprint() const noexcept {
        Footprint footprint;
        (void)mi_heap_visit_blocks(heap_, false, &AccumulateArea, &footprint);
        return footprint;
    }

    // Exact for blocks released on the owner thread: mimalloc updates a page's
    // use count on every local free.
    [[nodiscard]] std::size_t OutstandingAllocations() const noexcept {
        return GetFootprint().live_allocations;
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
#ifdef CNODE_TEST_ALLOCATOR
        if (reject_next_pmr_allocation) {
            reject_next_pmr_allocation = false;
            ++rejected_pmr_allocations;
            return nullptr;
        }
#endif
        return mi_theap_malloc_aligned(theap_, bytes, alignment);
    }

    void Deallocate(void* pointer, std::size_t = 0, std::size_t = 0) noexcept {
#ifdef CNODE_TEST_ALLOCATOR
        if (!pointer) return;
        RequireOwnerThread();
        if (mi_heap_of(pointer) != heap_) std::terminate();
#endif
        mi_free(pointer);
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
    static bool AccumulateArea(const mi_heap_t*, const mi_heap_area_t* area, void*,
                               std::size_t, void* argument) noexcept {
        auto& footprint = *static_cast<Footprint*>(argument);
        footprint.committed_bytes += area->committed;
        footprint.used_bytes += area->used * area->full_block_size;
        footprint.live_allocations += area->used;
        ++footprint.pages;
        return true;
    }

    void RequireOwnerThread() const noexcept {
        if (owner_token_ != detail::CurrentThreadToken()) std::terminate();
    }

    mi_heap_t* const heap_;
    mi_theap_t* theap_ = nullptr;
    std::uintptr_t owner_token_ = 0;
};

// Releases a block whose owning Worker pool is not at hand (unsized object
// delete). It must come from a Worker heap and be released on its owner
// thread; CNODE_TEST_ALLOCATOR builds verify the former.
inline void ReleaseWorkerBlock(void* p) noexcept {
#ifdef CNODE_TEST_ALLOCATOR
    if (!p) return;
    const mi_heap_t* const heap = mi_heap_of(p);
    if (!heap || heap == mi_heap_main()) std::terminate();
#endif
    mi_free(p);
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

// Objects allocated from an explicit Worker pool: `new (pool) T(...)`.
// Deleting through a base pointer is fine: release does not need the pool.
struct WorkerAllocated {
    static void* operator new(std::size_t) = delete;
    static void* operator new(std::size_t, std::align_val_t) = delete;
    static void* operator new(std::size_t size, worker_memory& pool) {
        if (void* p = pool.Allocate(size, alignof(std::max_align_t))) return p;
        throw std::bad_alloc();
    }
    static void* operator new(std::size_t size, std::align_val_t alignment, worker_memory& pool) {
        if (void* p = pool.Allocate(size, static_cast<std::size_t>(alignment))) return p;
        throw std::bad_alloc();
    }
    static void* operator new(std::size_t, void* p) noexcept { return p; }
    static void operator delete(void*, void*) noexcept {}
    static void operator delete(void* p, worker_memory&) noexcept { ReleaseWorkerBlock(p); }
    static void operator delete(void* p, std::align_val_t, worker_memory&) noexcept {
        ReleaseWorkerBlock(p);
    }
    static void operator delete(void* p) noexcept { ReleaseWorkerBlock(p); }
    static void operator delete(void* p, std::align_val_t) noexcept { ReleaseWorkerBlock(p); }
};

template <class T, class... Args>
    requires std::is_base_of_v<WorkerAllocated, T>
[[nodiscard]] std::unique_ptr<T> MakeUnique(worker_memory& pool, Args&&... args) {
    return std::unique_ptr<T>(new (pool) T(std::forward<Args>(args)...));
}

// Forces this thread's process-layer mimalloc state to return empty pages now.
inline void CollectProcessHeap() noexcept {
    mi_collect(true);
}

// Owner thread of `pool` only: also collects the pool heap.
inline void CollectBurst(worker_memory& pool) noexcept {
    pool.Collect();
    CollectProcessHeap();
}

// PMR allocator bound to one resource. Default construction means the process
// layer; a Worker pool is used only when passed in. Copies keep the source's
// resource; move assignment and swap carry it along.
template <class T>
class Allocator {
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
    Allocator() noexcept : resource_(process_resource()) {}
    Allocator(std::pmr::memory_resource* resource) noexcept
        : resource_(ResourceOrProcess(resource)) {}
    Allocator(const Allocator&) noexcept = default;
    Allocator& operator=(const Allocator&) noexcept = default;
    Allocator(Allocator&&) noexcept = default;
    Allocator& operator=(Allocator&&) noexcept = default;
    template <class U>
    Allocator(const Allocator<U>& other) noexcept
        : resource_(other.resource_) {}
    template <class U>
    Allocator(const std::pmr::polymorphic_allocator<U>& other) noexcept
        : Allocator(other.resource()) {}
    template <class U> struct rebind { using other = Allocator<U>; };
    [[nodiscard]] Allocator select_on_container_copy_construction() const noexcept {
        return *this;
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
    [[nodiscard]] bool operator==(const Allocator<U>& other) const noexcept {
        return resource_ == other.resource_ || resource_->is_equal(*other.resource_);
    }

private:
    template <class> friend class Allocator;

    std::pmr::memory_resource* resource_;
};
template <class T, class... Args>
[[nodiscard]] std::shared_ptr<T> AllocateShared(std::pmr::memory_resource* resource, Args&&... args) {
    return std::allocate_shared<T>(Allocator<T>(resource), std::forward<Args>(args)...);
}
template <class T> using Vector = std::vector<T, Allocator<T>>;

// Zero-allocation-when-empty PMR ring deque. Allocates a contiguous power-of-2
// array from its memory_resource on demand and returns it immediately when the
// queue drains to empty, so idle sessions/substreams retain 0 bytes.
template <class T>
class RingDeque {
public:
    using value_type = T;
    using allocator_type = Allocator<T>;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using reference = T&;
    using const_reference = const T&;

    RingDeque() noexcept : RingDeque(nullptr) {}
    explicit RingDeque(std::pmr::memory_resource* resource) noexcept
        : resource_(ResourceOrProcess(resource)) {}
    explicit RingDeque(const allocator_type& alloc) noexcept
        : RingDeque(alloc.resource()) {}
    RingDeque(const RingDeque& other)
        : RingDeque(other.resource_) {
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

template <class T> using List = std::list<T, Allocator<T>>;
template <class Key, class Value, class Compare = std::less<Key>>
using Map = std::map<Key, Value, Compare, Allocator<std::pair<const Key, Value>>>;
template <class Key, class Value, class Hash = std::hash<Key>, class Eq = std::equal_to<Key>>
using UnorderedMap = std::unordered_map<Key, Value, Hash, Eq,
    Allocator<std::pair<const Key, Value>>>;
template <class Key, class Hash = std::hash<Key>, class Eq = std::equal_to<Key>>
using UnorderedSet = std::unordered_set<Key, Hash, Eq, Allocator<Key>>;
using String = std::basic_string<char, std::char_traits<char>, Allocator<char>>;
using ByteVector = Vector<uint8_t>;

} // namespace memory
