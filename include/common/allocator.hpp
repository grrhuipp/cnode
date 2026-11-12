#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <memory_resource>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

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

// CNODE_TEST_ALLOCATOR: test-only allocation fault injection. It must be
// defined consistently for every translation unit of one binary.
#ifdef CNODE_TEST_ALLOCATOR
inline thread_local bool reject_next_process_allocation = false;
inline thread_local size_t rejected_process_allocations = 0;
inline thread_local std::ptrdiff_t process_allocation_budget = -1;
#endif

namespace detail {
[[nodiscard]] inline void* TryAllocateProcessRaw(
    std::size_t bytes_value, std::size_t alignment) noexcept {
#ifdef CNODE_TEST_ALLOCATOR
    if (reject_next_process_allocation) {
        reject_next_process_allocation = false;
        ++rejected_process_allocations;
        return nullptr;
    }
    if (process_allocation_budget == 0) {
        ++rejected_process_allocations;
        return nullptr;
    }
    if (process_allocation_budget > 0) --process_allocation_budget;
#endif
    return mi_malloc_aligned(bytes_value, alignment);
}

[[nodiscard]] inline void* AllocateProcessRaw(std::size_t bytes_value, std::size_t alignment) {
    if (void* block = TryAllocateProcessRaw(bytes_value, alignment)) return block;
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

// Resolve a caller-owned resource once; omitted resources use the process layer.
[[nodiscard]] inline std::pmr::memory_resource* ResourceOrProcess(
    std::pmr::memory_resource* resource) noexcept {
    return resource ? resource : process_resource();
}

// Native Asio operation storage may retire on a different reactor thread.
template <class T>
class ProcessAllocator : public std::pmr::polymorphic_allocator<T> {
public:
    ProcessAllocator() noexcept : std::pmr::polymorphic_allocator<T>(process_resource()) {}
    template <class U>
    ProcessAllocator(const ProcessAllocator<U>&) noexcept : ProcessAllocator() {}
    template <class U> struct rebind { using other = ProcessAllocator<U>; };
};

// Collects the calling thread's mimalloc heap and purges its empty pages.
inline void CollectThreadHeap() noexcept {
    mi_collect(true);
}

// Zero-allocation-when-empty PMR ring deque. Allocates a contiguous power-of-2
// array from its memory_resource on demand and returns it immediately when the
// queue drains to empty, so idle sessions/substreams retain 0 bytes.
template <class T>
class RingDeque {
public:
    using value_type = T;
    using allocator_type = std::pmr::polymorphic_allocator<T>;
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
        CopyElementsFrom(other);
    }

    RingDeque(RingDeque&& other) noexcept
        : resource_(other.resource_)
        , data_(std::exchange(other.data_, nullptr))
        , head_(std::exchange(other.head_, 0))
        , size_(std::exchange(other.size_, 0))
        , capacity_(std::exchange(other.capacity_, 0)) {}

    RingDeque& operator=(const RingDeque& other) {
        if (this != &other) {
            RingDeque copy(resource_);
            copy.CopyElementsFrom(other);
            clear();
            data_ = std::exchange(copy.data_, nullptr);
            head_ = std::exchange(copy.head_, 0);
            size_ = std::exchange(copy.size_, 0);
            capacity_ = std::exchange(copy.capacity_, 0);
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
    // 空队列按 other 的顺序拷贝元素；失败时清空并释放已取得的存储。
    void CopyElementsFrom(const RingDeque& other) {
        if (other.empty()) return;
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

    // 把现有元素按逻辑顺序搬到 next_data[offset...]；抛异常时析构已搬入的元素并
    // 继续抛出，旧存储保持不变，next_data 由调用方释放。
    void RelocateInto(T* next_data, std::size_t offset) {
        std::size_t constructed = 0;
        try {
            for (; constructed < size_; ++constructed) {
                ConstructRelocatedAt(next_data + offset + constructed,
                    data_[(head_ + constructed) & (capacity_ - 1)]);
            }
        } catch (...) {
            for (std::size_t i = 0; i < constructed; ++i) {
                std::destroy_at(next_data + offset + i);
            }
            throw;
        }
    }

    // 析构旧元素、释放旧存储，并接管已完成搬移的新存储。
    void AdoptRelocated(T* next_data, std::size_t next_cap) noexcept {
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
        try {
            RelocateInto(next_data, 0);
        } catch (...) {
            resource_->deallocate(next_data, next_cap * sizeof(T), alignof(T));
            throw;
        }
        AdoptRelocated(next_data, next_cap);
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
        try {
            ConstructAt(new_elem, std::forward<Args>(args)...);
        } catch (...) {
            resource_->deallocate(next_data, next_cap * sizeof(T), alignof(T));
            throw;
        }
        try {
            RelocateInto(next_data, at_back ? 0 : 1);
        } catch (...) {
            std::destroy_at(new_elem);
            resource_->deallocate(next_data, next_cap * sizeof(T), alignof(T));
            throw;
        }
        AdoptRelocated(next_data, next_cap);
        ++size_;
        return *new_elem;
    }

    std::pmr::memory_resource* resource_;
    T* data_ = nullptr;
    std::size_t head_ = 0;
    std::size_t size_ = 0;
    std::size_t capacity_ = 0;
};
} // namespace memory
