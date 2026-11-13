#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <new>
#include <stdexcept>
#include <type_traits>
#include <utility>

#include <mimalloc.h>

namespace common {

#ifdef CNODE_TEST_BUFFER_STATS
inline thread_local uint64_t test_buffers_live = 0;
inline thread_local uint64_t test_buffers_peak = 0;
inline void OnBufferNew() noexcept {
    ++test_buffers_live;
    if (test_buffers_live > test_buffers_peak)
        test_buffers_peak = test_buffers_live;
}
inline void OnBufferFree() noexcept { --test_buffers_live; }
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

inline void CheckTestAllocationFault() {
#ifdef CNODE_TEST_ALLOCATOR
    if (reject_next_process_allocation) {
        reject_next_process_allocation = false;
        ++rejected_process_allocations;
        throw std::bad_alloc();
    }
    if (process_allocation_budget == 0) {
        ++rejected_process_allocations;
        throw std::bad_alloc();
    }
    if (process_allocation_budget > 0) --process_allocation_budget;
#endif
}

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


// Collects the calling thread's mimalloc heap and purges its empty pages.
inline void CollectThreadHeap() noexcept {
    mi_collect(true);
}

// Zero-allocation-when-empty ring deque backed directly by mimalloc.
// Allocates a contiguous power-of-2 array on demand and returns it immediately
// when the queue drains to empty, so idle sessions/substreams retain 0 bytes.
template <class T>
class RingDeque {
public:
    using value_type = T;
    using size_type = std::size_t;
    using difference_type = std::ptrdiff_t;
    using reference = T&;
    using const_reference = const T&;

    RingDeque() noexcept = default;

    RingDeque(const RingDeque& other) {
        CopyElementsFrom(other);
    }

    RingDeque(RingDeque&& other) noexcept
        : data_(std::exchange(other.data_, nullptr))
        , head_(std::exchange(other.head_, 0))
        , size_(std::exchange(other.size_, 0))
        , capacity_(std::exchange(other.capacity_, 0)) {}

    RingDeque& operator=(const RingDeque& other) {
        if (this != &other) {
            RingDeque copy(other);
            swap(copy);
        }
        return *this;
    }

    RingDeque& operator=(RingDeque&& other) noexcept {
        if (this != &other) {
            RingDeque incoming(std::move(other));
            swap(incoming);
        }
        return *this;
    }

    ~RingDeque() noexcept {
        clear();
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
        std::construct_at(ptr, std::forward<Args>(args)...);
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
        std::construct_at(ptr, std::forward<Args>(args)...);
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
            T* next_data = static_cast<T*>(
                TryAllocateProcessRaw(target_cap * sizeof(T), alignof(T)));
            if (!next_data) return;
            for (std::size_t i = 0; i < size_; ++i) {
                const std::size_t idx = (head_ + i) & (capacity_ - 1);
                std::construct_at(next_data + i, std::move(data_[idx]));
                std::destroy_at(data_ + idx);
            }
            mi_free(data_);
            data_ = next_data;
            head_ = 0;
            capacity_ = target_cap;
        }
    }

    void swap(RingDeque& other) noexcept {
        if (this == &other) return;
        std::swap(data_, other.data_);
        std::swap(head_, other.head_);
        std::swap(size_, other.size_);
        std::swap(capacity_, other.capacity_);
    }

private:
    void CopyElementsFrom(const RingDeque& other) {
        if (other.empty()) return;
        Reserve(other.size_);
        try {
            for (std::size_t i = 0; i < other.size_; ++i) {
                std::construct_at(data_ + size_, other[i]);
                ++size_;
            }
        } catch (...) {
            clear();
            throw;
        }
    }

    void RelocateInto(T* next_data, std::size_t offset) {
        std::size_t constructed = 0;
        try {
            for (; constructed < size_; ++constructed) {
                std::construct_at(
                    next_data + offset + constructed,
                    std::move_if_noexcept(data_[(head_ + constructed) & (capacity_ - 1)]));
            }
        } catch (...) {
            for (std::size_t i = 0; i < constructed; ++i) {
                std::destroy_at(next_data + offset + i);
            }
            throw;
        }
    }

    void AdoptRelocated(T* next_data, std::size_t next_cap) noexcept {
        for (std::size_t i = 0; i < size_; ++i) {
            std::destroy_at(data_ + ((head_ + i) & (capacity_ - 1)));
        }
        if (data_) {
            mi_free(data_);
        }
        data_ = next_data;
        head_ = 0;
        capacity_ = next_cap;
    }

    [[gnu::noinline]] void ReleaseStorage() noexcept {
        auto* data = std::exchange(data_, nullptr);
        capacity_ = 0;
        head_ = 0;
        if (data) {
            mi_free(data);
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
            AllocateProcessRaw(next_cap * sizeof(T), alignof(T)));
        try {
            RelocateInto(next_data, 0);
        } catch (...) {
            mi_free(next_data);
            throw;
        }
        AdoptRelocated(next_data, next_cap);
    }

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
            AllocateProcessRaw(next_cap * sizeof(T), alignof(T)));
        T* new_elem = next_data + (at_back ? size_ : 0);
        try {
            std::construct_at(new_elem, std::forward<Args>(args)...);
        } catch (...) {
            mi_free(next_data);
            throw;
        }
        try {
            RelocateInto(next_data, at_back ? 0 : 1);
        } catch (...) {
            std::destroy_at(new_elem);
            mi_free(next_data);
            throw;
        }
        AdoptRelocated(next_data, next_cap);
        ++size_;
        return *new_elem;
    }

    T* data_ = nullptr;
    std::size_t head_ = 0;
    std::size_t size_ = 0;
    std::size_t capacity_ = 0;
};


// 当哈希容器在流量高峰后变得非常稀疏时，主动回缩 bucket，
// 避免 burst 后长时间保留大块空桶内存。
template <typename HashContainer>
inline void MaybeShrinkHashContainer(
    HashContainer& container,
    std::size_t keep_min_buckets = 64,
    std::size_t sparse_ratio = 8) noexcept {
    const std::size_t buckets = container.bucket_count();
    if (buckets <= keep_min_buckets || sparse_ratio == 0) {
        return;
    }
    const std::size_t size = container.size();
    if (size == 0) {
        try {
            container.rehash(keep_min_buckets);
        } catch (...) {}
        return;
    }
    if (buckets / sparse_ratio <= size) {
        return;
    }
    const std::size_t target_buckets = std::max(keep_min_buckets, size * 2);
    if (target_buckets < buckets) {
        try {
            container.rehash(target_buckets);
        } catch (...) {}
    }
}
}  // namespace common
