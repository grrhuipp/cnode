#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <limits>
#include <list>
#include <map>
#include <memory>
#include <memory_resource>
#include <new>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <sys/prctl.h>
#endif
#if defined(__GLIBC__)
#include <malloc.h>
#endif

namespace acpp::memory {

#ifdef CNODE_TEST_ALLOCATOR_FAULT
// Fault injection belongs to allocation infrastructure, never to the current
// execution thread. Tests install probes only while no allocation is running.
using AllocationFaultProbe = bool (*)(std::size_t, std::size_t) noexcept;
using AllocationObserver = void (*)(bool, std::size_t, std::size_t) noexcept;
inline std::atomic<AllocationFaultProbe> allocation_fault_probe{nullptr};
inline std::atomic<AllocationObserver> allocation_observer{nullptr};
inline std::atomic<bool> reject_next_data_allocation{false};
inline std::atomic<std::size_t> rejected_data_allocations{0};
inline std::atomic<std::size_t> data_allocations{0};
inline std::atomic<std::size_t> live_data_allocations{0};
#endif

namespace detail {
[[nodiscard]] inline bool RejectAllocation(std::size_t bytes,
                                            std::size_t alignment) noexcept {
#ifdef CNODE_TEST_ALLOCATOR_FAULT
    const auto probe = allocation_fault_probe.load(std::memory_order_relaxed);
    if (reject_next_data_allocation.exchange(false, std::memory_order_relaxed) ||
        (probe && probe(bytes, alignment))) {
        rejected_data_allocations.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
#else
    (void)bytes;
    (void)alignment;
#endif
    return false;
}
inline void Allocated(std::size_t bytes, std::size_t alignment) noexcept {
#ifdef CNODE_TEST_ALLOCATOR_FAULT
    data_allocations.fetch_add(1, std::memory_order_relaxed);
    live_data_allocations.fetch_add(1, std::memory_order_relaxed);
    if (const auto observer = allocation_observer.load(std::memory_order_relaxed))
        observer(true, bytes, alignment);
#else
    (void)bytes;
    (void)alignment;
#endif
}
inline void Freed(std::size_t bytes, std::size_t alignment) noexcept {
#ifdef CNODE_TEST_ALLOCATOR_FAULT
    live_data_allocations.fetch_sub(1, std::memory_order_relaxed);
    if (const auto observer = allocation_observer.load(std::memory_order_relaxed))
        observer(false, bytes, alignment);
#else
    (void)bytes;
    (void)alignment;
#endif
}
[[nodiscard]] inline bool ValidAlignment(std::size_t alignment) noexcept {
    return alignment && (alignment & (alignment - 1)) == 0;
}
} // namespace detail

// This allocation domain has process lifetime and supports concurrent allocation
// and cross-thread destruction. Size may be unknown at release; alignment must
// match the allocation. No thread-local pool, return queue or global PMR default.
[[nodiscard]] inline void* AllocateData(
    std::size_t bytes, std::size_t alignment = alignof(std::max_align_t)) noexcept {
    if (!detail::ValidAlignment(alignment) ||
        detail::RejectAllocation(bytes, alignment)) return nullptr;
    void* pointer = alignment > __STDCPP_DEFAULT_NEW_ALIGNMENT__
        ? ::operator new(bytes, std::align_val_t{alignment}, std::nothrow)
        : ::operator new(bytes, std::nothrow);
    if (pointer) detail::Allocated(bytes, alignment);
    return pointer;
}
inline void DeallocateData(void* pointer, std::size_t bytes = 0,
                           std::size_t alignment = alignof(std::max_align_t)) noexcept {
    if (!pointer) return;
    detail::Freed(bytes, alignment);
    if (alignment > __STDCPP_DEFAULT_NEW_ALIGNMENT__)
        ::operator delete(pointer, std::align_val_t{alignment});
    else
        ::operator delete(pointer);
}

// Fixed, stateless upstream. Explicit phase resources may use it as their
// upstream, but asynchronous operation storage and shared control blocks always
// keep this process-lifetime resource instead of borrowing a phase.
class DataMemoryResource final : public std::pmr::memory_resource {
private:
    void* do_allocate(std::size_t bytes, std::size_t alignment) override {
        if (void* pointer = AllocateData(bytes, alignment)) return pointer;
        throw std::bad_alloc();
    }
    void do_deallocate(void* pointer, std::size_t bytes, std::size_t alignment) override {
        DeallocateData(pointer, bytes, alignment);
    }
    [[nodiscard]] bool do_is_equal(
        const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }
};
[[nodiscard]] inline std::pmr::memory_resource* DataResource() noexcept {
    static DataMemoryResource resource;
    return &resource;
}

struct DataAllocated {
    static void* operator new(std::size_t bytes) {
        if (void* pointer = AllocateData(bytes)) return pointer;
        throw std::bad_alloc();
    }
    static void* operator new(std::size_t bytes, std::align_val_t alignment) {
        if (void* pointer = AllocateData(bytes, static_cast<std::size_t>(alignment))) return pointer;
        throw std::bad_alloc();
    }
    static void operator delete(void* pointer) noexcept { DeallocateData(pointer); }
    static void operator delete(void* pointer, std::size_t bytes) noexcept {
        DeallocateData(pointer, bytes);
    }
    static void operator delete(void* pointer, std::align_val_t alignment) noexcept {
        DeallocateData(pointer, 0, static_cast<std::size_t>(alignment));
    }
    static void operator delete(void* pointer, std::size_t bytes,
                                std::align_val_t alignment) noexcept {
        DeallocateData(pointer, bytes, static_cast<std::size_t>(alignment));
    }
};

// Ownership is explicit in the allocator value. Default construction binds the
// thread-safe process resource, never std::pmr::get_default_resource(). A custom
// resource must outlive every allocation and remain safe for its owner's domain.
template <class T>
class DataAllocator {
public:
    using value_type = T;
    using propagate_on_container_copy_assignment = std::false_type;
    using propagate_on_container_move_assignment = std::true_type;
    using propagate_on_container_swap = std::true_type;
    using is_always_equal = std::false_type;

    DataAllocator() noexcept : resource_(DataResource()) {}
    DataAllocator(std::pmr::memory_resource* resource) : resource_(resource) {
        if (!resource_) throw std::invalid_argument("data allocator resource is null");
    }
    explicit DataAllocator(std::pmr::memory_resource& resource) noexcept : resource_(&resource) {}
    template <class U>
    DataAllocator(const DataAllocator<U>& other) noexcept : resource_(other.resource()) {}

    [[nodiscard]] T* allocate(std::size_t count) {
        if (count > std::numeric_limits<std::size_t>::max() / sizeof(T))
            throw std::bad_array_new_length();
        return static_cast<T*>(resource_->allocate(count * sizeof(T), alignof(T)));
    }
    void deallocate(T* pointer, std::size_t count) noexcept {
        resource_->deallocate(pointer, count * sizeof(T), alignof(T));
    }
    template <class U, class... Args>
    void construct(U* pointer, Args&&... args) {
        std::uninitialized_construct_using_allocator(
            pointer, *this, std::forward<Args>(args)...);
    }
    [[nodiscard]] std::pmr::memory_resource* resource() const noexcept { return resource_; }
    template <class U>
    [[nodiscard]] bool operator==(const DataAllocator<U>& other) const noexcept {
        return resource_->is_equal(*other.resource());
    }
private:
    std::pmr::memory_resource* resource_;
};

template <class T, class... Args>
[[nodiscard]] std::shared_ptr<T> AllocateShared(Args&&... args) {
    return std::allocate_shared<T>(DataAllocator<T>{}, std::forward<Args>(args)...);
}
template <class T> using DataVector = std::vector<T, DataAllocator<T>>;
template <class T> using DataDeque = std::deque<T, DataAllocator<T>>;
template <class T> using DataList = std::list<T, DataAllocator<T>>;
template <class Key, class Value, class Compare = std::less<Key>>
using DataMap = std::map<Key, Value, Compare, DataAllocator<std::pair<const Key, Value>>>;
template <class Key, class Value, class Hash = std::hash<Key>, class Eq = std::equal_to<Key>>
using DataUnorderedMap = std::unordered_map<Key, Value, Hash, Eq,
    DataAllocator<std::pair<const Key, Value>>>;
template <class Key, class Hash = std::hash<Key>, class Eq = std::equal_to<Key>>
using DataUnorderedSet = std::unordered_set<Key, Hash, Eq, DataAllocator<Key>>;
using DataString = std::basic_string<char, std::char_traits<char>, DataAllocator<char>>;
using ByteVector = DataVector<std::uint8_t>;

// Startup-only tuning of the standard allocator. Does not change new/delete or
// the PMR default and does not establish a thread-affine allocation domain.
inline void ConfigureProcessAllocator() noexcept {
#if defined(__linux__) && defined(PR_SET_THP_DISABLE)
    (void)::prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0);
#endif
#if defined(__GLIBC__)
    (void)::mallopt(M_ARENA_MAX, 2);
    (void)::mallopt(M_TRIM_THRESHOLD, 64 * 1024);
    (void)::mallopt(M_MMAP_THRESHOLD, 64 * 1024);
#endif
}

} // namespace acpp::memory

namespace std {
template <>
struct hash<acpp::memory::DataString> {
    [[nodiscard]] size_t operator()(const acpp::memory::DataString& value) const noexcept {
        return hash<string_view>{}(string_view{value.data(), value.size()});
    }
};
} // namespace std
