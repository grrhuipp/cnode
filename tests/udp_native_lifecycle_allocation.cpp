#include "async_allocation_fault.hpp"
#include "udp_native_lifecycle_allocation.hpp"

#include <cstdlib>
#include <new>

#ifdef _WIN32
#  include <malloc.h>
#endif

namespace {
thread_local int standard_budget = -1;
thread_local std::size_t standard_failures = 0;
thread_local bool dispatch_stage_armed = false;
thread_local int dispatch_stage_budget = -1;
thread_local udp_native_lifecycle_fault::DispatchStageFault dispatch_stage_fault =
    udp_native_lifecycle_fault::DispatchStageFault::StandardNew;

[[nodiscard]] bool RejectStandardAllocation() noexcept {
    if (standard_budget < 0) return false;
    if (standard_budget > 0) {
        --standard_budget;
        return false;
    }
    standard_budget = -1;
    ++standard_failures;
    return true;
}

[[nodiscard]] void* AllocateAligned(std::size_t size, std::size_t alignment) {
    if (RejectStandardAllocation()) throw std::bad_alloc();
    size = size == 0 ? 1 : size;
    if (alignment < alignof(void*)) alignment = alignof(void*);
#ifdef _WIN32
    if (void* pointer = ::_aligned_malloc(size, alignment)) return pointer;
#else
    void* pointer = nullptr;
    if (::posix_memalign(&pointer, alignment, size) == 0) return pointer;
#endif
    throw std::bad_alloc();
}
} // namespace

namespace udp_native_lifecycle_fault {

void ArmStandardNew(int successful_allocations_before_failure) noexcept {
    standard_budget = successful_allocations_before_failure;
}

void ArmAtDispatchStage(
    DispatchStageFault fault, int successful_allocations_before_failure) noexcept {
    dispatch_stage_fault = fault;
    dispatch_stage_budget = successful_allocations_before_failure;
    dispatch_stage_armed = true;
}

void OnNativeDispatchStage() noexcept {
    if (!dispatch_stage_armed) return;
    dispatch_stage_armed = false;
    if (dispatch_stage_fault == DispatchStageFault::StandardNew) {
        ArmStandardNew(dispatch_stage_budget);
        return;
    }
    async_allocation_test::fail_after = dispatch_stage_budget;
}

void Disarm() noexcept {
    standard_budget = -1;
    dispatch_stage_budget = -1;
    dispatch_stage_armed = false;
    async_allocation_test::fail_after = -1;
}

std::size_t StandardNewFailures() noexcept { return standard_failures; }

std::size_t AsioAlignedNewFailures() noexcept {
    return static_cast<std::size_t>(async_allocation_test::injected);
}

} // namespace udp_native_lifecycle_fault

void* operator new(std::size_t size) {
    if (RejectStandardAllocation()) throw std::bad_alloc();
    if (void* pointer = std::malloc(size == 0 ? 1 : size)) return pointer;
    throw std::bad_alloc();
}

void* operator new[](std::size_t size) {
    if (RejectStandardAllocation()) throw std::bad_alloc();
    if (void* pointer = std::malloc(size == 0 ? 1 : size)) return pointer;
    throw std::bad_alloc();
}

void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete[](void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }
void operator delete[](void* pointer, std::size_t) noexcept { std::free(pointer); }

void* operator new(std::size_t size, std::align_val_t alignment) {
    return AllocateAligned(size, static_cast<std::size_t>(alignment));
}
void* operator new[](std::size_t size, std::align_val_t alignment) {
    return AllocateAligned(size, static_cast<std::size_t>(alignment));
}
void operator delete(void* pointer, std::align_val_t) noexcept {
#ifdef _WIN32
    ::_aligned_free(pointer);
#else
    std::free(pointer);
#endif
}
void operator delete[](void* pointer, std::align_val_t) noexcept {
#ifdef _WIN32
    ::_aligned_free(pointer);
#else
    std::free(pointer);
#endif
}
void operator delete(void* pointer, std::size_t, std::align_val_t) noexcept {
#ifdef _WIN32
    ::_aligned_free(pointer);
#else
    std::free(pointer);
#endif
}
void operator delete[](void* pointer, std::size_t, std::align_val_t) noexcept {
#ifdef _WIN32
    ::_aligned_free(pointer);
#else
    std::free(pointer);
#endif
}
