#include "timeout_scheduler_allocation.hpp"

#include <cstdlib>
#include <new>

// Keep the complete test allocation pair in its own translation unit. Under
// sanitizer instrumentation GCC can otherwise inline only delete into a caller
// and incorrectly diagnose this legal malloc-backed replacement as a mismatch.
// No production allocator is replaced and no diagnostics are disabled.
void* operator new(std::size_t size) {
    if (timeout_allocation_test::reject_allocations) {
        ++timeout_allocation_test::rejected_allocations;
        throw std::bad_alloc();
    }
    if (void* pointer = std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void operator delete(void* pointer, const std::nothrow_t&) noexcept { ::operator delete(pointer); }
