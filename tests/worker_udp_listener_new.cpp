#include "async_allocation_fault.hpp"

#include <cstdlib>
#include <new>

// Test-only replacement; also catches Asio awaitable frame allocation when
// frame recycling is disabled for this fixture. Production allocation is not
// replaced. Keep the allocation/deallocation pair in its own translation unit.
void* operator new(std::size_t size) {
    async_allocation_test::Check();
    if (void* pointer = std::malloc(size ? size : 1)) return pointer;
    throw std::bad_alloc();
}
void operator delete(void* pointer) noexcept { std::free(pointer); }
void operator delete(void* pointer, std::size_t) noexcept { std::free(pointer); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void operator delete(void* pointer, const std::nothrow_t&) noexcept { ::operator delete(pointer); }
