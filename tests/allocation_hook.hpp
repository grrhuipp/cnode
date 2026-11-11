#pragma once

#include <cstddef>

// Tests observe or fail global operator new/delete while the binary keeps the
// daemon's overriding mimalloc. allocation_hook.cpp wraps the unaligned scalar,
// array and nothrow forms at link time; each linking test defines `hooks`.
namespace allocation_hook {

struct Hooks {
    // Runs before the allocation and may throw std::bad_alloc to inject failure.
    void (*before_new)(std::size_t size) = nullptr;
    void (*after_new)(void* pointer, std::size_t size) noexcept = nullptr;
    void (*before_delete)(void* pointer) noexcept = nullptr;
};

// Constant-initialized by the test so it is active before dynamic initialization.
extern Hooks hooks;

}  // namespace allocation_hook
