#pragma once

// Test-only forced include: intercept Asio's actual aligned allocation path,
// including _aligned_malloc on Windows. Production targets and dependency
// sources are unchanged; the original allocation/deallocation pair is kept.
#include <asio/detail/memory.hpp>

#include <cstddef>
#include <new>

namespace timeout_allocation_test {
inline thread_local bool reject_allocations = false;
inline thread_local std::size_t rejected_allocations = 0;
inline thread_local bool reject_asio_allocations = false;
inline thread_local std::size_t rejected_asio_allocations = 0;
}

namespace asio::detail {
inline void* CheckedTimeoutAlignedNew(std::size_t alignment, std::size_t size) {
    if (timeout_allocation_test::reject_asio_allocations) {
        ++timeout_allocation_test::rejected_asio_allocations;
        throw std::bad_alloc();
    }
    return aligned_new(alignment, size);
}
}

#define aligned_new CheckedTimeoutAlignedNew
