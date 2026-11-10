#pragma once

#include <asio/detail/memory.hpp>
#include <new>

namespace async_allocation_test {
inline thread_local int fail_after = -1;
inline thread_local int injected = 0;
inline void Check() {
    if (fail_after >= 0 && fail_after-- == 0) {
        ++injected;
        throw std::bad_alloc();
    }
}
}

// asio::aligned_new is reached both qualified (recycling_allocator) and
// unqualified from asio::detail, so the hook lives in namespace asio.
namespace asio {
inline void* CheckedAsyncAlignedNew(std::size_t alignment, std::size_t size) {
    async_allocation_test::Check();
    return aligned_new(alignment, size);
}
}
#define aligned_new CheckedAsyncAlignedNew
