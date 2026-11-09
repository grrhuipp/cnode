#pragma once

#include <cstdint>

#include <atomic>

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

}  // namespace memory
