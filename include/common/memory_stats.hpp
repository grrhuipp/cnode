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

#ifdef CNODE_MEMORY_STATS
namespace detail {
inline std::atomic<uint64_t> g_remote_frees{0};
}  // namespace detail

inline void OnRemoteFree() noexcept {
    detail::g_remote_frees.fetch_add(1, std::memory_order_relaxed);
}
inline uint64_t RemoteFreeCount() noexcept {
    return detail::g_remote_frees.load(std::memory_order_relaxed);
}
#else
inline void OnRemoteFree() noexcept {}
inline uint64_t RemoteFreeCount() noexcept { return 0; }
#endif
}  // namespace memory
