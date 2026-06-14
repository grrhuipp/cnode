#pragma once

#include <cstdint>

#ifdef CNODE_MEMORY_STATS
#include <atomic>
#endif

namespace acpp::memory {

struct RuntimeMemoryStats {
    uint64_t buffers_live = 0;
    uint64_t buffers_peak = 0;
    uint64_t async_streams_live = 0;
    uint64_t async_streams_peak = 0;
    uint64_t tcp_streams_live = 0;
    uint64_t tcp_streams_peak = 0;
    uint64_t tls_streams_live = 0;
    uint64_t tls_streams_peak = 0;
};

#ifdef CNODE_MEMORY_STATS

namespace detail {
inline std::atomic<uint64_t> g_buffers_live{0};
inline std::atomic<uint64_t> g_buffers_peak{0};
inline std::atomic<uint64_t> g_async_streams_live{0};
inline std::atomic<uint64_t> g_async_streams_peak{0};
inline std::atomic<uint64_t> g_tcp_streams_live{0};
inline std::atomic<uint64_t> g_tcp_streams_peak{0};
inline std::atomic<uint64_t> g_tls_streams_live{0};
inline std::atomic<uint64_t> g_tls_streams_peak{0};

inline void BumpPeak(std::atomic<uint64_t>& peak, uint64_t value) noexcept {
    uint64_t old = peak.load(std::memory_order_relaxed);
    while (old < value &&
           !peak.compare_exchange_weak(
               old, value,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {}
}
}  // namespace detail

inline void OnBufferNew() noexcept {
    const auto live = detail::g_buffers_live.fetch_add(1, std::memory_order_relaxed) + 1;
    detail::BumpPeak(detail::g_buffers_peak, live);
}

inline void OnBufferFree() noexcept {
    detail::g_buffers_live.fetch_sub(1, std::memory_order_relaxed);
}

inline void OnAsyncStreamNew() noexcept {
    const auto live = detail::g_async_streams_live.fetch_add(1, std::memory_order_relaxed) + 1;
    detail::BumpPeak(detail::g_async_streams_peak, live);
}

inline void OnAsyncStreamFree() noexcept {
    detail::g_async_streams_live.fetch_sub(1, std::memory_order_relaxed);
}

inline void OnTcpStreamNew() noexcept {
    const auto live = detail::g_tcp_streams_live.fetch_add(1, std::memory_order_relaxed) + 1;
    detail::BumpPeak(detail::g_tcp_streams_peak, live);
}

inline void OnTcpStreamFree() noexcept {
    detail::g_tcp_streams_live.fetch_sub(1, std::memory_order_relaxed);
}

inline void OnTlsStreamNew() noexcept {
    const auto live = detail::g_tls_streams_live.fetch_add(1, std::memory_order_relaxed) + 1;
    detail::BumpPeak(detail::g_tls_streams_peak, live);
}

inline void OnTlsStreamFree() noexcept {
    detail::g_tls_streams_live.fetch_sub(1, std::memory_order_relaxed);
}

inline RuntimeMemoryStats SnapshotRuntimeMemoryStats() noexcept {
    return {
        detail::g_buffers_live.load(std::memory_order_relaxed),
        detail::g_buffers_peak.load(std::memory_order_relaxed),
        detail::g_async_streams_live.load(std::memory_order_relaxed),
        detail::g_async_streams_peak.load(std::memory_order_relaxed),
        detail::g_tcp_streams_live.load(std::memory_order_relaxed),
        detail::g_tcp_streams_peak.load(std::memory_order_relaxed),
        detail::g_tls_streams_live.load(std::memory_order_relaxed),
        detail::g_tls_streams_peak.load(std::memory_order_relaxed),
    };
}

#else

inline void OnBufferNew() noexcept {}
inline void OnBufferFree() noexcept {}
inline void OnAsyncStreamNew() noexcept {}
inline void OnAsyncStreamFree() noexcept {}
inline void OnTcpStreamNew() noexcept {}
inline void OnTcpStreamFree() noexcept {}
inline void OnTlsStreamNew() noexcept {}
inline void OnTlsStreamFree() noexcept {}
inline RuntimeMemoryStats SnapshotRuntimeMemoryStats() noexcept { return {}; }

#endif

}  // namespace acpp::memory
