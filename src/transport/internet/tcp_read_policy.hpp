#pragma once

#include <cstdint>
#include <limits>

namespace acpp::transport::internet::tcp_read_policy {

// Keep the decision Worker-local: connected TcpStream objects never cross their
// owning io_context thread, so this counter needs neither a lock nor a shared
// atomic cache line. At normal load readv4 preserves the validated throughput
// ceiling; once a Worker owns many TCP streams, readv2 bounds pending payload RSS.
inline constexpr uint32_t kNormalReadBufferCap = 4;
inline constexpr uint32_t kPressureReadBufferCap = 2;
inline constexpr uint32_t kPressureActiveStreamThreshold = 512;

inline thread_local uint32_t g_active_streams = 0;

inline void RegisterActiveStream() noexcept {
    if (g_active_streams < std::numeric_limits<uint32_t>::max()) {
        ++g_active_streams;
    }
}

inline void UnregisterActiveStream() noexcept {
    if (g_active_streams > 0) {
        --g_active_streams;
    }
}

[[nodiscard]] inline uint32_t ActiveStreamCount() noexcept {
    return g_active_streams;
}

[[nodiscard]] inline uint32_t MaxReadBufferCount() noexcept {
    return g_active_streams >= kPressureActiveStreamThreshold
        ? kPressureReadBufferCap
        : kNormalReadBufferCap;
}

}  // namespace acpp::transport::internet::tcp_read_policy
