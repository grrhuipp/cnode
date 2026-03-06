#pragma once

// ============================================================================
// spinlock.hpp — 通用自旋锁
//
// 供 ShardedUserStats、HotUserCache 及其他需要轻量级锁的模块使用。
// x86/ARM 自旋等待时使用 pause/yield 指令降低功耗和总线争用。
// ============================================================================

#include <atomic>

#ifdef _MSC_VER
#include <intrin.h>
#endif

namespace acpp {

class SpinLock {
public:
    void Lock() const noexcept {
        while (flag_.test_and_set(std::memory_order_acquire)) {
#if defined(_MSC_VER)
            _mm_pause();
#elif defined(__x86_64__) || defined(_M_X64)
            __builtin_ia32_pause();
#elif defined(__aarch64__)
            asm volatile("yield");
#endif
        }
    }
    void Unlock() const noexcept {
        flag_.clear(std::memory_order_release);
    }

private:
    mutable std::atomic_flag flag_ = ATOMIC_FLAG_INIT;
};

}  // namespace acpp
