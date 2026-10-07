#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>

namespace acpp {

// Worker-local byte reservations. Initial credit is one second of traffic;
// idle credit is capped at two seconds. Waiting cannot earn reserved bytes again.
class TokenBucket {
public:
    using Clock = std::chrono::steady_clock;

    explicit TokenBucket(uint64_t rate, Clock::time_point now = Clock::now()) noexcept
        : rate_(rate), tokens_(rate), last_ms_(Millis(now)) {}

    TokenBucket(const TokenBucket&) = delete;
    TokenBucket& operator=(const TokenBucket&) = delete;

    [[nodiscard]] std::chrono::milliseconds Consume(
        size_t bytes, Clock::time_point now = Clock::now()) noexcept {
        if (rate_ == 0 || bytes == 0) return std::chrono::milliseconds::zero();
        const int64_t now_ms = Millis(now);
        if (now_ms > last_ms_) {
            Refill(static_cast<uint64_t>(now_ms) - static_cast<uint64_t>(last_ms_));
            last_ms_ = now_ms;
        }
        if (tokens_ >= bytes) {
            tokens_ -= bytes;
            return DelayFrom(now_ms);
        }

        const uint64_t deficit = bytes - tokens_;
        // Whole seconds plus a remainder in [1, rate] avoid deficit * 1000.
        const uint64_t seconds = (deficit - 1) / rate_;
        const uint64_t remainder = (deficit - 1) % rate_ + 1;
        uint32_t low = 1, high = 1000;
        while (low < high) {
            const uint32_t mid = low + (high - low) / 2;
            if (Credit(mid) >= remainder) high = mid;
            else low = mid + 1;
        }
        tokens_ = Credit(low) - remainder;
        fraction_ = ((rate_ % 1000) * low + fraction_) % 1000;

        constexpr uint64_t maximum = std::numeric_limits<int64_t>::max();
        const bool overflow = seconds > (maximum - low) / 1000;
        const uint64_t wait = overflow
            ? maximum : seconds * 1000 + low;
        const uint64_t room = maximum - static_cast<uint64_t>(last_ms_);
        if (overflow || wait > room) {
            last_ms_ = std::numeric_limits<int64_t>::max();
            tokens_ = fraction_ = 0;
        } else {
            last_ms_ += static_cast<int64_t>(wait);
        }
        return DelayFrom(now_ms);
    }

private:
    static int64_t Millis(Clock::time_point now) noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    // elapsed <= 1000: the result never exceeds rate_, even at UINT64_MAX.
    uint64_t Credit(uint32_t elapsed) const noexcept {
        return (rate_ / 1000) * elapsed + ((rate_ % 1000) * elapsed + fraction_) / 1000;
    }

    void Refill(uint64_t elapsed) noexcept {
        constexpr uint64_t maximum = std::numeric_limits<uint64_t>::max();
        const uint64_t capacity = rate_ > maximum / 2 ? maximum : rate_ * 2;
        if (elapsed >= 2000) {
            tokens_ = capacity;
            fraction_ = 0;
            return;
        }
        if (elapsed >= 1000) {
            if (rate_ >= capacity - tokens_) {
                tokens_ = capacity;
                fraction_ = 0;
                return;
            }
            tokens_ += rate_;
            elapsed -= 1000;
        }
        const uint64_t credit = Credit(static_cast<uint32_t>(elapsed));
        if (credit >= capacity - tokens_) {
            tokens_ = capacity;
            fraction_ = 0;
        } else {
            tokens_ += credit;
            fraction_ = ((rate_ % 1000) * elapsed + fraction_) % 1000;
        }
    }

    std::chrono::milliseconds DelayFrom(int64_t now) const noexcept {
        if (last_ms_ <= now) return std::chrono::milliseconds::zero();
        const uint64_t delay = static_cast<uint64_t>(last_ms_) - static_cast<uint64_t>(now);
        return std::chrono::milliseconds{static_cast<int64_t>(std::min<uint64_t>(
            delay, std::numeric_limits<int64_t>::max()))};
    }

    uint64_t rate_;
    uint64_t tokens_;
    uint64_t fraction_ = 0; // Thousandths of one byte, not yet spendable.
    int64_t last_ms_;      // Includes credit reserved in future waits.
};

}  // namespace acpp
