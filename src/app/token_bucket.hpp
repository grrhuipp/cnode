#pragma once

// relay 限速的私有令牌桶；实现位于 src/app/relay.cpp。

#include <chrono>
#include <cstddef>
#include <cstdint>

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
        size_t bytes, Clock::time_point now = Clock::now()) noexcept;

private:
    static int64_t Millis(Clock::time_point now) noexcept {
        return std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    }

    // elapsed <= 1000: the result never exceeds rate_, even at UINT64_MAX.
    uint64_t Credit(uint32_t elapsed) const noexcept {
        return (rate_ / 1000) * elapsed + ((rate_ % 1000) * elapsed + fraction_) / 1000;
    }
    void Refill(uint64_t elapsed) noexcept;
    std::chrono::milliseconds DelayFrom(int64_t now) const noexcept;

    uint64_t rate_;
    uint64_t tokens_;
    uint64_t fraction_ = 0; // Thousandths of one byte, not yet spendable.
    int64_t last_ms_;      // Includes credit reserved in future waits.
};
