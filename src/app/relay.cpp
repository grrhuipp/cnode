#include "app/relay.hpp"
#include "app/token_bucket.hpp"

#include <algorithm>
#include <limits>

namespace app {

std::chrono::milliseconds TokenBucket::Consume(size_t bytes, Clock::time_point now) noexcept {
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

void TokenBucket::Refill(uint64_t elapsed) noexcept {
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

std::chrono::milliseconds TokenBucket::DelayFrom(int64_t now) const noexcept {
    if (last_ms_ <= now) return std::chrono::milliseconds::zero();
    const uint64_t delay = static_cast<uint64_t>(last_ms_) - static_cast<uint64_t>(now);
    return std::chrono::milliseconds{static_cast<int64_t>(std::min<uint64_t>(
        delay, std::numeric_limits<int64_t>::max()))};
}

}  // namespace app

namespace app::relay_detail {

struct RelayRateLimits {
    TokenBucket up;
    TokenBucket down;
    transport::internet::AsyncDelay up_wait;
    transport::internet::AsyncDelay down_wait;

    RelayRateLimits(net::io_context& io, uint64_t rate)
        : up(rate), down(rate), up_wait(io), down_wait(io) {}
};

void RelayRateLimitsDelete::operator()(RelayRateLimits* limits) const noexcept {
    delete limits;
}

RelayRateLimitsPtr AllocateRelayRateLimits(net::io_context& io, uint64_t rate) {
    if (rate == 0) return {};
    return RelayRateLimitsPtr(new RelayRateLimits(io, rate));
}

void CancelRelayRateWaits(RelayRateLimits& limits) noexcept {
    limits.up_wait.Cancel();
    limits.down_wait.Cancel();
}

std::chrono::milliseconds ReserveRelayBytes(
    RelayRateLimits& limits, bool upload, size_t bytes) noexcept {
    return (upload ? limits.up : limits.down).Consume(bytes);
}

net::awaitable<void> WaitRelayRate(
    RelayRateLimits& limits, bool upload, std::chrono::milliseconds delay) {
    return (upload ? limits.up_wait : limits.down_wait).WaitFor(delay);
}

void FlushRelayStats(StatsShard& stats, LocalStatsAccumulator& acc) {
    if (acc.bytes_in == 0 && acc.bytes_out == 0) return;
    stats.CommitAccumulator(acc);
    acc.Reset();
}

RelayState::RelayState(net::io_context& io)
    : wake(net::any_io_executor(io.get_executor()), 1) {}

void RelayState::Mark(bool client_side) noexcept {
    if (!close_side_known && !local_failure) {
        close_side_known = true;
        client_closed_first = client_side;
    }
}

void RelayState::Stop(common::ErrorCode error) noexcept {
    if (reason == common::ErrorCode::OK || (reason == common::ErrorCode::CANCELLED && error != common::ErrorCode::CANCELLED))
        reason = error;
    phase = RelayPhase::Stopping;
    wake.close();
}

void RelayState::Complete() noexcept {
    if (reason != common::ErrorCode::OK) return;
    phase = RelayPhase::Completing;
    wake.close();
}

}  // namespace relay_detail
