#include "app/token_bucket.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <random>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {
using Clock = ::TokenBucket::Clock;
Clock::time_point At(int64_t millis) {
    return Clock::time_point{std::chrono::milliseconds{millis}};
}

// Independent exact thousandths-of-a-byte accounting, replacing the Python
// big-integer oracle. Refill is capped before multiplication: every intermediate
// is bounded by UINT64_MAX * 2000, well within signed 128-bit arithmetic.
__extension__ using Wide = __int128;
class ExactModel {
public:
    ExactModel(uint64_t rate, int64_t now)
        : rate_(rate), now_(now), credit_(Wide{rate} * 1000),
          capacity_(std::min(Wide{rate} * 2, Wide{std::numeric_limits<uint64_t>::max()}) * 1000) {}

    int64_t Consume(uint64_t size, int64_t now) {
        if (rate_ == 0 || size == 0) return 0;
        if (now > now_) {
            const Wide elapsed = Wide{now} - now_;
            credit_ = elapsed >= 2000 ? capacity_ : std::min(capacity_, credit_ + rate_ * elapsed);
            now_ = now;
        }
        credit_ -= Wide{size} * 1000;
        if (credit_ < 0) {
            const Wide wait = (-credit_ + rate_ - 1) / rate_;
            credit_ += rate_ * wait;
            if (wait > Maximum || now_ + wait > Maximum) {
                now_ = Maximum;
                credit_ = 0;
            } else {
                now_ += wait;
            }
        }
        return static_cast<int64_t>(std::clamp(now_ - now, Wide{0}, Maximum));
    }
private:
    static constexpr Wide Maximum = std::numeric_limits<int64_t>::max();
    Wide rate_;
    Wide now_;
    Wide credit_;
    Wide capacity_;
};

TEST(TokenBucket, RealClockWaitDoesNotDoubleRefillReservations) {
    ::TokenBucket bucket(1000);
    const auto first = bucket.Consume(2000);
    std::this_thread::sleep_for(first);
    const auto second = bucket.Consume(1000);
    EXPECT_GE(second, 850ms);
    EXPECT_LE(second, 1000ms);
}

TEST(TokenBucket, MaximumConsumptionSaturatesWait) {
    ::TokenBucket slow(1, At(0));
    EXPECT_EQ(slow.Consume(std::numeric_limits<size_t>::max(), At(0)), std::chrono::milliseconds::max());
}

TEST(TokenBucket, ContinuousAndOverlappingReservations) {
    ::TokenBucket continuous(1000, At(0));
    EXPECT_EQ(continuous.Consume(2000, At(0)), 1000ms);
    EXPECT_EQ(continuous.Consume(1000, At(1000)), 1000ms);
    EXPECT_EQ(continuous.Consume(1000, At(2000)), 1000ms);
    ::TokenBucket reserved(1000, At(0));
    EXPECT_EQ(reserved.Consume(2000, At(0)), 1000ms);
    EXPECT_EQ(reserved.Consume(1000, At(0)), 2000ms);
    EXPECT_EQ(reserved.Consume(1000, At(2000)), 1000ms);
}

TEST(TokenBucket, IdleCreditIsLimitedToTwoSeconds) {
    ::TokenBucket idle(1000, At(0));
    EXPECT_EQ(idle.Consume(1000, At(0)), 0ms);
    EXPECT_EQ(idle.Consume(2000, At(10000)), 0ms);
    EXPECT_EQ(idle.Consume(1000, At(10000)), 1000ms);
}

TEST(TokenBucket, FractionalCreditSurvivesReservations) {
    ::TokenBucket fractional(3, At(0));
    EXPECT_EQ(fractional.Consume(3, At(0)), 0ms);
    EXPECT_EQ(fractional.Consume(1, At(333)), 1ms);
    EXPECT_EQ(fractional.Consume(1, At(334)), 333ms);
    EXPECT_EQ(fractional.Consume(1, At(667)), 333ms);
}

TEST(TokenBucket, UnlimitedExtremeRateAndCapacitySaturation) {
    constexpr auto maximum = std::numeric_limits<size_t>::max();
    ::TokenBucket unlimited(0, At(0));
    EXPECT_EQ(unlimited.Consume(maximum, At(0)), 0ms);
    ::TokenBucket extreme(std::numeric_limits<uint64_t>::max(), At(0));
    EXPECT_EQ(extreme.Consume(maximum, At(0)), 0ms);
    EXPECT_EQ(extreme.Consume(maximum, At(1)), 999ms);
    ::TokenBucket saturated(uint64_t{1} << 63, At(0));
    EXPECT_EQ(saturated.Consume(uint64_t{1} << 63, At(0)), 0ms);
    EXPECT_EQ(saturated.Consume(maximum, At(2000)), 0ms);
    EXPECT_EQ(saturated.Consume(1, At(2000)), 1ms);
}

TEST(TokenBucket, ExactIntegerOracleAcrossRatesSizesAndTimeJumps) {
    constexpr uint64_t maximum = std::numeric_limits<uint64_t>::max();
    static_assert(sizeof(size_t) == sizeof(uint64_t), "oracle requires the project's 64-bit target");
    std::mt19937_64 rng(320031);
    std::vector<uint64_t> rates{0, 1, 2, 3, 999, 1000, 1001, 8192, 1'000'000,
        (uint64_t{1} << 32) + 1, (uint64_t{1} << 63) - 1, uint64_t{1} << 63, maximum - 1, maximum};
    for (unsigned index = 0; index < 24; ++index) rates.push_back(1 + rng() % (maximum - 1));
    constexpr std::array<int64_t, 4> starts{-1000, 0, 100000, 1'000'000'000'000};
    for (const auto rate : rates) {
        int64_t now = starts[rng() % starts.size()];
        std::optional<::TokenBucket> bucket(std::in_place, rate, At(now));
        ExactModel model(rate, now);
        for (unsigned index = 0; index < 600; ++index) {
            const std::array<uint64_t, 7> sizes{0, 1, 8192, maximum, std::max(uint64_t{1}, rate / 1000),
                1 + rng() % 99999, 1 + rng() % (maximum - 1)};
            const auto size = sizes[rng() % sizes.size()];
            SCOPED_TRACE(::testing::Message() << "rate=" << rate << " size=" << size << " now=" << now << " sample=" << index);
            const int64_t wait = model.Consume(size, now);
            ASSERT_EQ(bucket->Consume(size, At(now)).count(), wait);
            if (wait > 100000 || index % 29 == 0) {
                now = starts[rng() % starts.size()];
                model = ExactModel(rate, now);
                bucket.emplace(rate, At(now));
            } else {
                const std::array<int64_t, 8> steps{0, 1, 333, 999, 1000, 2000, wait, wait + 3};
                now += steps[rng() % steps.size()];
            }
        }
    }
}

TEST(TokenBucket, ExactOracleAtRepresentableClockBoundariesAndBackwardsTime) {
    constexpr uint64_t maximum = std::numeric_limits<uint64_t>::max();
    const int64_t earliest = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::duration::min()).count();
    const int64_t latest = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::duration::max()).count();
    const std::array<uint64_t, 8> rates{0, 1, 3, 999, 1001, (uint64_t{1} << 63) - 1, uint64_t{1} << 63, maximum};
    const std::array<uint64_t, 7> sizes{0, 1, 999, 1000, uint64_t{1} << 63, maximum - 1, maximum};
    for (const auto rate : rates) {
        for (const auto start : {earliest, int64_t{-1000}, int64_t{0}, latest}) {
            ::TokenBucket bucket(rate, At(start));
            ExactModel model(rate, start);
            for (const auto now : {start, start, earliest, latest, int64_t{0}}) {
                for (const auto size : sizes) {
                    SCOPED_TRACE(::testing::Message() << "rate=" << rate << " start=" << start << " now=" << now << " size=" << size);
                    EXPECT_EQ(bucket.Consume(size, At(now)).count(), model.Consume(size, now));
                }
            }
        }
    }
}
} // namespace
