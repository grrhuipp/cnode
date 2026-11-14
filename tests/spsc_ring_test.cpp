#include "common/spsc_ring.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <thread>

namespace {

struct Slot {
    uint64_t sequence = 0;
    uint64_t check = 0;
};

TEST(SpscRing, RefusesWhenFullAndReturnsSlotsInOrder) {
    common::SpscRing<Slot, 4> ring;
    Slot out;
    EXPECT_TRUE(ring.Empty());
    EXPECT_FALSE(ring.TryPop(out));
    for (uint64_t n = 0; n != 4; ++n) EXPECT_TRUE(ring.TryPush({n, ~n}));
    EXPECT_FALSE(ring.HasRoom());
    EXPECT_FALSE(ring.TryPush({4, ~uint64_t{4}}));
    ASSERT_TRUE(ring.TryPop(out));
    EXPECT_EQ(out.sequence, 0u);
    EXPECT_TRUE(ring.HasRoom());
    EXPECT_TRUE(ring.TryPush({4, ~uint64_t{4}}));
    for (uint64_t n = 1; n != 5; ++n) {
        ASSERT_TRUE(ring.TryPop(out));
        EXPECT_EQ(out.sequence, n);
        EXPECT_EQ(out.check, ~n);
    }
    EXPECT_TRUE(ring.Empty());
}

// Producer and consumer on separate threads: every slot arrives once, in
// order and intact, across many wraps of a small ring.
TEST(SpscRing, ConcurrentProducerAndConsumerKeepOrderAndContents) {
    constexpr uint64_t kCount = 2'000'000;
    common::SpscRing<Slot, 64> ring;
    std::thread producer([&] {
        for (uint64_t n = 0; n != kCount;) {
            if (ring.TryPush({n, n * 0x9e3779b97f4a7c15ULL})) ++n;
            else std::this_thread::yield();
        }
    });
    uint64_t expected = 0;
    bool intact = true;
    Slot out;
    while (expected != kCount) {
        if (!ring.TryPop(out)) {
            std::this_thread::yield();
            continue;
        }
        intact = intact && out.sequence == expected &&
                 out.check == expected * 0x9e3779b97f4a7c15ULL;
        ++expected;
    }
    producer.join();
    EXPECT_TRUE(intact);
    EXPECT_TRUE(ring.Empty());
}

}  // namespace
