#include <gtest/gtest.h>

#include "proxy/vmess/session_history.hpp"

namespace {
vmess::SessionHistory::SessionKey Key(uint8_t byte) {
    vmess::SessionHistory::SessionKey key{};
    key.fill(byte);
    return key;
}

TEST(VmessSessionHistory, FullTableRejectsWithoutEvictingUnexpiredTuples) {
    vmess::SessionHistory history(2);
    EXPECT_TRUE(history.AddIfNew(Key(1), 1000));
    EXPECT_TRUE(history.AddIfNew(Key(2), 1001));
    EXPECT_FALSE(history.AddIfNew(Key(3), 1002));
    EXPECT_FALSE(history.AddIfNew(Key(1), 1002));
    EXPECT_FALSE(history.AddIfNew(Key(2), 1002));
    EXPECT_TRUE(history.AddIfNew(Key(3), 1000 + vmess::SessionHistory::kTtlSeconds));
    EXPECT_FALSE(history.AddIfNew(Key(2), 1000 + vmess::SessionHistory::kTtlSeconds));
    EXPECT_FALSE(history.AddIfNew(Key(3), 1000 + vmess::SessionHistory::kTtlSeconds));
}

TEST(VmessSessionHistory, ReplayDoesNotExtendExactExpiryBoundary) {
    vmess::SessionHistory history(1);
    EXPECT_TRUE(history.AddIfNew(Key(1), 1000));
    EXPECT_FALSE(history.AddIfNew(Key(1), 1000 + vmess::SessionHistory::kTtlSeconds - 1));
    EXPECT_TRUE(history.AddIfNew(Key(1), 1000 + vmess::SessionHistory::kTtlSeconds));
}

TEST(VmessSessionHistory, ZeroCapacityNeverAccepts) {
    vmess::SessionHistory history(0);
    EXPECT_FALSE(history.AddIfNew(Key(1), 1000));
    EXPECT_FALSE(history.AddIfNew(Key(1), 1000 + vmess::SessionHistory::kTtlSeconds));
}
}  // namespace
