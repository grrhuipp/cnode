#include <gtest/gtest.h>

#include "proxy/vmess/session_history.hpp"
namespace {
proxy::VmessSessionHistory::SessionKey Key(uint8_t byte) {
    proxy::VmessSessionHistory::SessionKey key{};
    key.fill(byte);
    return key;
}

TEST(VmessSessionHistory, FullTableRejectsWithoutEvictingUnexpiredTuples) {
    proxy::VmessSessionHistory history(2);
    EXPECT_TRUE(history.AddIfNew(Key(1), 1000));
    EXPECT_TRUE(history.AddIfNew(Key(2), 1001));
    EXPECT_FALSE(history.AddIfNew(Key(3), 1002));
    EXPECT_FALSE(history.AddIfNew(Key(1), 1002));
    EXPECT_FALSE(history.AddIfNew(Key(2), 1002));
    EXPECT_TRUE(history.AddIfNew(Key(3), 1000 + proxy::VmessSessionHistory::kTtlSeconds));
    EXPECT_FALSE(history.AddIfNew(Key(2), 1000 + proxy::VmessSessionHistory::kTtlSeconds));
    EXPECT_FALSE(history.AddIfNew(Key(3), 1000 + proxy::VmessSessionHistory::kTtlSeconds));
}

TEST(VmessSessionHistory, ReplayDoesNotExtendExactExpiryBoundary) {
    proxy::VmessSessionHistory history(1);
    EXPECT_TRUE(history.AddIfNew(Key(1), 1000));
    EXPECT_FALSE(history.AddIfNew(Key(1), 1000 + proxy::VmessSessionHistory::kTtlSeconds - 1));
    EXPECT_TRUE(history.AddIfNew(Key(1), 1000 + proxy::VmessSessionHistory::kTtlSeconds));
}

TEST(VmessSessionHistory, ZeroCapacityNeverAccepts) {
    proxy::VmessSessionHistory history(0);
    EXPECT_FALSE(history.AddIfNew(Key(1), 1000));
    EXPECT_FALSE(history.AddIfNew(Key(1), 1000 + proxy::VmessSessionHistory::kTtlSeconds));
}
}  // namespace
