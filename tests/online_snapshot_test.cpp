#include <gtest/gtest.h>

#include "controller/node_transaction.hpp"
TEST(OnlineSnapshot, CountsUsersSeparatelyFromTheirDevices) {
    const auto snapshot = ::controller::BuildOnlineSnapshot({
        {7, "203.0.113.1"}, {7, "203.0.113.2"}, {8, "203.0.113.8"}});
    EXPECT_EQ(snapshot.user_count, 2);
    EXPECT_EQ(snapshot.entries.size(), 3);
}

TEST(OnlineSnapshot, DeduplicatesDevicesAndSortsByUserThenAddress) {
    const auto snapshot = ::controller::BuildOnlineSnapshot({
        {8, "203.0.113.8"}, {7, "203.0.113.2"},
        {7, "203.0.113.1"}, {7, "203.0.113.1"}});
    ASSERT_EQ(snapshot.entries.size(), 3);
    EXPECT_EQ(snapshot.entries[0].UID, 7);
    EXPECT_EQ(snapshot.entries[0].IP, "203.0.113.1");
    EXPECT_EQ(snapshot.entries[1].UID, 7);
    EXPECT_EQ(snapshot.entries[1].IP, "203.0.113.2");
    EXPECT_EQ(snapshot.entries[2].UID, 8);
    EXPECT_EQ(snapshot.entries[2].IP, "203.0.113.8");
}

TEST(OnlineSnapshot, ExcludesMissingIdentityAndEmptyAddress) {
    const auto snapshot = ::controller::BuildOnlineSnapshot({
        {0, "203.0.113.9"}, {9, ""}, {7, "203.0.113.1"}});
    EXPECT_EQ(snapshot.user_count, 1);
    ASSERT_EQ(snapshot.entries.size(), 1);
    EXPECT_EQ(snapshot.entries[0].UID, 7);
    EXPECT_EQ(snapshot.entries[0].IP, "203.0.113.1");
}
