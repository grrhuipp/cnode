#include <gtest/gtest.h>

#include "controller/node_transaction.hpp"
#include <chrono>

TEST(PanelSchedule, UsesPositiveConfiguredInterval) {
    using namespace std::chrono_literals;
    EXPECT_EQ(::controller::PanelInterval(45, 60), 45s);
    EXPECT_EQ(::controller::PanelInterval(30, 60), 30s);
}

TEST(PanelSchedule, FallsBackForNonpositiveConfiguredInterval) {
    using namespace std::chrono_literals;
    EXPECT_EQ(::controller::PanelInterval(0, 60), 60s);
    EXPECT_EQ(::controller::PanelInterval(-1, 30), 30s);
}
