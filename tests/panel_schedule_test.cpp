#include <gtest/gtest.h>

#include "panel_schedule.hpp"

#include <chrono>

TEST(PanelSchedule, Contract) {
    using ::controller::PanelInterval;
    using namespace std::chrono_literals;

    ASSERT_FALSE((PanelInterval(45, 60) != 45s));
    ASSERT_FALSE((PanelInterval(30, 60) != 30s));
    ASSERT_FALSE((PanelInterval(0, 60) != 60s));
    ASSERT_FALSE((PanelInterval(-1, 30) != 30s));
}
