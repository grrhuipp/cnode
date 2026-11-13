#include <gtest/gtest.h>
#include "app/inbound_handler.hpp"
TEST(WorkerRequestLoad, NestedDispatchesReleasePressureWhenTheyComplete) {
    ::app::RequestLoadState load(3, 7);
    {
        ::app::RequestLoadState::PhysicalConnectionScope physical(load);
        ::app::RequestLoadState::DispatchScope first(load);
        EXPECT_EQ(load.ActiveConnections(), 1u);
        EXPECT_EQ(load.PressureIdleTimeout(), 0u);
        {
            ::app::RequestLoadState::DispatchScope second(load);
            ::app::RequestLoadState::DispatchScope third(load);
            EXPECT_EQ(load.ActiveConnections(), 3u);
            EXPECT_EQ(load.PressureIdleTimeout(), 7u);
        }
        EXPECT_EQ(load.ActiveConnections(), 1u);
        EXPECT_EQ(load.PressureIdleTimeout(), 0u);
    }
    EXPECT_EQ(load.ActiveConnections(), 0u);
}

TEST(WorkerRequestLoad, PhysicalConnectionReachesPressureThreshold) {
    ::app::RequestLoadState load(1, 9);
    {
        ::app::RequestLoadState::PhysicalConnectionScope physical(load);
        EXPECT_EQ(load.ActiveConnections(), 1u);
        EXPECT_EQ(load.PressureIdleTimeout(), 9u);
    }
    EXPECT_EQ(load.ActiveConnections(), 0u);
}
