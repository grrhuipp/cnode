#include <gtest/gtest.h>

#include "app/request_load_state.hpp"

TEST(WorkerRuntimeContract, Contract) {
    ::app::RequestLoadState load(3, 7);
    ASSERT_FALSE((load.ActiveConnections() != 0 || load.PressureIdleTimeout() != 0));
    {
        ::app::RequestLoadState::PhysicalConnectionScope physical(load);
        ::app::RequestLoadState::DispatchScope first(load);
        ASSERT_FALSE((load.ActiveConnections() != 1 || load.PressureIdleTimeout() != 0));
        {
            ::app::RequestLoadState::DispatchScope second(load);
            ::app::RequestLoadState::DispatchScope third(load);
            ASSERT_FALSE((load.ActiveConnections() != 3 || load.PressureIdleTimeout() != 7));
        }
        ASSERT_FALSE((load.ActiveConnections() != 1 || load.PressureIdleTimeout() != 0));
    }
    ASSERT_FALSE((load.ActiveConnections() != 0));
    ::app::RequestLoadState one_connection(1, 9);
    {
        ::app::RequestLoadState::PhysicalConnectionScope physical(one_connection);
        ASSERT_FALSE((one_connection.ActiveConnections() != 1 ||
            one_connection.PressureIdleTimeout() != 9));
    }
}
