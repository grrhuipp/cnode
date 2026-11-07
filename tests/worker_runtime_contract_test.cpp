#include "acppnode/app/request_load_state.hpp"
#include "acppnode/app/session_group_executor.hpp"
#include "acppnode/app/session_tracking.hpp"

#include <type_traits>
#include <unordered_map>

static_assert(
    sizeof(acpp::app::SessionTrackingState) ==
    sizeof(std::unordered_map<std::string, int>));
static_assert(
    std::is_same_v<
        decltype(acpp::app::DomainTrafficSnapshot::domain),
        std::weak_ptr<acpp::ExecutionDomain>>);

int main() {
    acpp::app::RequestLoadState load(3, 7);
    if (load.ActiveConnections() != 0 || load.PressureIdleTimeout() != 0) return 1;
    {
        acpp::app::RequestLoadState::PhysicalConnectionScope physical(load);
        acpp::app::RequestLoadState::DispatchScope first(load);
        if (load.ActiveConnections() != 1 || load.PressureIdleTimeout() != 0) return 2;
        {
            acpp::app::RequestLoadState::DispatchScope second(load);
            acpp::app::RequestLoadState::DispatchScope third(load);
            if (load.ActiveConnections() != 3 || load.PressureIdleTimeout() != 7) return 3;
        }
        if (load.ActiveConnections() != 1 || load.PressureIdleTimeout() != 0) return 5;
    }
    if (load.ActiveConnections() != 0) return 6;
    acpp::app::RequestLoadState one_connection(1, 9);
    {
        acpp::app::RequestLoadState::PhysicalConnectionScope physical(one_connection);
        if (one_connection.ActiveConnections() != 1 ||
            one_connection.PressureIdleTimeout() != 9) return 7;
    }
    return 0;
}
