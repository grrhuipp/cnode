#include "acppnode/app/worker.hpp"
#include "acppnode/app/request_load_state.hpp"
#include "acppnode/app/router/router.hpp"
#include "acppnode/app/proxyman/outbound/prepared_config.hpp"

#include <concepts>
#include <string>
#include <utility>

static_assert(std::same_as<
    decltype(std::declval<acpp::Worker&>().ShutdownTask()),
    acpp::net::awaitable<void>>);
static_assert(std::same_as<
    decltype(std::declval<acpp::Worker&>().StartWorkerLocalServices()),
    void>);
static_assert(std::same_as<
    decltype(std::declval<acpp::Worker&>().AddOutboundTask(
        std::declval<acpp::proxyman::outbound::PreparedOutboundConfig>())),
    acpp::net::awaitable<void>>);
static_assert(std::same_as<
    decltype(std::declval<acpp::Worker&>().UnregisterListenerTask(
        std::declval<std::string>())),
    acpp::net::awaitable<void>>);
static_assert(noexcept(std::declval<acpp::app::router::Router&>().SetDefaultOutbound(
    std::declval<std::string>())));

int main() {
    acpp::app::RequestLoadState load(3, 7);
    if (load.ActiveConnections() != 0 || load.PressureIdleTimeout() != 0) return 1;
    {
        acpp::app::RequestLoadState::PhysicalConnectionScope physical(load);
        acpp::app::RequestLoadState::DispatchScope first(&load);
        if (load.ActiveConnections() != 1 || load.PressureIdleTimeout() != 0) return 2;
        {
            acpp::app::RequestLoadState::DispatchScope second(&load);
            acpp::app::RequestLoadState::DispatchScope third(&load);
            if (load.ActiveConnections() != 3 || load.PressureIdleTimeout() != 7) return 3;
            load.Configure(2, 5);
            if (load.PressureIdleTimeout() != 5) return 4;
        }
        if (load.ActiveConnections() != 1 || load.PressureIdleTimeout() != 0) return 5;
    }
    if (load.ActiveConnections() != 0) return 6;
    load.Configure(1, 9);
    {
        acpp::app::RequestLoadState::PhysicalConnectionScope physical(load);
        if (load.ActiveConnections() != 1 || load.PressureIdleTimeout() != 9) return 7;
    }
    return 0;
}
