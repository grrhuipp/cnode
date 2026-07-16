#include "acppnode/app/worker.hpp"
#include "acppnode/app/router/router.hpp"
#include "acppnode/app/proxyman/outbound/prepared_config.hpp"

#include <concepts>
#include <string>
#include <utility>

static_assert(std::same_as<
    decltype(std::declval<acpp::Worker&>().ShutdownTask()),
    acpp::net::awaitable<void>>);
static_assert(std::same_as<
    decltype(std::declval<acpp::Worker&>().AddOutboundTask(
        std::declval<acpp::proxyman::outbound::PreparedOutboundConfig>())),
    acpp::net::awaitable<void>>);
static_assert(noexcept(std::declval<acpp::app::router::Router&>().SetDefaultOutbound(
    std::declval<std::string>())));

int main() {
    return 0;
}
