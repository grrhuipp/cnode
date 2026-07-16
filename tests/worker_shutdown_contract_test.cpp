#include "acppnode/app/worker.hpp"

#include <concepts>
#include <string>
#include <utility>
#include <vector>

static_assert(std::same_as<
    decltype(std::declval<acpp::Worker&>().ShutdownListenersTask(
        std::declval<std::vector<std::string>>())),
    acpp::net::awaitable<void>>);

int main() {
    return 0;
}
