#include "acppnode/app/worker.hpp"

#include <concepts>
#include <utility>

static_assert(std::same_as<
    decltype(std::declval<acpp::Worker&>().ShutdownTask()),
    acpp::net::awaitable<void>>);

int main() {
    return 0;
}
