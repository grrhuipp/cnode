// Keep the PImpl header first: no factory/configuration/protocol definitions.
#include "acppnode/app/proxyman/inbound/manager.hpp"

#include <concepts>
#include <type_traits>
#include <utility>

namespace {
template <typename T>
concept Complete = requires { sizeof(T); };

using Manager = acpp::proxyman::inbound::Manager;
static_assert(!Complete<acpp::proxyman::inbound::BuildRequest>);
static_assert(!Complete<acpp::proxyman::inbound::Handler>);
static_assert(!Complete<acpp::Inbound>);
static_assert(std::is_constructible_v<Manager, acpp::StatsShard&>);
static_assert(std::same_as<
    decltype(std::declval<Manager&>().NewHandler(
        std::declval<acpp::ConnectionLimiterPtr>(),
        std::declval<const acpp::proxyman::inbound::BuildRequest&>())),
    std::unique_ptr<acpp::Inbound>>);
}  // namespace

int main() {}
