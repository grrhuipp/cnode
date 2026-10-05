#pragma once

#include "acppnode/infra/json.hpp"
#include "anytls_outbound.hpp"

#include <tl/expected.hpp>
#include <string>

namespace acpp::proxy::anytls::outbound {

[[nodiscard]] tl::expected<Settings, std::string> ParseSettings(
    const json::object& source);

}  // namespace acpp::proxy::anytls::outbound
