#pragma once

#include "acppnode/infra/json.hpp"
#include "acppnode/proxy/anytls/outbound/anytls_outbound.hpp"

#include <expected>
#include <string>

namespace acpp::proxy::anytls::outbound {

[[nodiscard]] std::expected<Settings, std::string> ParseSettings(
    const json::object& source);

}  // namespace acpp::proxy::anytls::outbound
