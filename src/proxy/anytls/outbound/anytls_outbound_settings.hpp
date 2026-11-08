#pragma once

#include "infra/json.hpp"
#include "anytls_outbound.hpp"

#include <tl/expected.hpp>
#include <string>

namespace proxy::anytls::outbound {

[[nodiscard]] tl::expected<Settings, std::string> ParseSettings(
    const json::object& source);

}  // namespace proxy::anytls::outbound
