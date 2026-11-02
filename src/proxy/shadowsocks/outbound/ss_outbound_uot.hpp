#pragma once

#include "acppnode/infra/json.hpp"
#include "ss_outbound.hpp"

#include <tl/expected.hpp>
#include <optional>
#include <string>

namespace acpp::proxy::shadowsocks::outbound {

[[nodiscard]] tl::expected<std::optional<SsUotVersion>, std::string>
ParseUotVersion(const json::object& source);

}  // namespace acpp::proxy::shadowsocks::outbound
