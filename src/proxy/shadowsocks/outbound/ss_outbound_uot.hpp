#pragma once

#include "acppnode/infra/json.hpp"
#include "acppnode/proxy/shadowsocks/outbound/ss_outbound.hpp"

#include <expected>
#include <optional>
#include <string>

namespace acpp::proxy::shadowsocks::outbound {

[[nodiscard]] std::expected<std::optional<SsUotVersion>, std::string>
ParseUotVersion(const json::object& source);

}  // namespace acpp::proxy::shadowsocks::outbound
