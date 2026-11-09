#pragma once

#include "infra/json.hpp"
#include "ss_outbound.hpp"

#include <tl/expected.hpp>
#include <optional>
#include <string>

namespace proxy::shadowsocks::outbound {

[[nodiscard]] tl::expected<std::optional<proxy::uot::Version>, std::string>
ParseUotVersion(const json::object& source);

}  // namespace proxy::shadowsocks::outbound
