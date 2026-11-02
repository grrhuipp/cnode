#pragma once

#include "acppnode/infra/json.hpp"

#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace acpp {

[[nodiscard]] std::expected<std::optional<uint64_t>, std::string>
ParseJsonUint64(
    const json::object& source,
    std::string_view key,
    uint64_t maximum = std::numeric_limits<uint64_t>::max());
}  // namespace acpp
