#pragma once

#include "acppnode/infra/json.hpp"

#include <cstdint>
#include <expected>
#include <optional>
#include <string>

namespace acpp {

inline constexpr uint32_t kHttp2MaxInitialWindow = 0x7fffffffU;

[[nodiscard]] std::expected<std::optional<uint32_t>, std::string>
ParseHttp2InitialWindow(const json::object& source);

}  // namespace acpp
