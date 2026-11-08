#pragma once

#include "infra/json.hpp"

#include <cstdint>
#include <tl/expected.hpp>
#include <optional>
#include <string>


inline constexpr uint32_t kHttp2MaxInitialWindow = 0x7fffffffU;

[[nodiscard]] tl::expected<std::optional<uint32_t>, std::string>
ParseHttp2InitialWindow(const json::object& source);

