#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace acpp::vless {

// Parses a UUID string, or maps a 1-30 byte VLESS custom id to UUIDv5.
[[nodiscard]] std::optional<std::array<uint8_t, 16>>
ParseUuidBytes(std::string_view uuid) noexcept;

[[nodiscard]] std::string NormalizeFlow(std::string_view flow);

}  // namespace acpp::vless
