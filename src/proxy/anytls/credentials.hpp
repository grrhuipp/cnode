#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace acpp::anytls {

[[nodiscard]] std::array<uint8_t, 32> PasswordHash(std::string_view password) noexcept;

}  // namespace acpp::anytls
