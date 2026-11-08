#pragma once

#include <array>
#include <string_view>

namespace trojan {

using PasswordHash = std::array<char, 56>;

[[nodiscard]] PasswordHash HashPassword(std::string_view password) noexcept;

}  // namespace trojan
