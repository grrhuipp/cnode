#pragma once

#include "acppnode/common/user_profile.hpp"

#include <array>
#include <cstdint>
#include <string_view>

namespace acpp::anytls {

[[nodiscard]] std::array<uint8_t, 32> PasswordHash(std::string_view password) noexcept;

struct UserInfo {
    std::array<uint8_t, 32> password_hash{};
    ::acpp::UserProfile profile;
};

}  // namespace acpp::anytls
