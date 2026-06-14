#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace acpp::anytls {

[[nodiscard]] std::array<uint8_t, 32> PasswordHash(std::string_view password) noexcept;

struct UserInfo {
    std::array<uint8_t, 32> password_hash{};
    std::string email;
    uint64_t user_id = 0;
    uint64_t speed_limit = 0;
    uint32_t device_limit = 0;
};

}  // namespace acpp::anytls
