#pragma once

#include <cstdint>
#include <string>

namespace acpp::trojan {

struct TrojanUserInfo {
    std::string password_hash;  // SHA224 hash used for storage and lookup.
    std::string email;
    int64_t user_id = 0;
    uint64_t speed_limit = 0;   // bytes/s, 0 = unlimited
    uint32_t device_limit = 0;  // online IP limit, 0 = unlimited
};

}  // namespace acpp::trojan
