#pragma once

#include <cstdint>
#include <string>

namespace acpp {

struct UserProfile {
    int64_t user_id = 0;
    std::string email;
    uint64_t speed_limit = 0;
    uint32_t device_limit = 0;
};

}  // namespace acpp
