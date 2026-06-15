#pragma once

#include "acppnode/common/user_profile.hpp"

#include <string>

namespace acpp::trojan {

struct TrojanUserInfo {
    std::string password_hash;  // SHA224 hash used for storage and lookup.
    ::acpp::UserProfile profile;
};

}  // namespace acpp::trojan
