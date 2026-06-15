#pragma once

#include "acppnode/common/user_profile.hpp"
#include "acppnode/proxy/shadowsocks/shadowsocks_protocol.hpp"

#include <cstddef>
#include <string>

namespace acpp::ss {

struct SsUserInfo {
    std::string password;
    ::acpp::UserProfile profile;
    KeyBytes derived_key;
    SsCipherType cipher_type = SsCipherType::AES_256_GCM;
    size_t key_size = 32;
    size_t salt_size = 32;
};

}  // namespace acpp::ss
