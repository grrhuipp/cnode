#pragma once

#include "acppnode/proxy/shadowsocks/shadowsocks_protocol.hpp"

#include <cstdint>
#include <cstddef>
#include <string>

namespace acpp::ss {

struct SsUserInfo {
    std::string password;
    std::string email;
    int64_t user_id = 0;
    uint64_t speed_limit = 0;
    uint32_t device_limit = 0;
    KeyBytes derived_key;
    SsCipherType cipher_type = SsCipherType::AES_256_GCM;
    size_t key_size = 32;
    size_t salt_size = 32;
};

}  // namespace acpp::ss
