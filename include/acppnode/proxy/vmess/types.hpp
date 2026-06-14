#pragma once

#include <cstdint>

namespace acpp::vmess {

enum class Security : uint8_t {
    AUTO              = 0,
    AES_128_GCM      = 3,
    CHACHA20_POLY1305 = 4,
    NONE             = 5,
    ZERO             = 6
};

}  // namespace acpp::vmess
