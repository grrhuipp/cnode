#pragma once

#include <cstdint>

namespace vmess {

// Wire values of the request header security nibble.
enum class Security : uint8_t {
    AES_128_GCM       = 3,
    CHACHA20_POLY1305 = 4,
    NONE              = 5,
    ZERO              = 6
};

}  // namespace vmess
