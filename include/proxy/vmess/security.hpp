#pragma once

#include <cstdint>

namespace proxy::vmess {
// 请求头 security 半字节的线上取值。

enum class Security : uint8_t {
    AES_128_GCM = 3,
    CHACHA20_POLY1305 = 4,
    NONE = 5,
    ZERO = 6,
};

}  // namespace proxy::vmess
