#pragma once

#include <cstddef>
#include <cstdint>

namespace ss {

enum class SsCipherType : uint8_t {
    AES_128_GCM = 0,
    AES_256_GCM = 1,
    CHACHA20_POLY1305 = 2,
    AES_128_GCM_2022 = 3,
    AES_256_GCM_2022 = 4,
    CHACHA20_POLY1305_2022 = 5,
};

struct SsCipherInfo {
    SsCipherType type;
    size_t key_size;
    size_t salt_size;
};

}  // namespace ss
