#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
namespace proxy {

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

// 根据方法名获取密码参数（不区分大小写），含 AEAD 与 2022-blake3 方法。
[[nodiscard]] std::optional<SsCipherInfo> ParseCipherMethod(std::string_view method);

}  // namespace proxy
