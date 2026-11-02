#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace acpp {

// Base64 编码（用于 WebSocket 握手密钥等内部场景）
inline std::string Base64Encode(const uint8_t* data, size_t len) {
    static const char* kTable =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    result.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t b = (data[i] << 16) |
                     (i + 1 < len ? data[i + 1] << 8 : 0) |
                     (i + 2 < len ? data[i + 2]      : 0);
        result += kTable[(b >> 18) & 0x3F];
        result += kTable[(b >> 12) & 0x3F];
        result += (i + 1 < len) ? kTable[(b >> 6) & 0x3F] : '=';
        result += (i + 2 < len) ? kTable[(b >> 0) & 0x3F] : '=';
    }
    return result;
}

}  // namespace acpp
