#pragma once

// RFC 4648 binary-to-text codecs: Base16 digits, standard Base64 encoding and
// unpadded base64url decoding. Single authority for these alphabets.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>


// RFC 4648 §8 / RFC 5234 HEXDIG digit value, accepting both letter cases;
// -1 for any other character.
[[nodiscard]] constexpr int HexDigitValue(unsigned char ch) noexcept {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

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

// RFC 4648 §5 base64url digit value; '=' padding and the standard '+' '/'
// alphabet are invalid digits (-1).
[[nodiscard]] constexpr int Base64UrlDigitValue(char ch) noexcept {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '-') return 62;
    if (ch == '_') return 63;
    return -1;
}

[[nodiscard]] constexpr size_t Base64UrlDecodedSize(size_t encoded_size) noexcept {
    return encoded_size / 4 * 3 + (encoded_size % 4 * 3) / 4;
}

struct Base64UrlDecoded {
    size_t size = 0;
    // RFC 4648 §3.5 lets each decoder decide whether non-zero pad bits are
    // rejected, so the result reports them and the caller applies its policy.
    bool nonzero_pad_bits = false;
};

// Decodes unpadded base64url into out. nullopt for a non-alphabet digit, a
// length no encoding produces (size % 4 == 1) or output larger than out.
[[nodiscard]] constexpr std::optional<Base64UrlDecoded> DecodeBase64Url(
    std::string_view text, std::span<uint8_t> out) noexcept {
    if (text.size() % 4 == 1 || Base64UrlDecodedSize(text.size()) > out.size()) {
        return std::nullopt;
    }
    Base64UrlDecoded decoded;
    uint32_t accumulator = 0;
    unsigned int bit_count = 0;
    for (const char ch : text) {
        const int digit = Base64UrlDigitValue(ch);
        if (digit < 0) {
            return std::nullopt;
        }
        accumulator = (accumulator << 6) | static_cast<uint32_t>(digit);
        bit_count += 6;
        if (bit_count >= 8) {
            bit_count -= 8;
            out[decoded.size++] = static_cast<uint8_t>(accumulator >> bit_count);
            accumulator &= (uint32_t{1} << bit_count) - 1;
        }
    }
    decoded.nonzero_pad_bits = accumulator != 0;
    return decoded;
}

