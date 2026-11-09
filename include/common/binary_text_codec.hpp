#pragma once

// RFC 4648 binary-to-text codecs: Base16 digits and unpadded base64url
// decoding. Single authority for these alphabets.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

// RFC 4648 §8 / RFC 5234 HEXDIG digit value, accepting both letter cases;
// -1 for any other character.
[[nodiscard]] constexpr int HexDigitValue(unsigned char ch) noexcept {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
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


// Parses exactly 32 hexadecimal digits; '-' separators are ignored wherever
// they appear. Signs, whitespace and prefixes are rejected.
[[nodiscard]] constexpr std::optional<std::array<uint8_t, 16>>
ParseUuid(std::string_view text) noexcept {
    std::array<uint8_t, 16> out{};
    size_t nibble_index = 0;
    for (const char ch : text) {
        if (ch == '-') {
            continue;
        }
        const int value = HexDigitValue(static_cast<unsigned char>(ch));
        if (value < 0 || nibble_index >= 32) {
            return std::nullopt;
        }
        uint8_t& byte = out[nibble_index / 2];
        byte = (nibble_index & 1) == 0
            ? static_cast<uint8_t>(value << 4)
            : static_cast<uint8_t>(byte | value);
        ++nibble_index;
    }
    if (nibble_index != 32) {
        return std::nullopt;
    }
    return out;
}

