#include "credentials.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <cctype>
#include <cstring>

namespace acpp::vless {

namespace {

[[nodiscard]] int HexValue(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

[[nodiscard]] std::array<uint8_t, 16>
MapCustomIdToUuidV5(std::string_view id) noexcept {
    std::array<uint8_t, 16 + 30> input{};
    std::memcpy(input.data() + 16, id.data(), id.size());

    std::array<uint8_t, SHA_DIGEST_LENGTH> digest{};
    SHA1(input.data(), 16 + id.size(), digest.data());

    std::array<uint8_t, 16> out{};
    std::copy_n(digest.begin(), out.size(), out.begin());
    out[6] = static_cast<uint8_t>((out[6] & 0x0f) | 0x50);
    out[8] = static_cast<uint8_t>((out[8] & 0x3f) | 0x80);
    return out;
}

}  // namespace

std::optional<std::array<uint8_t, 16>>
ParseUuidBytes(std::string_view uuid) noexcept {
    std::array<uint8_t, 16> out{};
    size_t nibble_index = 0;
    bool uuid_candidate = true;

    for (char ch : uuid) {
        if (ch == '-') {
            continue;
        }
        const int value = HexValue(ch);
        if (value < 0 || nibble_index >= 32) {
            uuid_candidate = false;
            break;
        }
        const size_t byte_index = nibble_index / 2;
        if ((nibble_index & 1) == 0) {
            out[byte_index] = static_cast<uint8_t>(value << 4);
        } else {
            out[byte_index] |= static_cast<uint8_t>(value);
        }
        ++nibble_index;
    }

    if (uuid_candidate && nibble_index == 32) {
        return out;
    }
    if (!uuid.empty() && uuid.size() <= 30) {
        return MapCustomIdToUuidV5(uuid);
    }
    return std::nullopt;
}

std::string NormalizeFlow(std::string_view flow) {
    std::string out(flow);
    std::ranges::transform(out, out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

}  // namespace acpp::vless
