#include "acppnode/transport/internet/reality_key.hpp"

namespace acpp::transport::internet {
namespace {

int Base64UrlValue(char value) noexcept {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '-') return 62;
    if (value == '_') return 63;
    return -1;
}

}  // namespace

std::expected<RealityKey, RealityKeyError>
ParseRealityKey(std::string_view value) noexcept {
    constexpr std::size_t kEncodedSize = (kRealityKeySize * 8 + 5) / 6;
    if (value.size() != kEncodedSize) {
        return std::unexpected(RealityKeyError::InvalidFormat);
    }

    RealityKey decoded{};
    std::size_t output = 0;
    uint32_t accumulator = 0;
    unsigned int bit_count = 0;
    for (const char character : value) {
        const int digit = Base64UrlValue(character);
        if (digit < 0) {
            return std::unexpected(RealityKeyError::InvalidFormat);
        }
        accumulator = (accumulator << 6) | static_cast<uint32_t>(digit);
        bit_count += 6;
        if (bit_count >= 8) {
            bit_count -= 8;
            if (output >= decoded.size()) {
                return std::unexpected(RealityKeyError::InvalidFormat);
            }
            decoded[output++] = static_cast<uint8_t>(accumulator >> bit_count);
            accumulator &= bit_count == 0 ? 0u : (uint32_t{1} << bit_count) - 1;
        }
    }
    if (output != decoded.size() || accumulator != 0) {
        return std::unexpected(RealityKeyError::InvalidFormat);
    }
    return decoded;
}

}  // namespace acpp::transport::internet
