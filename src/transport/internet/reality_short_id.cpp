#include "acppnode/transport/internet/reality_short_id.hpp"

namespace acpp::transport::internet {
namespace {

int HexValue(char value) noexcept {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

}  // namespace

std::expected<RealityShortId, RealityShortIdError>
ParseRealityShortId(std::string_view value) noexcept {
    if (value.size() % 2 != 0 || value.size() > kRealityShortIdSize * 2) {
        return std::unexpected(RealityShortIdError::InvalidFormat);
    }

    RealityShortId parsed{};
    for (std::size_t i = 0; i < value.size(); i += 2) {
        const int high = HexValue(value[i]);
        const int low = HexValue(value[i + 1]);
        if (high < 0 || low < 0) {
            return std::unexpected(RealityShortIdError::InvalidFormat);
        }
        parsed[i / 2] = static_cast<uint8_t>((high << 4) | low);
    }
    return parsed;
}

}  // namespace acpp::transport::internet
