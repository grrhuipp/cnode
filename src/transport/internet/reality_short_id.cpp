#include "acppnode/transport/internet/reality_short_id.hpp"
#include "acppnode/common/binary_text_codec.hpp"

namespace acpp::transport::internet {
tl::expected<RealityShortId, RealityShortIdError>
ParseRealityShortId(std::string_view value) noexcept {
    if (value.size() % 2 != 0 || value.size() > kRealityShortIdSize * 2) {
        return tl::unexpected(RealityShortIdError::InvalidFormat);
    }

    RealityShortId parsed{};
    for (std::size_t i = 0; i < value.size(); i += 2) {
        const int high = HexDigitValue(value[i]);
        const int low = HexDigitValue(value[i + 1]);
        if (high < 0 || low < 0) {
            return tl::unexpected(RealityShortIdError::InvalidFormat);
        }
        parsed[i / 2] = static_cast<uint8_t>((high << 4) | low);
    }
    return parsed;
}

}  // namespace acpp::transport::internet
