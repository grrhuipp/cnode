#include "reality_key_share.hpp"

#include <algorithm>
#include <optional>

namespace acpp::transport::internet {
namespace {

constexpr uint16_t kTlsGroupX25519 = 29;
constexpr uint16_t kTlsGroupX25519MlKem768 = 0x11ec;
constexpr std::size_t kMlKem768PublicKeySize = 1184;
constexpr std::size_t kX25519MlKem768ClientShareSize =
    kMlKem768PublicKeySize + kRealityKeySize;

[[nodiscard]] uint16_t ReadBigEndianU16(const uint8_t* data) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) |
                                 static_cast<uint16_t>(data[1]));
}

}  // namespace

std::expected<RealityKey, RealityKeyShareError>
ParseRealityClientKeyShareExtension(
    std::span<const uint8_t> extension) noexcept {
    if (extension.size() < 2) {
        return std::unexpected(RealityKeyShareError::InvalidFormat);
    }
    const uint16_t list_size = ReadBigEndianU16(extension.data());
    if (static_cast<std::size_t>(list_size) + 2 != extension.size()) {
        return std::unexpected(RealityKeyShareError::InvalidFormat);
    }

    std::optional<RealityKey> x25519;
    std::optional<RealityKey> hybrid_x25519;
    bool saw_x25519 = false;
    bool saw_hybrid = false;
    std::size_t position = 2;
    const std::size_t end = extension.size();
    while (position < end) {
        if (end - position < 4) {
            return std::unexpected(RealityKeyShareError::InvalidFormat);
        }
        const uint16_t group =
            ReadBigEndianU16(extension.data() + position);
        position += 2;
        const uint16_t key_size =
            ReadBigEndianU16(extension.data() + position);
        position += 2;
        if (key_size == 0 || key_size > end - position) {
            return std::unexpected(RealityKeyShareError::InvalidFormat);
        }

        const uint8_t* key = extension.data() + position;
        if (group == kTlsGroupX25519) {
            if (saw_x25519 || key_size != kRealityKeySize) {
                return std::unexpected(RealityKeyShareError::InvalidFormat);
            }
            saw_x25519 = true;
            RealityKey parsed{};
            std::copy_n(key, parsed.size(), parsed.begin());
            x25519 = parsed;
        }
        if (group == kTlsGroupX25519MlKem768) {
            if (saw_hybrid || key_size != kX25519MlKem768ClientShareSize) {
                return std::unexpected(RealityKeyShareError::InvalidFormat);
            }
            saw_hybrid = true;
            RealityKey parsed{};
            std::copy_n(
                key + key_size - kRealityKeySize,
                parsed.size(),
                parsed.begin());
            hybrid_x25519 = parsed;
        }
        position += key_size;
    }
    if (x25519) return *x25519;
    if (hybrid_x25519) return *hybrid_x25519;
    return std::unexpected(RealityKeyShareError::InvalidFormat);
}

}  // namespace acpp::transport::internet
