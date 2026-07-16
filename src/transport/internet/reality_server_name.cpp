#include "acppnode/transport/internet/reality_server_name.hpp"

#include <algorithm>
#include <bitset>

namespace acpp::transport::internet {
namespace {

[[nodiscard]] uint16_t ReadBigEndianU16(const uint8_t* data) noexcept {
    return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) |
                                 static_cast<uint16_t>(data[1]));
}

[[nodiscard]] constexpr unsigned char LowerAscii(unsigned char value) noexcept {
    return value >= 'A' && value <= 'Z'
        ? static_cast<unsigned char>(value + ('a' - 'A'))
        : value;
}

[[nodiscard]] bool EqualsDnsName(std::string_view lhs,
                                 std::string_view rhs) noexcept {
    return lhs.size() == rhs.size() &&
           std::ranges::equal(lhs, rhs, [](char left, char right) {
               return LowerAscii(static_cast<unsigned char>(left)) ==
                      LowerAscii(static_cast<unsigned char>(right));
           });
}

}  // namespace

std::expected<std::string_view, RealityServerNameExtensionError>
ParseRealityServerNameExtension(std::span<const uint8_t> extension) noexcept {
    if (extension.size() < 2) {
        return std::unexpected(
            RealityServerNameExtensionError::InvalidFormat);
    }

    const uint16_t list_size = ReadBigEndianU16(extension.data());
    if (static_cast<std::size_t>(list_size) + 2 != extension.size()) {
        return std::unexpected(
            RealityServerNameExtensionError::InvalidFormat);
    }

    std::bitset<256> seen_types;
    std::string_view host_name;
    std::size_t position = 2;
    const std::size_t end = extension.size();
    while (position < end) {
        if (end - position < 3) {
            return std::unexpected(
                RealityServerNameExtensionError::InvalidFormat);
        }
        const uint8_t name_type = extension[position++];
        if (seen_types.test(name_type)) {
            return std::unexpected(
                RealityServerNameExtensionError::InvalidFormat);
        }
        seen_types.set(name_type);
        const uint16_t name_size =
            ReadBigEndianU16(extension.data() + position);
        position += 2;
        if (name_size == 0 || name_size > end - position) {
            return std::unexpected(
                RealityServerNameExtensionError::InvalidFormat);
        }
        if (name_type == 0) {
            host_name = std::string_view(
                reinterpret_cast<const char*>(extension.data() + position),
                name_size);
        }
        position += name_size;
    }
    if (host_name.empty()) {
        return std::unexpected(
            RealityServerNameExtensionError::InvalidFormat);
    }
    return host_name;
}

bool IsRealityServerNameAllowed(
    std::span<const std::string> allowed,
    std::string_view requested) noexcept {
    return std::ranges::any_of(allowed, [requested](const std::string& name) {
        return EqualsDnsName(name, requested);
    });
}

}  // namespace acpp::transport::internet
