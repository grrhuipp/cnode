#include "acppnode/transport/internet/reality_server_name.hpp"

#include <algorithm>

namespace acpp::transport::internet {
namespace {

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

bool IsRealityServerNameAllowed(
    std::span<const std::string> allowed,
    std::string_view requested) noexcept {
    return std::ranges::any_of(allowed, [requested](const std::string& name) {
        return EqualsDnsName(name, requested);
    });
}

}  // namespace acpp::transport::internet
