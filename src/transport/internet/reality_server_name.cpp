#include "acppnode/transport/internet/reality_server_name.hpp"
#include "acppnode/common/domain_name.hpp"

#include <algorithm>

namespace acpp::transport::internet {
namespace {

[[nodiscard]] bool EqualsDnsName(std::string_view lhs,
                                 std::string_view rhs) noexcept {
    // RFC 1034 section 3.1: the final dot denotes the DNS root. RFC 6066
    // senders omit it on the wire; tolerate its equivalent presentation here.
    if (lhs.size() > 1 && lhs.ends_with('.')) lhs.remove_suffix(1);
    if (rhs.size() > 1 && rhs.ends_with('.')) rhs.remove_suffix(1);
    return lhs.size() == rhs.size() &&
           std::ranges::equal(lhs, rhs, [](char left, char right) {
               return domain::ToLowerAscii(static_cast<unsigned char>(left)) ==
                      domain::ToLowerAscii(static_cast<unsigned char>(right));
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
