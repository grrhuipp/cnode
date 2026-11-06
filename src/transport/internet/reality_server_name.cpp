#include "acppnode/transport/internet/reality_server_name.hpp"
#include "acppnode/common/domain_name.hpp"

#include <algorithm>

namespace acpp::transport::internet {
bool IsRealityServerNameAllowed(
    std::span<const std::string> allowed,
    std::string_view requested) noexcept {
    return std::ranges::any_of(allowed, [requested](const std::string& name) {
        return domain::DnsHostnamesEqual(name, requested);
    });
}

}  // namespace acpp::transport::internet
