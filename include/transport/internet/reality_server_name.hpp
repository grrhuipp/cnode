#pragma once

#include "common/domain_name.hpp"

#include <algorithm>
#include <span>
#include <string>
#include <string_view>

namespace transport::internet {

[[nodiscard]] inline bool IsRealityServerNameAllowed(
    std::span<const std::string> allowed,
    std::string_view requested) noexcept {
    return std::ranges::any_of(allowed, [requested](const std::string& name) {
        return domain::DnsHostnamesEqual(name, requested);
    });
}
}  // namespace transport::internet
