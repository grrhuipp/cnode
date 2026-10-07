#pragma once

#include <span>
#include <string>
#include <string_view>

namespace acpp::transport::internet {

[[nodiscard]] bool IsRealityServerNameAllowed(
    std::span<const std::string> allowed,
    std::string_view requested) noexcept;

}  // namespace acpp::transport::internet
