#pragma once

#include <span>
#include <string>
#include <string_view>

namespace transport::internet {

[[nodiscard]] bool IsRealityServerNameAllowed(
    std::span<const std::string> allowed,
    std::string_view requested) noexcept;

}  // namespace transport::internet
