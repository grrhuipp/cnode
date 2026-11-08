#pragma once

#include <string_view>

namespace transport::internet::detail {

// An unset configured path addresses the origin root.
[[nodiscard]] constexpr std::string_view EffectiveHttpPath(
    std::string_view configured) noexcept {
    return configured.empty() ? std::string_view("/") : configured;
}

[[nodiscard]] constexpr std::string_view PathWithoutQuery(
    std::string_view path) noexcept {
    return path.substr(0, path.find('?'));
}

[[nodiscard]] constexpr bool PathMatchesExactly(
    std::string_view configured,
    std::string_view actual) noexcept {
    return PathWithoutQuery(actual) == EffectiveHttpPath(configured);
}

[[nodiscard]] constexpr bool PathPrefixMatchesSegment(
    std::string_view configured,
    std::string_view actual) noexcept {
    const std::string_view expected = EffectiveHttpPath(configured);
    actual = PathWithoutQuery(actual);
    if (!actual.starts_with(expected)) {
        return false;
    }
    if (expected == "/" || actual.size() == expected.size() ||
        expected.back() == '/') {
        return true;
    }
    return actual[expected.size()] == '/';
}

}  // namespace transport::internet::detail
