#pragma once

#include <string_view>

namespace acpp::transport::internet::detail {

[[nodiscard]] inline bool PathPrefixMatchesSegment(
    std::string_view configured,
    std::string_view actual) noexcept {
    const std::string_view expected = configured.empty()
        ? std::string_view("/")
        : configured;
    if (const size_t query = actual.find('?'); query != std::string_view::npos) {
        actual = actual.substr(0, query);
    }
    if (!actual.starts_with(expected)) {
        return false;
    }
    if (expected == "/" || actual.size() == expected.size() ||
        expected.back() == '/') {
        return true;
    }
    return actual[expected.size()] == '/';
}

}  // namespace acpp::transport::internet::detail
