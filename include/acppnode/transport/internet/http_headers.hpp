#pragma once

#include <string>
#include <string_view>
#include <unordered_map>

namespace acpp::transport::internet {

using HttpHeaders = std::unordered_map<std::string, std::string>;

[[nodiscard]] inline bool IsValidHttpHeaderName(
    std::string_view name) noexcept {
    if (name.empty()) return false;
    for (const unsigned char ch : name) {
        if ((ch >= '0' && ch <= '9') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= 'a' && ch <= 'z')) {
            continue;
        }
        switch (ch) {
            case '!': case '#': case '$': case '%': case '&': case '\'':
            case '*': case '+': case '-': case '.': case '^': case '_':
            case '`': case '|': case '~':
                continue;
            default:
                return false;
        }
    }
    return true;
}

[[nodiscard]] inline bool IsValidHttpHeaderValue(
    std::string_view value) noexcept {
    for (const unsigned char ch : value) {
        if ((ch < 0x20 && ch != '\t') || ch == 0x7f) {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline bool IsValidHttpRequestTarget(
    std::string_view target) noexcept {
    if (target.empty() || target.front() != '/') return false;
    for (const unsigned char ch : target) {
        if (ch <= 0x20 || ch == 0x7f || ch == '#') {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline bool IsValidHttpAuthority(
    std::string_view authority) noexcept {
    if (authority.empty()) return false;
    for (const unsigned char ch : authority) {
        if (ch <= 0x20 || ch == 0x7f || ch == '/' || ch == '\\' ||
            ch == '?' || ch == '#' || ch == '@') {
            return false;
        }
    }
    return true;
}

[[nodiscard]] inline std::string NormalizeHttpHeaderName(
    std::string_view name) {
    std::string normalized(name);
    for (char& ch : normalized) {
        if (ch >= 'A' && ch <= 'Z') {
            ch = static_cast<char>(ch - 'A' + 'a');
        }
    }
    return normalized;
}

}  // namespace acpp::transport::internet
