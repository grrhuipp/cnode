#pragma once

#include <string>
#include <string_view>

// 唯一的 ASCII 字符工具：只折叠 A-Z，不受 locale 影响，非 ASCII 字节原样保留。

[[nodiscard]] constexpr char ToLowerAscii(char ch) noexcept {
    return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch + ('a' - 'A')) : ch;
}

[[nodiscard]] constexpr unsigned char ToLowerAscii(unsigned char ch) noexcept {
    return ch >= 'A' && ch <= 'Z' ? static_cast<unsigned char>(ch + ('a' - 'A')) : ch;
}

inline void LowerAsciiInPlace(std::string& value) noexcept {
    for (char& ch : value) ch = ToLowerAscii(ch);
}

[[nodiscard]] inline std::string LowerAscii(std::string value) {
    LowerAsciiInPlace(value);
    return value;
}

[[nodiscard]] inline std::string LowerAscii(std::string_view value) {
    return LowerAscii(std::string(value));
}

[[nodiscard]] inline std::string LowerAscii(const char* value) {
    return LowerAscii(std::string(value));
}

[[nodiscard]] constexpr bool EqualsAsciiCI(std::string_view lhs, std::string_view rhs) noexcept {
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (ToLowerAscii(lhs[i]) != ToLowerAscii(rhs[i])) return false;
    }
    return true;
}

// 去掉首尾 SP/HTAB 以及游离的 CR/LF。
[[nodiscard]] constexpr std::string_view TrimAscii(std::string_view value) noexcept {
    constexpr auto is_space = [](char ch) noexcept {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
    };
    while (!value.empty() && is_space(value.front())) value.remove_prefix(1);
    while (!value.empty() && is_space(value.back())) value.remove_suffix(1);
    return value;
}
