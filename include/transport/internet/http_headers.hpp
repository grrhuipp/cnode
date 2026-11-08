#pragma once

#include "common/binary_text_codec.hpp"

#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace transport::internet {

using HttpHeaders = std::unordered_map<std::string, std::string>;

[[nodiscard]] constexpr bool EqualsAsciiCI(
    std::string_view lhs, std::string_view rhs) noexcept {
    constexpr auto lower = [](char ch) noexcept {
        return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch - 'A' + 'a') : ch;
    };
    if (lhs.size() != rhs.size()) return false;
    for (size_t i = 0; i < lhs.size(); ++i) {
        if (lower(lhs[i]) != lower(rhs[i])) return false;
    }
    return true;
}

[[nodiscard]] constexpr std::string_view TrimHttpOws(
    std::string_view value) noexcept {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.remove_prefix(1);
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
        value.remove_suffix(1);
    }
    return value;
}

// Strips SP/HTAB and stray CR/LF around a header value or token.
[[nodiscard]] constexpr std::string_view TrimAscii(std::string_view value) noexcept {
    constexpr auto is_space = [](char ch) noexcept {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
    };
    while (!value.empty() && is_space(value.front())) value.remove_prefix(1);
    while (!value.empty() && is_space(value.back())) value.remove_suffix(1);
    return value;
}

// Configured names are normalized at load time, but derived headers may add
// mixed-case names; lookup stays case-insensitive. Returns null when absent.
[[nodiscard]] inline const std::string* FindHttpHeader(
    const HttpHeaders& headers, std::string_view name) noexcept {
    for (const auto& [key, value] : headers) {
        if (EqualsAsciiCI(key, name)) return &value;
    }
    return nullptr;
}

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

// RFC 9112 7.1/7.1.1 and RFC 9110 5.6.2-5.6.4. The caller removes
// exactly one CRLF and bounds the line length. Unknown extensions are ignored
// semantically, not mistaken for arbitrary bytes. BWS is forbidden to send,
// but recipients must parse it at the grammar's BWS positions.
[[nodiscard]] inline std::optional<size_t> ParseHttpChunkSize(
    std::string_view line) noexcept {
    size_t pos = 0;
    size_t size = 0;
    while (pos < line.size()) {
        const int digit = HexDigitValue(line[pos]);
        if (digit < 0) break;
        if (size > (std::numeric_limits<size_t>::max() -
                    static_cast<size_t>(digit)) / 16) return std::nullopt;
        size = size * 16 + static_cast<size_t>(digit);
        ++pos;
    }
    if (pos == 0) return std::nullopt;
    const auto skip_bws = [&line](size_t& at) {
        while (at < line.size() && (line[at] == ' ' || line[at] == '\t')) ++at;
    };
    const auto read_token = [&line](size_t& at) {
        const size_t start = at;
        while (at < line.size() && IsValidHttpHeaderName(line.substr(at, 1))) ++at;
        return at != start;
    };
    while (pos < line.size()) {
        skip_bws(pos);
        if (pos == line.size() || line[pos++] != ';') return std::nullopt;
        skip_bws(pos);
        if (!read_token(pos)) return std::nullopt;
        size_t equals = pos;
        skip_bws(equals);
        if (equals == line.size() || line[equals] != '=') continue;
        pos = equals + 1;
        skip_bws(pos);
        if (pos == line.size()) return std::nullopt;
        if (line[pos] != '"') {
            if (!read_token(pos)) return std::nullopt;
            continue;
        }
        ++pos;
        bool closed = false;
        while (pos < line.size()) {
            const auto ch = static_cast<unsigned char>(line[pos++]);
            if (ch == '"') {
                closed = true;
                break;
            }
            if (ch == '\\') {
                if (pos == line.size()) return std::nullopt;
                const auto escaped = static_cast<unsigned char>(line[pos++]);
                if (escaped != '\t' && escaped != ' ' &&
                    !(escaped >= 0x21 && escaped <= 0x7e) && escaped < 0x80)
                    return std::nullopt;
            } else if (ch != '\t' && ch != ' ' && ch != 0x21 &&
                       !(ch >= 0x23 && ch <= 0x5b) &&
                       !(ch >= 0x5d && ch <= 0x7e) && ch < 0x80) {
                return std::nullopt;
            }
        }
        if (!closed) return std::nullopt;
    }
    return size;
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

}  // namespace transport::internet
