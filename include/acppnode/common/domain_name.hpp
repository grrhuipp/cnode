#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace acpp::domain {

enum class TrailingDotPolicy {
    Forbid,
    Allow,
};

[[nodiscard]] constexpr char ToLowerAscii(unsigned char ch) noexcept {
    return ch >= 'A' && ch <= 'Z'
        ? static_cast<char>(ch + ('a' - 'A'))
        : static_cast<char>(ch);
}

[[nodiscard]] inline std::string_view WithoutTrailingRootDot(
    std::string_view hostname) noexcept {
    if (!hostname.empty() && hostname.back() == '.') {
        hostname.remove_suffix(1);
    }
    return hostname;
}

[[nodiscard]] inline bool DnsHostnamesEqual(
    std::string_view lhs,
    std::string_view rhs) noexcept {
    lhs = WithoutTrailingRootDot(lhs);
    rhs = WithoutTrailingRootDot(rhs);
    if (lhs.size() != rhs.size()) return false;
    for (std::size_t i = 0; i < lhs.size(); ++i) {
        if (ToLowerAscii(static_cast<unsigned char>(lhs[i])) !=
            ToLowerAscii(static_cast<unsigned char>(rhs[i]))) {
            return false;
        }
    }
    return true;
}

inline void NormalizeDnsHostnameInPlace(std::string& hostname) noexcept {
    if (!hostname.empty() && hostname.back() == '.') {
        hostname.pop_back();
    }
    for (char& ch : hostname) {
        ch = ToLowerAscii(static_cast<unsigned char>(ch));
    }
}

[[nodiscard]] inline std::string CanonicalDnsHostname(
    std::string_view hostname) {
    std::string canonical(hostname);
    NormalizeDnsHostnameInPlace(canonical);
    return canonical;
}

[[nodiscard]] inline bool IsValidDnsHostname(
    std::string_view hostname,
    TrailingDotPolicy trailing_dot_policy) noexcept {
    if (hostname.empty()) return false;

    if (hostname.back() == '.') {
        if (trailing_dot_policy == TrailingDotPolicy::Forbid) return false;
        hostname.remove_suffix(1);
    }
    if (hostname.empty() || hostname.size() > 253) return false;

    std::size_t label_size = 0;
    bool label_ends_with_hyphen = false;
    for (const unsigned char ch : hostname) {
        if (ch == '.') {
            if (label_size == 0 || label_ends_with_hyphen) return false;
            label_size = 0;
            label_ends_with_hyphen = false;
            continue;
        }

        const bool alphanumeric =
            (ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9');
        if (!alphanumeric && ch != '-') return false;
        if (label_size == 0 && ch == '-') return false;
        if (++label_size > 63) return false;
        label_ends_with_hyphen = ch == '-';
    }
    return label_size != 0 && !label_ends_with_hyphen;
}

[[nodiscard]] inline bool IsIpv4AddressLiteral(
    std::string_view hostname) noexcept {
    std::size_t position = 0;
    for (unsigned int part = 0; part < 4; ++part) {
        const std::size_t end = hostname.find('.', position);
        const std::string_view octet = end == std::string_view::npos
            ? hostname.substr(position)
            : hostname.substr(position, end - position);
        if (octet.empty() || octet.size() > 3 ||
            (octet.size() > 1 && octet.front() == '0')) {
            return false;
        }

        unsigned int value = 0;
        for (const unsigned char ch : octet) {
            if (ch < '0' || ch > '9') return false;
            value = value * 10 + static_cast<unsigned int>(ch - '0');
        }
        if (value > 255) return false;

        if (part == 3) return end == std::string_view::npos;
        if (end == std::string_view::npos) return false;
        position = end + 1;
    }
    return false;
}

}  // namespace acpp::domain
