#pragma once

#include "acppnode/common/asio_types.hpp"

#include <array>
#include <charconv>
#include <cstring>
#include <optional>
#include <string_view>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace acpp::iputil {

// Parse one complete IP literal, never an endpoint or a hostname. Numeric
// IPv6 scope IDs are data; resolving interface names is outside this boundary.
// Fixed storage also prevents C-string APIs from truncating embedded NULs.
[[nodiscard]] inline std::optional<net::ip::address> ParseLiteral(
    std::string_view text) noexcept {
    if (text.empty() || text.find('\0') != std::string_view::npos) return std::nullopt;

    auto parse_v4 = [](std::string_view value) -> std::optional<net::ip::address_v4::bytes_type> {
        net::ip::address_v4::bytes_type bytes{};
        size_t start = 0;
        for (size_t i = 0; i < bytes.size(); ++i) {
            const auto end = value.find('.', start);
            const auto part = value.substr(start, end == std::string_view::npos ? end : end - start);
            if (part.empty() || part.size() > 3 || (part.size() > 1 && part.front() == '0'))
                return std::nullopt;
            unsigned int octet = 0;
            const auto [last, error] = std::from_chars(part.data(), part.data() + part.size(), octet);
            if (error != std::errc{} || last != part.data() + part.size() || octet > 255)
                return std::nullopt;
            bytes[i] = static_cast<unsigned char>(octet);
            if (i + 1 == bytes.size()) {
                if (end != std::string_view::npos) return std::nullopt;
            } else {
                if (end == std::string_view::npos) return std::nullopt;
                start = end + 1;
            }
        }
        return bytes;
    };

    if (text.find(':') == std::string_view::npos) {
        const auto bytes = parse_v4(text);
        if (!bytes) return std::nullopt;
        return net::ip::address_v4(*bytes);
    }

    uint32_t scope = 0;
    if (const auto separator = text.find('%'); separator != std::string_view::npos) {
        const auto suffix = text.substr(separator + 1);
        if (suffix.empty()) return std::nullopt;
        const auto [end, error] = std::from_chars(suffix.data(), suffix.data() + suffix.size(), scope);
        if (error != std::errc{} || end != suffix.data() + suffix.size()) return std::nullopt;
        text = text.substr(0, separator);
    }
    if (text.empty() || text.size() >= INET6_ADDRSTRLEN) return std::nullopt;
    for (unsigned char c : text) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F') || c == ':' || c == '.')) return std::nullopt;
    }
    if (text.find('.') != std::string_view::npos &&
        !parse_v4(text.substr(text.rfind(':') + 1))) return std::nullopt;
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    std::memcpy(buffer.data(), text.data(), text.size());
    net::ip::address_v6::bytes_type bytes{};
    if (::inet_pton(AF_INET6, buffer.data(), bytes.data()) != 1) return std::nullopt;
    return net::ip::address_v6(bytes, scope);
}

}  // namespace acpp::iputil
