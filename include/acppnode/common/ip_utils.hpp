#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/core/constants.hpp"

#include <asio/ip/address.hpp>

#include <charconv>
#include <string>
#include <string_view>

namespace acpp::iputil {

inline bool IsWildcardBindAddress(std::string_view value) noexcept {
    return value.empty() ||
           value == constants::network::kAnyIpv4 ||
           value == "::";
}

inline net::ip::address NormalizeAddress(
    const net::ip::address& addr) {
    return addr;
}

inline std::string NormalizeAddressString(
    const net::ip::address& addr) {
    return NormalizeAddress(addr).to_string();
}

inline bool IsIpLiteral(std::string_view host) {
    IoErrorCode ec;
    auto addr = net::ip::make_address(host, ec);
    return !ec && (addr.is_v4() || addr.is_v6());
}

inline bool NeedsIpv6Brackets(std::string_view host) noexcept {
    return host.find(':') != std::string_view::npos &&
           !(host.size() >= 2 && host.front() == '[' && host.back() == ']');
}

inline std::string FormatHostForEndpoint(std::string_view host) {
    if (NeedsIpv6Brackets(host)) {
        std::string out;
        out.reserve(host.size() + 2);
        out.push_back('[');
        out.append(host);
        out.push_back(']');
        return out;
    }
    return std::string(host);
}

inline std::string FormatHttpHostHeader(
    std::string_view host,
    uint16_t port,
    bool use_ssl) {
    std::string header = FormatHostForEndpoint(host);
    const uint16_t default_port = use_ssl ? 443 : 80;
    if (port != 0 && port != default_port) {
        header += ":" + std::to_string(port);
    }
    return header;
}

inline std::string FormatEndpointForLog(
    std::string_view host,
    uint16_t port) {
    const bool bracket_ipv6 = NeedsIpv6Brackets(host);
    char port_buf[5];
    auto [ptr, ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), port);
    (void)ec;

    std::string out;
    out.reserve(host.size() + (bracket_ipv6 ? 2 : 0) + 1 +
                static_cast<size_t>(ptr - port_buf));
    if (bracket_ipv6) {
        out.push_back('[');
    }
    out.append(host);
    if (bracket_ipv6) {
        out.push_back(']');
    }
    out.push_back(':');
    out.append(port_buf, ptr);
    return out;
}

}  // namespace acpp::iputil
