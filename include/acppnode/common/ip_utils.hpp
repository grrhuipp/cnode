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
    if (addr.is_v6()) {
        const auto bytes = addr.to_v6().to_bytes();
        const bool is_v4_mapped =
            bytes[0] == 0 && bytes[1] == 0 &&
            bytes[2] == 0 && bytes[3] == 0 &&
            bytes[4] == 0 && bytes[5] == 0 &&
            bytes[6] == 0 && bytes[7] == 0 &&
            bytes[8] == 0 && bytes[9] == 0 &&
            bytes[10] == 0xff && bytes[11] == 0xff;
        if (is_v4_mapped) {
            net::ip::address_v4::bytes_type v4_bytes{
                bytes[12], bytes[13], bytes[14], bytes[15]};
            return net::ip::make_address_v4(v4_bytes);
        }
    }
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

// 把 "host:port" 写入 out（先 clear，复用其容量）。供需要按连接复用 scratch
// 的热路径调用，避免每次都分配新串。
inline void FormatEndpointForLogInto(
    std::string& out,
    std::string_view host,
    uint16_t port) {
    const bool bracket_ipv6 = NeedsIpv6Brackets(host);
    char port_buf[5];
    auto [ptr, ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), port);
    (void)ec;

    out.clear();
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
}

inline std::string FormatEndpointForLog(
    std::string_view host,
    uint16_t port) {
    std::string out;
    FormatEndpointForLogInto(out, host, port);
    return out;
}

}  // namespace acpp::iputil
