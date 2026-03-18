#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

#include <string>
#include <string_view>

namespace acpp::iputil {

inline bool IsWildcardBindAddress(std::string_view value) noexcept {
    return value.empty() || value == "0.0.0.0" || value == "::";
}

inline boost::asio::ip::address NormalizeAddress(
    const boost::asio::ip::address& addr) {
    if (addr.is_v6()) {
        const auto v6 = addr.to_v6();
        if (v6.is_v4_mapped()) {
            return boost::asio::ip::make_address_v4(
                boost::asio::ip::v4_mapped, v6);
        }
    }
    return addr;
}

inline std::string NormalizeAddressString(
    const boost::asio::ip::address& addr) {
    return NormalizeAddress(addr).to_string();
}

inline bool IsDualStackWildcardAddress(
    const boost::asio::ip::address& addr) noexcept {
    return addr.is_v6() && addr.to_v6().is_unspecified();
}

inline bool IsIpLiteral(std::string_view host) {
    boost::system::error_code ec;
    boost::asio::ip::make_address(std::string(host), ec);
    return !ec;
}

inline std::string FormatHttpHostHeader(
    std::string_view host,
    uint16_t port,
    bool use_ssl) {
    std::string header(host);
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(header, ec);
    if (!ec && addr.is_v6()) {
        header = "[" + header + "]";
    }

    const uint16_t default_port = use_ssl ? 443 : 80;
    if (port != 0 && port != default_port) {
        header += ":" + std::to_string(port);
    }
    return header;
}

}  // namespace acpp::iputil
