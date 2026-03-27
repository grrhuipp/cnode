#pragma once

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

#include <string>
#include <string_view>

namespace acpp::iputil {

inline bool IsWildcardBindAddress(std::string_view value) noexcept {
    return value.empty() || value == "0.0.0.0";
}

inline boost::asio::ip::address NormalizeAddress(
    const boost::asio::ip::address& addr) {
    if (addr.is_v4()) {
        return addr;
    }
    return boost::asio::ip::make_address("0.0.0.0");
}

inline std::string NormalizeAddressString(
    const boost::asio::ip::address& addr) {
    return NormalizeAddress(addr).to_string();
}

inline bool IsIpLiteral(std::string_view host) {
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(std::string(host), ec);
    return !ec && addr.is_v4();
}

inline std::string FormatHttpHostHeader(
    std::string_view host,
    uint16_t port,
    bool use_ssl) {
    std::string header(host);
    const uint16_t default_port = use_ssl ? 443 : 80;
    if (port != 0 && port != default_port) {
        header += ":" + std::to_string(port);
    }
    return header;
}

inline std::string FormatEndpointForLog(
    std::string_view host,
    uint16_t port) {
    return std::string(host) + ":" + std::to_string(port);
}

}  // namespace acpp::iputil
