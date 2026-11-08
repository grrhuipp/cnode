#pragma once

#include "common/asio_types.hpp"

#include <asio/ip/address.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>

#include <arpa/inet.h>
#include <net/if.h>
namespace iputil {

inline net::ip::address NormalizeAddress(
    const net::ip::address& addr) noexcept {
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

// Value-owned text; views are valid only while this stack buffer is alive.
// Numeric formatting never resolves DNS or allocates an owning string.
class AddressText {
public:

    AddressText(const AddressText&) = delete;
    AddressText& operator=(const AddressText&) = delete;
    explicit AddressText(const net::ip::address& address) {
        const bool ipv6 = address.is_v6();
        in6_addr native_v6{};
        in_addr native_v4{};
        if (ipv6) {
            const auto bytes = address.to_v6().to_bytes();
            std::memcpy(&native_v6, bytes.data(), bytes.size());
        } else {
            const auto bytes = address.to_v4().to_bytes();
            std::memcpy(&native_v4, bytes.data(), bytes.size());
        }
        const auto* result = ipv6
            ? ::inet_ntop(AF_INET6, &native_v6, text_.data(), text_.size())
            : ::inet_ntop(AF_INET, &native_v4, text_.data(), text_.size());
        if (!result) {
            throw std::system_error(errno, std::system_category(), "inet_ntop");
        }
        size_ = std::char_traits<char>::length(text_.data());
        if (!ipv6) return;
        const auto v6 = address.to_v6();
        if (v6.scope_id() == 0) return;
        text_[size_++] = '%';
        if ((v6.is_link_local() || v6.is_multicast_link_local()) &&
            v6.scope_id() <= std::numeric_limits<unsigned>::max() &&
            ::if_indextoname(static_cast<unsigned>(v6.scope_id()), text_.data() + size_)) {
            size_ += std::char_traits<char>::length(text_.data() + size_);
            return;
        }
        const auto [end, error] = std::to_chars(
            text_.data() + size_, text_.data() + text_.size(), v6.scope_id());
        if (error != std::errc{}) throw std::system_error(std::make_error_code(error));
        size_ = static_cast<size_t>(end - text_.data());
    }

    [[nodiscard]] std::string_view View() const noexcept { return {text_.data(), size_}; }

private:
    static constexpr size_t kScopeBytes = std::max<size_t>(IF_NAMESIZE, 20);
    std::array<char, INET6_ADDRSTRLEN + 1 + kScopeBytes> text_;
    size_t size_ = 0;
};

inline std::string NormalizeAddressString(
    const net::ip::address& addr) {
    return std::string(AddressText(NormalizeAddress(addr)).View());
}

inline bool NeedsIpv6Brackets(std::string_view host) noexcept {
    return host.find(':') != std::string_view::npos &&
           !(host.size() >= 2 && host.front() == '[' && host.back() == ']');
}

template<class Allocator>
inline void FormatHttpHostHeaderInto(
    std::basic_string<char, std::char_traits<char>, Allocator>& out,
    std::string_view host,
    uint16_t port,
    bool use_ssl) {
    const bool bracket_ipv6 = NeedsIpv6Brackets(host);
    const uint16_t default_port = use_ssl ? 443 : 80;
    const bool include_port = port != 0 && port != default_port;
    char port_buf[5];
    char* port_end = port_buf;
    if (include_port) {
        auto [ptr, ec] = std::to_chars(port_buf, port_buf + sizeof(port_buf), port);
        (void)ec;
        port_end = ptr;
    }

    out.clear();
    out.reserve(host.size() + (bracket_ipv6 ? 2 : 0) +
                (include_port ? 1 + static_cast<size_t>(port_end - port_buf) : 0));
    if (bracket_ipv6) {
        out.push_back('[');
    }
    out.append(host);
    if (bracket_ipv6) {
        out.push_back(']');
    }
    if (include_port) {
        out.push_back(':');
        out.append(port_buf, port_end);
    }
}

inline std::string FormatHttpHostHeader(
    std::string_view host,
    uint16_t port,
    bool use_ssl) {
    std::string header;
    FormatHttpHostHeaderInto(header, host, port, use_ssl);
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

}  // namespace iputil
