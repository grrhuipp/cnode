#pragma once

#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/network.hpp"

#include <charconv>
#include <format>
#include <optional>
#include <string>
#include <string_view>

namespace acpp {

// ============================================================================
// 目标地址
// ============================================================================
struct TargetAddress {
    AddressType type = AddressType::IPv4;
    std::string host;                // 域名；IP 目标只保留 resolved_addr
    uint16_t port = 0;

    // DNS 解析后的地址
    std::optional<net::ip::address> resolved_addr;

    // 构造函数
    TargetAddress() = default;

    TargetAddress(std::string_view h, uint16_t p)
        : host(h), port(p) {
        DetermineType();
    }

    TargetAddress(const net::ip::address& addr, uint16_t p)
        : port(p) {
        if (addr.is_v4()) {
            type = AddressType::IPv4;
            resolved_addr = addr;
        } else if (addr.is_v6()) {
            type = AddressType::IPv6;
            resolved_addr = addr;
        }
    }

    // 判断是否有效
    bool IsValid() const {
        return port > 0 && (!host.empty() || resolved_addr.has_value());
    }

    // 判断是否为域名
    bool IsDomain() const {
        return type == AddressType::Domain;
    }

    // 判断是否为 IP
    bool IsIP() const {
        return type == AddressType::IPv4 || type == AddressType::IPv6;
    }

    bool IsIPv4() const {
        return type == AddressType::IPv4;
    }

    bool IsIPv6() const {
        return type == AddressType::IPv6;
    }

    // 判断是否已解析
    bool IsResolved() const {
        return resolved_addr.has_value();
    }

    // 转换为字符串
    std::string ToString() const {
        if (host.empty() && resolved_addr) {
            return iputil::FormatEndpointForLog(resolved_addr->to_string(), port);
        }
        return iputil::FormatEndpointForLog(std::string_view(host.data(), host.size()), port);
    }

    // 写入调用方提供的 out（复用其容量），语义与 ToString() 完全一致。
    // 用于按连接复用 scratch 的热路径，省去每次的 destination 串分配。
    void ToStringInto(std::string& out) const {
        if (host.empty() && resolved_addr) {
            iputil::FormatEndpointForLogInto(out, resolved_addr->to_string(), port);
            return;
        }
        iputil::FormatEndpointForLogInto(out, std::string_view(host.data(), host.size()), port);
    }

    // 从字符串解析
    [[nodiscard]]
    static std::optional<TargetAddress> Parse(std::string_view addr);

private:
    static bool ParsePort(std::string_view text, uint16_t& port) {
        if (text.empty()) {
            return false;
        }
        uint32_t value = 0;
        const char* first = text.data();
        const char* last = text.data() + text.size();
        auto [ptr, ec] = std::from_chars(first, last, value);
        if (ec != std::errc{} || ptr != last || value == 0 || value > 65535) {
            return false;
        }
        port = static_cast<uint16_t>(value);
        return true;
    }

    void DetermineType() {
        IoErrorCode ec;
        auto addr = net::ip::make_address(std::string_view(host.data(), host.size()), ec);
        if (!ec) {
            if (addr.is_v4()) {
                type = AddressType::IPv4;
                resolved_addr = addr;
                host.clear();
            } else if (addr.is_v6()) {
                type = AddressType::IPv6;
                resolved_addr = addr;
                host.clear();
            }
        } else {
            type = AddressType::Domain;
        }
    }
};

// 从字符串解析地址
inline std::optional<TargetAddress> TargetAddress::Parse(std::string_view addr) {
    if (addr.empty()) {
        return std::nullopt;
    }

    std::string_view host;
    uint16_t port = 0;

    if (addr.front() == '[') {
        const auto close = addr.find(']');
        if (close == std::string::npos ||
            close + 1 >= addr.size() ||
            addr[close + 1] != ':') {
            return std::nullopt;
        }
        host = addr.substr(1, close - 1);
        if (!ParsePort(addr.substr(close + 2), port)) {
            return std::nullopt;
        }
    } else {
        const auto colon = addr.rfind(':');
        if (colon == std::string::npos ||
            addr.find(':') != colon) {
            return std::nullopt;
        }
        host = addr.substr(0, colon);
        if (!ParsePort(addr.substr(colon + 1), port)) {
            return std::nullopt;
        }
    }

    if (host.empty() || port == 0) {
        return std::nullopt;
    }

    return TargetAddress(host, port);
}

}  // namespace acpp

template <>
struct std::formatter<acpp::TargetAddress> {
    constexpr auto parse(std::format_parse_context& ctx) {
        return ctx.begin();
    }

    template <class FormatContext>
    auto format(const acpp::TargetAddress& target, FormatContext& ctx) const {
        std::string ip_storage;
        std::string_view host(target.host.data(), target.host.size());
        const bool use_resolved = host.empty() && target.resolved_addr.has_value();
        if (use_resolved) {
            ip_storage = target.resolved_addr->to_string();
            host = ip_storage;
        }
        if (host.empty()) {
            host = "unknown";
        }

        const bool needs_brackets = use_resolved
            ? target.resolved_addr->is_v6()
            : host.find(':') != std::string_view::npos;
        if (needs_brackets) {
            return std::format_to(ctx.out(), "[{}]:{}", host, target.port);
        }
        return std::format_to(ctx.out(), "{}:{}", host, target.port);
    }
};
