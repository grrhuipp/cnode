#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/ip_utils.hpp"

namespace acpp {

// ============================================================================
// 目标地址
// ============================================================================
struct TargetAddress {
    AddressType type = AddressType::IPv4;
    std::string host;                              // IP 或域名
    uint16_t port = 0;
    
    // DNS 解析后的地址
    std::optional<net::ip::address> resolved_addr;
    
    // 构造函数
    TargetAddress() = default;
    
    TargetAddress(const std::string& h, uint16_t p)
        : host(h), port(p) {
        DetermineType();
    }
    
    TargetAddress(const net::ip::address& addr, uint16_t p)
        : port(p) {
        if (addr.is_v4()) {
            type = AddressType::IPv4;
            resolved_addr = addr;
            host = addr.to_string();
        }
    }
    
    // 判断是否有效
    bool IsValid() const {
        return !host.empty() && port > 0;
    }
    
    // 判断是否为域名
    bool IsDomain() const {
        return type == AddressType::Domain;
    }
    
    // 判断是否为 IP
    bool IsIP() const {
        return type == AddressType::IPv4;
    }
    
    // 判断是否已解析
    bool IsResolved() const {
        return resolved_addr.has_value();
    }
    
    // 获取用于连接的地址（优先使用解析后的地址）
    std::string GetConnectHost() const {
        if (resolved_addr) {
            return resolved_addr->to_string();
        }
        return host;
    }
    
    // 转换为字符串
    std::string ToString() const {
        return iputil::FormatEndpointForLog(host, port);
    }
    
    // 转换为带解析 IP 的字符串
    std::string ToStringWithResolved() const {
        if (resolved_addr && IsDomain()) {
            return iputil::FormatEndpointForLog(
                host + "(" + resolved_addr->to_string() + ")",
                port);
        }
        return ToString();
    }
    
    // 从字符串解析
    [[nodiscard]]
    static std::optional<TargetAddress> Parse(const std::string& addr);
    
private:
    void DetermineType() {
        boost::system::error_code ec;
        auto addr = net::ip::make_address(host, ec);
        if (!ec) {
            if (addr.is_v4()) {
                type = AddressType::IPv4;
                resolved_addr = addr;
            } else {
                type = AddressType::Domain;
                host.clear();
                resolved_addr.reset();
                return;
            }
        } else {
            type = AddressType::Domain;
        }
    }
};

// 从字符串解析地址
inline std::optional<TargetAddress> TargetAddress::Parse(const std::string& addr) {
    if (addr.empty()) {
        return std::nullopt;
    }
    
    std::string host;
    uint16_t port = 0;
    
    if (addr[0] == '[') {
        return std::nullopt;
    }

    auto colon = addr.rfind(':');
    if (colon == std::string::npos) {
        return std::nullopt;
    }
    host = addr.substr(0, colon);
    try {
        port = static_cast<uint16_t>(std::stoi(addr.substr(colon + 1)));
    } catch (...) {
        return std::nullopt;
    }
    
    if (host.empty() || port == 0) {
        return std::nullopt;
    }
    
    return TargetAddress(host, port);
}

}  // namespace acpp
