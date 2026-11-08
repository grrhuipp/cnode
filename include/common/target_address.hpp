#pragma once

#include "common/allocator.hpp"
#include "common/domain_name.hpp"
#include "common/ip_utils.hpp"
#include "common/ip_address.hpp"
#include "common/network.hpp"

#include <charconv>
#include <format>
#include <optional>
#include <string>
#include <string_view>


// ============================================================================
// 目标地址
// ============================================================================
struct TargetAddress {
    AddressType type = AddressType::Invalid;
    memory::ThreadLocalString host;  // 域名；IP 目标只保留 resolved_addr
    uint16_t port = 0;

    // DNS 解析后的地址
    std::optional<net::ip::address> resolved_addr;

    TargetAddress() = default;

    TargetAddress(std::string_view h, uint16_t p)
        : port(p) {
        InitFromHost(h);
    }

    TargetAddress(const net::ip::address& addr, uint16_t p)
        : port(p) {
        const net::ip::address normalized = iputil::NormalizeAddress(addr);
        if (normalized.is_v4()) {
            type = AddressType::IPv4;
            resolved_addr = normalized;
        } else if (normalized.is_v6()) {
            type = AddressType::IPv6;
            resolved_addr = normalized;
        }
    }

    bool IsValid() const noexcept {
        if (port == 0) return false;
        switch (type) {
            case AddressType::Domain:
                return domain::IsValidDnsHostname(
                    host, domain::TrailingDotPolicy::Allow);
            case AddressType::IPv4:
                return host.empty() && resolved_addr && resolved_addr->is_v4();
            case AddressType::IPv6:
                return host.empty() && resolved_addr && resolved_addr->is_v6();
            case AddressType::Invalid:
                return false;
        }
        return false;
    }

    [[nodiscard]] bool SameEndpoint(const TargetAddress& other) const noexcept {
        if (!IsValid() || !other.IsValid() || port != other.port) {
            return false;
        }
        if (IsDomain() || other.IsDomain()) {
            return IsDomain() && other.IsDomain() &&
                   domain::DnsHostnamesEqual(host, other.host);
        }
        return iputil::NormalizeAddress(*resolved_addr) ==
               iputil::NormalizeAddress(*other.resolved_addr);
    }

    bool IsDomain() const noexcept {
        return type == AddressType::Domain;
    }

    bool IsIP() const noexcept {
        return type == AddressType::IPv4 || type == AddressType::IPv6;
    }

    bool IsIPv4() const noexcept {
        return type == AddressType::IPv4;
    }

    bool IsIPv6() const noexcept {
        return type == AddressType::IPv6;
    }
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

    void InitFromHost(std::string_view h) {
        type = AddressType::Invalid;
        resolved_addr.reset();
        host.clear();
        if (h.empty()) {
            return;
        }
        if (auto literal = iputil::ParseLiteral(h)) {
            const auto addr = iputil::NormalizeAddress(*literal);
            if (addr.is_v4()) {
                type = AddressType::IPv4;
                resolved_addr = addr;
            } else if (addr.is_v6()) {
                type = AddressType::IPv6;
                resolved_addr = addr;
            }
            return;
        }
        if (domain::IsValidDnsHostname(
                h, domain::TrailingDotPolicy::Allow)) {
            host.assign(h);
            domain::NormalizeDnsHostnameInPlace(host);
            type = AddressType::Domain;
        }
    }
};

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

    TargetAddress target(host, port);
    // Brackets must enclose exactly an IPv6 literal. ParseLiteral takes the
    // IPv6 path iff the text contains ':', and v4-mapped literals normalize to
    // IPv4, so the bracket check uses the source text rather than the type.
    if (addr.front() == '[' &&
        (!target.IsIP() || host.find(':') == std::string_view::npos)) {
        return std::nullopt;
    }
    if (!target.IsValid()) {
        return std::nullopt;
    }
    return target;
}


inline constexpr size_t kMaxForwardedEmailLength = 96;
inline constexpr size_t kMaxForwardedTagLength = 96;
// 链式代理透传的最初入站身份与真实客户端 IP 只读视图。
struct ForwardedMetadataView {
    int64_t user_id = 0;
    std::string_view user_email{};
    std::optional<net::ip::address> client_ip{};
    std::string_view inbound_tag{};

    [[nodiscard]] bool Empty() const noexcept {
        return user_id <= 0 && user_email.empty() &&
               (!client_ip || client_ip->is_unspecified()) &&
               inbound_tag.empty();
    }
};

// 链式代理透传的最初入站身份与真实客户端 IP 拥有型存储。
struct ForwardedMetadata {
    int64_t user_id = 0;
    memory::ThreadLocalString user_email;
    std::optional<net::ip::address> client_ip;
    memory::ThreadLocalString inbound_tag;

    [[nodiscard]] bool Empty() const noexcept {
        return user_id <= 0 && user_email.empty() &&
               (!client_ip || client_ip->is_unspecified()) &&
               inbound_tag.empty();
    }

    [[nodiscard]] ForwardedMetadataView View() const& noexcept {
        return ForwardedMetadataView{
            .user_id = user_id,
            .user_email = user_email,
            .client_ip = client_ip,
            .inbound_tag = inbound_tag,
        };
    }
    ForwardedMetadataView View() const&& = delete;
};

template <>
struct std::formatter<::TargetAddress> {
    constexpr auto parse(std::format_parse_context& ctx) {
        return ctx.begin();
    }

    template <class FormatContext>
    auto format(const ::TargetAddress& target, FormatContext& ctx) const {
        std::optional<::iputil::AddressText> ip_storage;
        std::optional<::net::ip::address> normalized_resolved;
        std::string_view host(target.host.data(), target.host.size());
        const bool use_resolved = host.empty() && target.resolved_addr.has_value();
        if (use_resolved) {
            normalized_resolved = ::iputil::NormalizeAddress(*target.resolved_addr);
            ip_storage.emplace(*normalized_resolved);
            host = ip_storage->View();
        }
        if (host.empty()) {
            host = "unknown";
        }

        const bool needs_brackets = use_resolved
            ? normalized_resolved->is_v6()
            : host.find(':') != std::string_view::npos;
        if (needs_brackets) {
            return std::format_to(ctx.out(), "[{}]:{}", host, target.port);
        }
        return std::format_to(ctx.out(), "{}:{}", host, target.port);
    }
};
