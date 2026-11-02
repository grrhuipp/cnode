#pragma once

#include "acppnode/common/target_address.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string_view>

namespace acpp::proxy {

struct ParsedSocks5Address {
    TargetAddress target;
    size_t consumed = 0;
};

[[nodiscard]] inline size_t Socks5AddressBodySize(const TargetAddress& addr) noexcept {
    if (addr.IsDomain()) {
        return addr.host.size() <= 255 ? (1 + 1 + addr.host.size()) : 0;
    }
    if (addr.resolved_addr) {
        if (addr.resolved_addr->is_v4()) return 1 + 4;
        if (addr.resolved_addr->is_v6()) return 1 + 16;
    }
    return 0;
}

[[nodiscard]] inline size_t Socks5AddressEncodedSize(const TargetAddress& addr) noexcept {
    const size_t body = Socks5AddressBodySize(addr);
    return body == 0 ? 0 : body + 2;
}

[[nodiscard]] inline size_t EncodeSocks5AddressBodyTo(
    const TargetAddress& addr,
    uint8_t* output,
    size_t output_size) noexcept {
    const size_t needed = Socks5AddressBodySize(addr);
    if (needed == 0 || !output || needed > output_size) {
        return 0;
    }
    size_t pos = 0;
    if (addr.IsDomain()) {
        output[pos++] = 0x03;
        output[pos++] = static_cast<uint8_t>(addr.host.size());
        if (!addr.host.empty()) {
            std::memcpy(output + pos, addr.host.data(), addr.host.size());
            pos += addr.host.size();
        }
    } else if (addr.resolved_addr && addr.resolved_addr->is_v4()) {
        output[pos++] = 0x01;
        const auto bytes = addr.resolved_addr->to_v4().to_bytes();
        std::memcpy(output + pos, bytes.data(), bytes.size());
        pos += bytes.size();
    } else if (addr.resolved_addr && addr.resolved_addr->is_v6()) {
        output[pos++] = 0x04;
        const auto bytes = addr.resolved_addr->to_v6().to_bytes();
        std::memcpy(output + pos, bytes.data(), bytes.size());
        pos += bytes.size();
    } else {
        return 0;
    }
    return pos;
}

[[nodiscard]] inline size_t EncodeSocks5AddressTo(
    const TargetAddress& addr,
    uint8_t* output,
    size_t output_size) noexcept {
    if (output_size < 2) {
        return 0;
    }
    const size_t body = EncodeSocks5AddressBodyTo(addr, output, output_size - 2);
    if (body == 0) {
        return 0;
    }
    output[body] = static_cast<uint8_t>(addr.port >> 8);
    output[body + 1] = static_cast<uint8_t>(addr.port & 0xFF);
    return body + 2;
}

[[nodiscard]] inline std::optional<ParsedSocks5Address> ParseSocks5Address(
    const uint8_t* data,
    size_t len,
    size_t max_domain_len = 255,
    bool require_non_empty_domain = false) {
    if (!data || len < 1) return std::nullopt;

    size_t idx = 0;
    const uint8_t atyp = data[idx++];
    if (atyp == 0x01) {
        if (idx + 4 + 2 > len) return std::nullopt;
        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), data + idx, bytes.size());
        idx += 4;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        return ParsedSocks5Address{
            .target = TargetAddress(net::ip::make_address_v4(bytes), port),
            .consumed = idx,
        };
    }
    if (atyp == 0x03) {
        if (idx + 1 > len) return std::nullopt;
        const size_t name_len = data[idx++];
        if ((require_non_empty_domain && name_len == 0) ||
            name_len > max_domain_len ||
            idx + name_len + 2 > len) {
            return std::nullopt;
        }
        const std::string_view domain(reinterpret_cast<const char*>(data + idx), name_len);
        idx += name_len;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        return ParsedSocks5Address{
            .target = TargetAddress(domain, port),
            .consumed = idx,
        };
    }
    if (atyp == 0x04) {
        if (idx + 16 + 2 > len) return std::nullopt;
        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), data + idx, bytes.size());
        idx += bytes.size();
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        return ParsedSocks5Address{
            .target = TargetAddress(net::ip::make_address_v6(bytes), port),
            .consumed = idx,
        };
    }
    return std::nullopt;
}

}  // namespace acpp::proxy
