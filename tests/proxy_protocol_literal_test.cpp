#include <gtest/gtest.h>

#include "transport/internet/proxy_protocol.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <string>
#include <string_view>
#include <utility>

namespace {

::ProxyProtocolResult Parse(std::span<const uint8_t> bytes) {
    return ::ParseProxyProtocolHeader(bytes);
}

::ProxyProtocolResult Parse(std::string_view text) {
    return Parse(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

// haproxy PROXY protocol spec §2.1: "UNKNOWN" carries no source, the receiver
// ignores the rest of the line, and a line without CRLF inside 107 bytes is invalid.
bool V1BoundaryCasesPass() {
    const auto unknown = Parse("PROXY UNKNOWN\r\n");
    if (!unknown.success() || unknown.src_addr || unknown.consumed != 15) return false;
    const auto unknown_tail = Parse("PROXY UNKNOWN ffff::1 ffff::2 1 2\r\npayload");
    if (!unknown_tail.success() || unknown_tail.src_addr || unknown_tail.consumed != 35) {
        return false;
    }
    const std::string no_crlf = "PROXY " + std::string(101, 'x');
    if (Parse(no_crlf).status != ::ProxyProtocolParseStatus::Invalid) return false;
    if (!Parse(std::string_view(no_crlf).substr(0, 106)).incomplete()) return false;
    // A CRLF that only ends past byte 107 is still too late.
    if (Parse(no_crlf + "\r\n").status != ::ProxyProtocolParseStatus::Invalid) return false;
    if (Parse("PROXY TCP4 192.0.2.1 GARBAGE 32100 443\r\n").status !=
        ::ProxyProtocolParseStatus::Invalid) return false;
    if (Parse("PROXY TCP4 192.0.2.1 198.51.100.1 32100 70000\r\n").status !=
        ::ProxyProtocolParseStatus::Invalid) return false;
    if (Parse("PROXY TCP4 192.0.2.1 198.51.100.1 32100 443 EXTRA\r\n").status !=
        ::ProxyProtocolParseStatus::Invalid) return false;
    return true;
}

std::array<uint8_t, 28> V2Header(uint8_t version_command, uint8_t family_transport) {
    std::array<uint8_t, 28> header{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51,
                                   0x55, 0x49, 0x54, 0x0A, version_command,
                                   family_transport, 0x00, 0x0C};
    // INET block: 192.0.2.1 -> 198.51.100.1, 32100 -> 443.
    constexpr std::array<uint8_t, 12> address{192, 0, 2, 1, 198, 51, 100, 1,
                                              0x7D, 0x64, 0x01, 0xBB};
    std::copy(address.begin(), address.end(), header.begin() + 16);
    return header;
}

// Spec §2.2: unknown versions and commands are rejected; PROXY rejects
// families above UNIX and transports above DGRAM, while LOCAL ignores the
// protocol block. Rejection does not wait for the declared address block.
bool V2BoundaryCasesPass() {
    using Status = ::ProxyProtocolParseStatus;
    for (const auto& [version_command, family_transport] : {
             std::pair<uint8_t, uint8_t>{0x11, 0x11}, {0x31, 0x11}, {0x22, 0x11},
             {0x2F, 0x11}, {0x21, 0x41}, {0x21, 0xF1}, {0x21, 0x13}, {0x21, 0x1F}}) {
        const auto header = V2Header(version_command, family_transport);
        if (Parse(header).status != Status::Invalid ||
            Parse(std::span(header).first(16)).status != Status::Invalid) {
            return false;
        }
    }
    // Oversized v2 length (> kProxyHeaderMaxBytes) must fail immediately on 16-byte peek.
    auto oversized = V2Header(0x21, 0x11);
    oversized[14] = 0x10;
    oversized[15] = 0x00;
    if (Parse(std::span(oversized).first(16)).status != Status::Invalid) return false;
    for (const uint8_t family_transport : {uint8_t{0x11}, uint8_t{0x41}, uint8_t{0x13}, uint8_t{0xFF}}) {
        const auto header = V2Header(0x20, family_transport);
        const auto local = Parse(header);
        if (!local.success() || local.src_addr || local.consumed != header.size() ||
            !Parse(std::span(header).first(16)).incomplete()) {
            return false;
        }
    }
    const auto proxied = Parse(V2Header(0x21, 0x11));
    return proxied.success() && proxied.src_addr &&
        *proxied.src_addr == ::net::ip::make_address("192.0.2.1") &&
        proxied.src_port == 32100 && proxied.consumed == 28;
}

}  // namespace

TEST(ProxyProtocolLiteral, Contract) {
    using namespace std::string_view_literals;
    struct Case { std::string_view family, host; bool accepted; };
    for (const auto item : {
             Case{"TCP4", "192.0.2.1", true}, Case{"TCP6", "2001:db8::1", true},
             Case{"TCP6", "::ffff:192.0.2.1", true},
             Case{"TCP4", "192.0.2.1:9", false}, Case{"TCP4", "192.0.2.1\0ignored"sv, false},
             Case{"TCP6", "[2001:db8::1]", false}, Case{"TCP6", "2001:db8::1\0ignored"sv, false},
             Case{"TCP4", "192.00.2.1", false}, Case{"TCP4", "::1", false},
             Case{"TCP6", "192.0.2.1", false}}) {
        const std::string packet = std::string("PROXY ") + std::string(item.family) + " " +
            std::string(item.host) + (item.family == "TCP4" ? " 198.51.100.1" : " 2001:db8::2") + " 32100 443\r\n";
        const auto result = ::ParseProxyProtocolHeader(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(packet.data()), packet.size()));
        if (result.success() != item.accepted || (item.accepted &&
                (!result.src_addr || result.src_port != 32100 || result.consumed != packet.size()))) {
            std::fprintf(stderr, "PROXY source literal acceptance or tuple mismatch\n");
            FAIL() << "PROXY source literal acceptance or tuple mismatch";
        }
    }
    for (const uint8_t version : {uint8_t{1}, uint8_t{2}}) {
        for (const char* ip_text : {"192.0.2.10", "2001:db8::10"}) {
            const auto addr = ::net::ip::make_address(ip_text);
            const ::tcp::endpoint src(addr, 45678);
            const ::tcp::endpoint dst(addr, 443);
            std::array<uint8_t, 108> encoded{};
            const size_t n = ::EncodeProxyProtocolHeader(
                version, src, dst, encoded);
            const auto parsed = ::ParseProxyProtocolHeader(
                std::span<const uint8_t>(encoded.data(), n));
            if (n == 0 || !parsed.success() || parsed.consumed != n ||
                !parsed.src_addr || *parsed.src_addr != addr ||
                parsed.src_port != 45678) {
                std::fprintf(stderr, "PROXY v%u encode/parse round-trip failed\n",
                             static_cast<unsigned>(version));
                FAIL() << "PROXY v%u encode/parse round-trip failed";
            }
        }
    }
    if (!V1BoundaryCasesPass()) {
        std::fprintf(stderr, "PROXY v1 UNKNOWN or 107-byte line limit mismatch\n");
        FAIL() << "PROXY v1 UNKNOWN or 107-byte line limit mismatch";
    }
    if (!V2BoundaryCasesPass()) {
        std::fprintf(stderr, "PROXY v2 version/command/family/transport validation mismatch\n");
        FAIL() << "PROXY v2 version/command/family/transport validation mismatch";
    }
    std::puts("PROXY v1/v2 source literal, family, boundary, and encode round-trip cases passed");
}
