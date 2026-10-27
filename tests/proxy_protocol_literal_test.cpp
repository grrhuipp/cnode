#include "acppnode/transport/internet/proxy_protocol.hpp"

#include <array>
#include <cstdio>
#include <string>
#include <string_view>

int main() {
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
        const auto result = acpp::ProxyProtocolParser::Parse(
            reinterpret_cast<const uint8_t*>(packet.data()), packet.size());
        if (result.success() != item.accepted || (item.accepted &&
                (!result.src_addr || result.src_port != 32100 || result.consumed != packet.size()))) {
            std::fprintf(stderr, "PROXY source literal acceptance or tuple mismatch\n");
            return 1;
        }
    }
    for (const uint8_t version : {uint8_t{1}, uint8_t{2}}) {
        for (const char* ip_text : {"192.0.2.10", "2001:db8::10"}) {
            const auto addr = acpp::net::ip::make_address(ip_text);
            const acpp::tcp::endpoint src(addr, 45678);
            const acpp::tcp::endpoint dst(addr, 443);
            std::array<uint8_t, 108> encoded{};
            const size_t n = acpp::ProxyProtocolParser::Encode(
                version, src, dst, encoded);
            const auto parsed = acpp::ProxyProtocolParser::Parse(
                encoded.data(), n);
            if (n == 0 || !parsed.success() || parsed.consumed != n ||
                !parsed.src_addr || *parsed.src_addr != addr ||
                parsed.src_port != 45678) {
                std::fprintf(stderr, "PROXY v%u encode/parse round-trip failed\n",
                             static_cast<unsigned>(version));
                return 2;
            }
        }
    }
    std::puts("PROXY v1/v2 source literal, family, and encode round-trip cases passed");
}
