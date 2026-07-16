#include "acppnode/infra/runtime_config_types.hpp"

#include <array>
#include <string_view>

namespace {

bool Rejects(std::string_view value) {
    return !acpp::RoutingIpNetwork::Parse(value).has_value();
}

}  // namespace

int main() {
    auto ipv4 = acpp::RoutingIpNetwork::Parse("192.0.2.129/24");
    if (!ipv4 || ipv4->IsV6() || ipv4->Prefix() != 24 ||
        ipv4->Network()[0] != 192 || ipv4->Network()[1] != 0 ||
        ipv4->Network()[2] != 2 || ipv4->Network()[3] != 0) {
        return 1;
    }

    auto bare_ipv4 = acpp::RoutingIpNetwork::Parse("198.51.100.7");
    if (!bare_ipv4 || bare_ipv4->IsV6() || bare_ipv4->Prefix() != 32 ||
        bare_ipv4->Network()[3] != 7) {
        return 2;
    }

    auto ipv6 = acpp::RoutingIpNetwork::Parse("2001:db8:abcd:1234::1/48");
    const std::array<uint8_t, 6> ipv6_prefix{0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd};
    if (!ipv6 || !ipv6->IsV6() || ipv6->Prefix() != 48) {
        return 3;
    }
    for (size_t i = 0; i < ipv6_prefix.size(); ++i) {
        if (ipv6->Network()[i] != ipv6_prefix[i]) return 4;
    }
    for (size_t i = ipv6_prefix.size(); i < ipv6->Network().size(); ++i) {
        if (ipv6->Network()[i] != 0) return 5;
    }

    auto bare_ipv6 = acpp::RoutingIpNetwork::Parse("2001:db8::1");
    if (!bare_ipv6 || !bare_ipv6->IsV6() || bare_ipv6->Prefix() != 128 ||
        bare_ipv6->Network()[15] != 1) {
        return 6;
    }

    constexpr std::array<std::string_view, 11> invalid{
        "", "not-an-ip", "192.0.2.1/", "192.0.2.1/24junk",
        "192.0.2.1/-1", "192.0.2.1/33", "192.0.2.1/24/1",
        "2001:db8::/", "2001:db8::/32junk", "2001:db8::/129",
        "2001:db8::/64/1",
    };
    for (const auto value : invalid) {
        if (!Rejects(value)) return 7;
    }

    return 0;
}
