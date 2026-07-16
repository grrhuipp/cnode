#include "acppnode/common/target_address.hpp"

#include <cstdio>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    const acpp::TargetAddress empty;
    if (!Require(!empty.IsValid() && !empty.IsIP() && !empty.IsDomain(),
                 "a default target must have an explicit invalid type")) return 1;

    const acpp::TargetAddress injected("bad.example\r\nforged-log", 443);
    if (!Require(!injected.IsValid() && injected.host.empty(),
                 "an invalid target must not retain log-injectable bytes")) return 2;

    const acpp::TargetAddress empty_label("bad..example", 443);
    if (!Require(!empty_label.IsValid(),
                 "a malformed DNS hostname must not become a valid target")) return 3;

    if (!Require(!acpp::TargetAddress::Parse("bad..example:443"),
                 "TargetAddress::Parse must reject malformed hostnames")) return 4;

    const acpp::TargetAddress domain("example.com.", 443);
    if (!Require(domain.IsValid() && domain.IsDomain(),
                 "an absolute DNS hostname must remain a valid target")) return 5;

    const auto ipv6 = acpp::TargetAddress::Parse("[2001:db8::1]:443");
    if (!Require(ipv6 && ipv6->IsValid() && ipv6->IsIPv6(),
                 "a bracketed IPv6 endpoint must remain valid")) return 6;

    const acpp::TargetAddress mapped("::ffff:192.0.2.1", 443);
    if (!Require(mapped.IsValid() && mapped.IsIPv4() &&
                     mapped.resolved_addr->to_string() == "192.0.2.1",
                 "an IPv4-mapped IPv6 target must be canonicalized")) return 7;
    return 0;
}
