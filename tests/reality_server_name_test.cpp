#include "acppnode/transport/internet/reality_server_name.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    using acpp::transport::internet::IsRealityServerNameAllowed;

    const std::vector<std::string> names{"Example.COM", ""};
    if (!Require(IsRealityServerNameAllowed(names, "example.com"),
                 "DNS server names must compare case-insensitively")) return 1;
    if (!Require(IsRealityServerNameAllowed(names, ""),
                 "an empty configured name must allow missing SNI")) return 2;
    if (!Require(!IsRealityServerNameAllowed(names, "other.example"),
                 "an unconfigured server name must be rejected")) return 3;
    if (!Require(!IsRealityServerNameAllowed(names, "sub.example.com"),
                 "server name matching must remain exact")) return 4;

    const std::vector<std::string> named_only{"example.com"};
    if (!Require(!IsRealityServerNameAllowed(named_only, ""),
                 "missing SNI must require an explicit empty allow-list entry")) {
        return 5;
    }
    return 0;
}
