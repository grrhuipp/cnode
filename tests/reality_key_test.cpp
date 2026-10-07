#include "acppnode/transport/internet/reality_key.hpp"

#include <cstdio>
#include <string>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    using acpp::transport::internet::ParseRealityKey;
    using acpp::transport::internet::RealityKey;

    const std::string zero_key(43, 'A');
    const auto parsed = ParseRealityKey(zero_key);
    if (!Require(parsed && *parsed == RealityKey{},
                 "canonical 32-byte Base64URL key must decode")) return 1;

    std::string noncanonical = zero_key;
    noncanonical.back() = 'B';
    for (const std::string& invalid : {
             std::string(42, 'A'), std::string(44, 'A'),
             zero_key.substr(0, 42) + "=", noncanonical,
             zero_key.substr(0, 42) + "!"}) {
        if (!Require(!ParseRealityKey(invalid),
                     "invalid REALITY key must be rejected")) return 2;
    }
    return 0;
}
