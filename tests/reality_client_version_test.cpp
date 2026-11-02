#include "acppnode/transport/internet/reality_client_version.hpp"

#include <array>
#include <cstdio>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    using acpp::transport::internet::ParseRealityClientVersion;
    using acpp::transport::internet::RealityClientVersion;
    using acpp::transport::internet::RealityClientVersionValue;

    const auto unset = ParseRealityClientVersion("");
    if (!Require(unset && !*unset,
                 "empty version policy must remain unset")) return 1;

    const auto semantic = ParseRealityClientVersion("1.8.0");
    const RealityClientVersion expected_semantic{1, 8, 0, 0};
    if (!Require(semantic && *semantic == expected_semantic,
                 "three-part REALITY version must parse")) return 2;

    const auto short_version = ParseRealityClientVersion("1.8");
    const RealityClientVersion expected_short{1, 8, 0, 0};
    if (!Require(short_version && *short_version == expected_short,
                 "two-part REALITY version must zero-fill")) return 3;

    if (!Require(RealityClientVersionValue(expected_semantic) == 0x01080000u,
                 "REALITY version ordering value must preserve components")) {
        return 4;
    }

    for (const char* invalid : {"1.8.0.1", "1..0", "1.256.0", "v1.8.0"}) {
        if (!Require(!ParseRealityClientVersion(invalid),
                     "invalid REALITY version must be rejected")) return 5;
    }
    return 0;
}
