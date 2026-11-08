#include <gtest/gtest.h>

#include "transport/internet/reality_client_version.hpp"

#include <array>
#include <cstdio>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

TEST(RealityClientVersion, Contract) {
    using ::transport::internet::ParseRealityClientVersion;
    using ::transport::internet::RealityClientVersion;
    using ::transport::internet::RealityClientVersionValue;

    const auto unset = ParseRealityClientVersion("");
    ASSERT_FALSE((!Require(unset && !*unset,
                 "empty version policy must remain unset")));

    const auto semantic = ParseRealityClientVersion("1.8.0");
    const RealityClientVersion expected_semantic{1, 8, 0, 0};
    ASSERT_FALSE((!Require(semantic && *semantic == expected_semantic,
                 "three-part REALITY version must parse")));

    const auto short_version = ParseRealityClientVersion("1.8");
    const RealityClientVersion expected_short{1, 8, 0, 0};
    ASSERT_FALSE((!Require(short_version && *short_version == expected_short,
                 "two-part REALITY version must zero-fill")));

    ASSERT_FALSE((!Require(RealityClientVersionValue(expected_semantic) == 0x01080000u,
                 "REALITY version ordering value must preserve components")));

    for (const char* invalid : {"1.8.0.1", "1..0", "1.256.0", "v1.8.0"}) {
        ASSERT_FALSE((!Require(!ParseRealityClientVersion(invalid),
                     "invalid REALITY version must be rejected")));
    }
}
