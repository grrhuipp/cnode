#include <gtest/gtest.h>

#include "transport/internet/stream_settings.hpp"

#include <array>

TEST(RealityClientVersion, Contract) {
    using ::transport::internet::ParseRealityClientVersion;
    using ::transport::internet::RealityClientVersion;
    using ::transport::internet::RealityClientVersionValue;

    const auto unset = ParseRealityClientVersion("");
    ASSERT_TRUE(unset && !*unset)
        << "empty version policy must remain unset";

    const auto semantic = ParseRealityClientVersion("1.8.0");
    const RealityClientVersion expected_semantic{1, 8, 0, 0};
    ASSERT_TRUE(semantic && *semantic == expected_semantic)
        << "three-part REALITY version must parse";

    const auto short_version = ParseRealityClientVersion("1.8");
    const RealityClientVersion expected_short{1, 8, 0, 0};
    ASSERT_TRUE(short_version && *short_version == expected_short)
        << "two-part REALITY version must zero-fill";

    ASSERT_TRUE(RealityClientVersionValue(expected_semantic) == 0x01080000u)
        << "REALITY version ordering value must preserve components";

    for (const char* invalid : {"1.8.0.1", "1..0", "1.256.0", "v1.8.0"}) {
        ASSERT_FALSE(ParseRealityClientVersion(invalid))
            << "invalid REALITY version must be rejected";
    }
}
