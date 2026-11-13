#include <gtest/gtest.h>

#include "transport/stream_settings.hpp"
namespace {
using ::transport::ParseRealityClientVersion;
using ::transport::RealityClientVersion;
using ::transport::RealityClientVersionValue;

TEST(RealityClientVersion, EmptyPolicyDisablesVersionRestriction) {
    const auto parsed = ParseRealityClientVersion("");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_FALSE(*parsed);
}

class RealityVersionSyntax : public testing::TestWithParam<const char*> {};
TEST_P(RealityVersionSyntax, ParsesSemanticVersion) {
    const auto parsed = ParseRealityClientVersion(GetParam());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, (RealityClientVersion{1, 8, 0, 0}));
}
INSTANTIATE_TEST_SUITE_P(Components, RealityVersionSyntax, testing::Values("1.8.0", "1.8"));

TEST(RealityClientVersion, OrderingPreservesVersionComponents) {
    EXPECT_EQ(RealityClientVersionValue(RealityClientVersion{1, 8, 0, 0}), 0x01080000u);
}

class RealityInvalidVersion : public testing::TestWithParam<const char*> {};
TEST_P(RealityInvalidVersion, RejectsMalformedOrOverflowingVersion) {
    EXPECT_FALSE(ParseRealityClientVersion(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(Syntax, RealityInvalidVersion,
                        testing::Values("1.8.0.1", "1..0", "1.256.0", "v1.8.0"));
}  // namespace
