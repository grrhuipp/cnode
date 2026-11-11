#include <gtest/gtest.h>

#include "transport/internet/stream_settings.hpp"

namespace {
using ::transport::internet::ParseRealityShortId;
using ::transport::internet::RealityShortId;

TEST(RealityShortId, EmptyIdentifierRepresentsZeroPaddedIdentity) {
    const auto parsed = ParseRealityShortId("");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, RealityShortId{});
}

TEST(RealityShortId, DecodesMixedCaseHexAndPadsShortIdentity) {
    const auto parsed = ParseRealityShortId("01aB");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, (RealityShortId{0x01, 0xab, 0, 0, 0, 0, 0, 0}));
}

TEST(RealityShortId, DecodesFullWidthIdentity) {
    const auto parsed = ParseRealityShortId("0123456789abcdef");
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, (RealityShortId{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}));
}

class RealityInvalidShortId : public testing::TestWithParam<const char*> {};
TEST_P(RealityInvalidShortId, RejectsMalformedOrOversizedIdentity) {
    EXPECT_FALSE(ParseRealityShortId(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(Syntax, RealityInvalidShortId,
                        testing::Values("0", "not-hex", "0123456789abcdef00"));
}  // namespace
