#include <gtest/gtest.h>

#include "transport/internet/reality_short_id.hpp"

#include <cstdio>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

TEST(RealityShortId, Contract) {
    using ::transport::internet::ParseRealityShortId;
    using ::transport::internet::RealityShortId;

    const auto empty = ParseRealityShortId("");
    ASSERT_FALSE((!Require(empty && *empty == RealityShortId{},
                 "empty short ID must normalize to zero padding")));

    const auto short_id = ParseRealityShortId("01aB");
    const RealityShortId expected_short{0x01, 0xab, 0, 0, 0, 0, 0, 0};
    ASSERT_FALSE((!Require(short_id && *short_id == expected_short,
                 "short ID must decode and zero-pad")));

    const auto full = ParseRealityShortId("0123456789abcdef");
    const RealityShortId expected_full{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    ASSERT_FALSE((!Require(full && *full == expected_full,
                 "full short ID must decode exactly")));

    for (const char* invalid : {"0", "not-hex", "0123456789abcdef00"}) {
        ASSERT_FALSE((!Require(!ParseRealityShortId(invalid),
                     "invalid short ID must be rejected")));
    }
}
