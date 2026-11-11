#include <gtest/gtest.h>

#include "transport/internet/stream_settings.hpp"

TEST(RealityShortId, Contract) {
    using ::transport::internet::ParseRealityShortId;
    using ::transport::internet::RealityShortId;

    const auto empty = ParseRealityShortId("");
    ASSERT_TRUE(empty && *empty == RealityShortId{})
        << "empty short ID must normalize to zero padding";

    const auto short_id = ParseRealityShortId("01aB");
    const RealityShortId expected_short{0x01, 0xab, 0, 0, 0, 0, 0, 0};
    ASSERT_TRUE(short_id && *short_id == expected_short)
        << "short ID must decode and zero-pad";

    const auto full = ParseRealityShortId("0123456789abcdef");
    const RealityShortId expected_full{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    ASSERT_TRUE(full && *full == expected_full)
        << "full short ID must decode exactly";

    for (const char* invalid : {"0", "not-hex", "0123456789abcdef00"}) {
        ASSERT_FALSE(ParseRealityShortId(invalid))
            << "invalid short ID must be rejected";
    }
}
