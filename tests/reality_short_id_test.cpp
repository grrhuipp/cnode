#include "acppnode/transport/internet/reality_short_id.hpp"

#include <cstdio>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    using acpp::transport::internet::ParseRealityShortId;
    using acpp::transport::internet::RealityShortId;

    const auto empty = ParseRealityShortId("");
    if (!Require(empty && *empty == RealityShortId{},
                 "empty short ID must normalize to zero padding")) return 1;

    const auto short_id = ParseRealityShortId("01aB");
    const RealityShortId expected_short{0x01, 0xab, 0, 0, 0, 0, 0, 0};
    if (!Require(short_id && *short_id == expected_short,
                 "short ID must decode and zero-pad")) return 2;

    const auto full = ParseRealityShortId("0123456789abcdef");
    const RealityShortId expected_full{
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    if (!Require(full && *full == expected_full,
                 "full short ID must decode exactly")) return 3;

    for (const char* invalid : {"0", "not-hex", "0123456789abcdef00"}) {
        if (!Require(!ParseRealityShortId(invalid),
                     "invalid short ID must be rejected")) return 4;
    }
    return 0;
}
