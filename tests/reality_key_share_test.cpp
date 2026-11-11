#include <gtest/gtest.h>

#include "transport/internet/reality_tls.hpp"

#include <algorithm>
#include <span>
#include <utility>
#include <vector>

namespace {

using Entry = std::pair<uint16_t, std::vector<uint8_t>>;

void AppendU16(std::vector<uint8_t>& output, std::size_t value) {
    output.push_back(static_cast<uint8_t>(value >> 8));
    output.push_back(static_cast<uint8_t>(value));
}

std::vector<uint8_t> BuildExtension(
    std::span<const Entry> entries,
    std::span<const uint8_t> trailing = {}) {
    std::vector<uint8_t> body;
    for (const auto& [group, key] : entries) {
        AppendU16(body, group);
        AppendU16(body, key.size());
        body.insert(body.end(), key.begin(), key.end());
    }
    body.insert(body.end(), trailing.begin(), trailing.end());

    std::vector<uint8_t> extension;
    AppendU16(extension, body.size());
    extension.insert(extension.end(), body.begin(), body.end());
    return extension;
}

}  // namespace

TEST(RealityKeyShare, ParsesStandaloneX25519Share) {
    const std::vector<Entry> entries{{29, std::vector<uint8_t>(32, 0x2a)}};
    const auto parsed = ::transport::internet::ParseRealityClientKeyShareExtension(BuildExtension(entries));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(std::ranges::all_of(*parsed, [](uint8_t byte) { return byte == 0x2a; }));
}

TEST(RealityKeyShare, RejectsTrailingBytesAfterShare) {
    const std::vector<Entry> entries{{29, std::vector<uint8_t>(32, 0x2a)}};
    const std::vector<uint8_t> trailing{0xff};
    EXPECT_FALSE(::transport::internet::ParseRealityClientKeyShareExtension(BuildExtension(entries, trailing)));
}

TEST(RealityKeyShare, RejectsDuplicateX25519Group) {
    const std::vector<uint8_t> key(32, 0x2a);
    const std::vector<Entry> entries{{29, key}, {29, key}};
    EXPECT_FALSE(::transport::internet::ParseRealityClientKeyShareExtension(BuildExtension(entries)));
}

TEST(RealityKeyShare, RejectsTruncatedHybridShare) {
    const std::vector<Entry> entries{{0x11ec, std::vector<uint8_t>(32, 0x2a)}};
    EXPECT_FALSE(::transport::internet::ParseRealityClientKeyShareExtension(BuildExtension(entries)));
}

TEST(RealityKeyShare, ExtractsX25519SuffixFromHybridShare) {
    std::vector<uint8_t> key(1216, 0x11);
    std::fill_n(key.end() - 32, 32, uint8_t{0x3b});
    const std::vector<Entry> entries{{0x11ec, key}};
    const auto parsed = ::transport::internet::ParseRealityClientKeyShareExtension(BuildExtension(entries));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(std::ranges::all_of(*parsed, [](uint8_t byte) { return byte == 0x3b; }));
}

TEST(RealityKeyShare, PrefersStandaloneX25519OverEarlierHybridShare) {
    const std::vector<Entry> entries{
        {0x11ec, std::vector<uint8_t>(1216, 0x11)}, {29, std::vector<uint8_t>(32, 0x2a)}};
    const auto parsed = ::transport::internet::ParseRealityClientKeyShareExtension(BuildExtension(entries));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(std::ranges::all_of(*parsed, [](uint8_t byte) { return byte == 0x2a; }));
}
