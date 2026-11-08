#include <gtest/gtest.h>

#include "reality_key_share.hpp"

#include <algorithm>
#include <cstdio>
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

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

TEST(RealityKeyShare, Contract) {
    using ::transport::internet::ParseRealityClientKeyShareExtension;
    constexpr uint16_t kX25519 = 29;
    constexpr uint16_t kX25519MlKem768 = 0x11ec;

    const std::vector<uint8_t> x25519_key(32, 0x2a);
    const std::vector<Entry> valid_entries{{kX25519, x25519_key}};
    const auto valid =
        ParseRealityClientKeyShareExtension(BuildExtension(valid_entries));
    ASSERT_FALSE((!Require(valid && valid->front() == 0x2a,
                 "a canonical X25519 key share must parse")));

    const std::vector<uint8_t> trailing{0xff};
    ASSERT_FALSE((!Require(!ParseRealityClientKeyShareExtension(
                     BuildExtension(valid_entries, trailing)),
                 "bytes after an X25519 key share must not be ignored")));

    const std::vector<Entry> duplicate_entries{
        {kX25519, x25519_key}, {kX25519, x25519_key}};
    ASSERT_FALSE((!Require(!ParseRealityClientKeyShareExtension(
                     BuildExtension(duplicate_entries)),
                 "duplicate X25519 groups must be rejected")));

    const std::vector<Entry> short_hybrid{{kX25519MlKem768, x25519_key}};
    ASSERT_FALSE((!Require(!ParseRealityClientKeyShareExtension(
                     BuildExtension(short_hybrid)),
                 "a truncated X25519MLKEM768 share must be rejected")));

    std::vector<uint8_t> hybrid_key(1216, 0x11);
    std::fill_n(hybrid_key.end() - 32, 32, uint8_t{0x3b});
    const std::vector<Entry> valid_hybrid{{kX25519MlKem768, hybrid_key}};
    const auto parsed_hybrid =
        ParseRealityClientKeyShareExtension(BuildExtension(valid_hybrid));
    ASSERT_FALSE((!Require(parsed_hybrid && parsed_hybrid->front() == 0x3b,
                 "a canonical hybrid share must expose its X25519 suffix")));

    const std::vector<Entry> hybrid_then_x25519{
        {kX25519MlKem768, hybrid_key}, {kX25519, x25519_key}};
    const auto preferred_x25519 = ParseRealityClientKeyShareExtension(
        BuildExtension(hybrid_then_x25519));
    ASSERT_FALSE((!Require(preferred_x25519 && preferred_x25519->front() == 0x2a,
                 "a standalone X25519 share must remain preferred")));
}
