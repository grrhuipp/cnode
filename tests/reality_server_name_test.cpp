#include <gtest/gtest.h>

#include "transport/stream_settings.hpp"
#include "transport/tls_server_name.hpp"
#include <array>
#include <string>
#include <vector>

namespace {
using ::transport::IsRealityServerNameAllowed;
using ::transport::ParseTlsServerNameExtension;

TEST(RealityServerName, ParsesCanonicalHostName) {
    constexpr std::array<uint8_t, 16> extension{
        0x00, 0x0e, 0x00, 0x00, 0x0b,
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm'};
    const auto parsed = ParseTlsServerNameExtension(extension);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, "example.com");
}

class RealityMalformedServerName : public testing::TestWithParam<std::vector<uint8_t>> {};
TEST_P(RealityMalformedServerName, RejectsAmbiguousOrMalformedNameList) {
    EXPECT_FALSE(ParseTlsServerNameExtension(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(NameLists, RealityMalformedServerName, testing::Values(
    std::vector<uint8_t>{0, 15, 0, 0, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0xff},
    std::vector<uint8_t>{0, 8, 0, 0, 1, 'a', 0, 0, 1, 'b'},
    std::vector<uint8_t>{0, 3, 0, 0, 0},
    std::vector<uint8_t>{0, 12, 1, 0, 1, 'x', 1, 0, 1, 'y', 0, 0, 1, 'a'}));

TEST(RealityServerName, SkipsWellFormedUnknownNameType) {
    constexpr std::array<uint8_t, 10> extension{0, 8, 1, 0, 1, 'x', 0, 0, 1, 'a'};
    const auto parsed = ParseTlsServerNameExtension(extension);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(*parsed, "a");
}

struct AllowedNameCase { const char* name; bool allowed; };
class RealityAllowedServerName : public testing::TestWithParam<AllowedNameCase> {};
TEST_P(RealityAllowedServerName, MatchesOnlyConfiguredDnsIdentityOrExplicitMissingSni) {
    const std::vector<std::string> names{"Example.COM", ""};
    EXPECT_EQ(IsRealityServerNameAllowed(names, GetParam().name), GetParam().allowed);
}
INSTANTIATE_TEST_SUITE_P(Identities, RealityAllowedServerName, testing::Values(
    AllowedNameCase{"example.com", true}, AllowedNameCase{"", true},
    AllowedNameCase{"other.example", false}, AllowedNameCase{"sub.example.com", false},
    AllowedNameCase{"example.com.", true}, AllowedNameCase{"example.com..", false},
    AllowedNameCase{".", false}));

TEST(RealityServerName, MissingSniRequiresExplicitEmptyAllowListEntry) {
    EXPECT_FALSE(IsRealityServerNameAllowed(std::vector<std::string>{"example.com"}, ""));
}
}  // namespace
