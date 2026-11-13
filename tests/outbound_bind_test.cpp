#include <gtest/gtest.h>
#include "transport/outbound_bind.hpp"
#include "infra/config.hpp"
#include "infra/json.hpp"
#include <asio/ip/network_v4.hpp>
#include <asio/ip/network_v6.hpp>
#include <array>
#include <span>
#include <stdexcept>
#include <string_view>

namespace {
using Mode = ::transport::OutboundBind::Mode;
using Policy = ::transport::OutboundBind::ChoicePolicy;
using ::net::ip::make_address;
const std::array<std::string_view, 3> entries{
    "2602:2b5:20:0111::/64", "192.0.2.4", "127.0.0.0/24"};

struct BindCase { const char* text; Mode mode; };
class OutboundBindMode : public testing::TestWithParam<BindCase> {};
TEST_P(OutboundBindMode, ParsesWildcardAndAutomaticModes) {
    const auto bind = ::transport::OutboundBind::Parse(GetParam().text);
    ASSERT_TRUE(bind);
    EXPECT_EQ(bind->GetMode(), GetParam().mode);
    EXPECT_FALSE(bind->ExplicitAddress());
}
INSTANTIATE_TEST_SUITE_P(Inputs, OutboundBindMode, testing::Values(
    BindCase{"", Mode::None}, BindCase{"0.0.0.0", Mode::None}, BindCase{"::", Mode::None},
    BindCase{"0:0::", Mode::None}, BindCase{"::ffff:0.0.0.0", Mode::None},
    BindCase{"auto", Mode::Auto}, BindCase{"AUTO", Mode::Auto}));

class ExplicitOutboundBind : public testing::TestWithParam<const char*> {};
TEST_P(ExplicitOutboundBind, PreservesRequestedAddress) {
    const auto bind = ::transport::OutboundBind::Parse(GetParam());
    ASSERT_TRUE(bind);
    EXPECT_EQ(bind->ExplicitAddress(), make_address(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(Families, ExplicitOutboundBind,
    testing::Values("192.0.2.10", "2001:db8::10"));

class InvalidOutboundBind : public testing::TestWithParam<std::string_view> {};
TEST_P(InvalidOutboundBind, RejectsNonliteralAndAmbiguousInputs) {
    EXPECT_FALSE(::transport::OutboundBind::Parse(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(Inputs, InvalidOutboundBind, testing::Values(
    std::string_view("not-an-ip"), std::string_view("192.0.2.1junk"), std::string_view("  auto"),
    std::string_view("127.0.0.1:9"), std::string_view("[127.0.0.1]"), std::string_view("[::1]"),
    std::string_view("127.0.0.1 "), std::string_view("fe80::1%invalid"),
    std::string_view("127.0.0.1\0ignored", 17), std::string_view("::1\0ignored", 11)));

class InvalidBindCandidate : public testing::TestWithParam<const char*> {};
TEST_P(InvalidBindCandidate, RejectsUnusableOrMalformedRanges) {
    const std::array<std::string_view, 1> candidate{GetParam()};
    EXPECT_FALSE(::transport::OutboundBind::ParseCandidates(candidate, Policy::IpHash));
}
INSTANTIATE_TEST_SUITE_P(Inputs, InvalidBindCandidate, testing::Values(
    "", "auto", "0.0.0.0", "0.0.0.0/32", "::/128", "0.0.0.0/24", "192.0.2.1/0",
    "::ffff:192.0.2.0/24", "127.0.0.0/024", "192.0.2.0/33", "2001:db8::/129",
    "127.0.0.1/24x", "not-ip/24"));

class BindRangeFamily : public testing::TestWithParam<bool> {};
TEST_P(BindRangeFamily, HashesClientWithinFirstMatchingFamilyRange) {
    const bool ipv6 = GetParam();
    const std::array<std::string_view, 1> range{ipv6 ? "2602:2b5:20:111::/64" : "127.0.0.0/24"};
    const auto bind = ::transport::OutboundBind::ParseCandidates(range, Policy::IpHash);
    ASSERT_TRUE(bind);
    const auto remote = make_address(ipv6 ? "2001:db8:1::1" : "198.51.100.1");
    const auto first = bind->Select(remote, "203.0.113.42").address;
    ASSERT_TRUE(first);
    ASSERT_EQ(first->is_v6(), ipv6);
    if (ipv6) {
        EXPECT_EQ(::net::ip::network_v6(first->to_v6(), 64).network(),
                  ::net::ip::make_address_v6("2602:2b5:20:111::"));
    } else {
        EXPECT_EQ(::net::ip::network_v4(first->to_v4(), 24).network(),
                  ::net::ip::make_address_v4("127.0.0.0"));
    }
    EXPECT_EQ(bind->Select(remote, "203.0.113.42").address, first);
    EXPECT_NE(bind->Select(remote, "203.0.113.43").address, first);
    EXPECT_FALSE(bind->Select(make_address(ipv6 ? "198.51.100.1" : "2001:db8:1::1"), "client").address);
}
INSTANTIATE_TEST_SUITE_P(Families, BindRangeFamily, testing::Bool());

struct UserKeyCase { uint64_t uid; const char* email; };
class BindUserHash : public testing::TestWithParam<UserKeyCase> {};
TEST_P(BindUserHash, IsStableAcrossClientIpsAndIsolatesPanelNamespaces) {
    const auto bind = ::transport::OutboundBind::ParseCandidates(entries, Policy::UserHash);
    ASSERT_TRUE(bind);
    const auto remote = make_address("2001:db8:1::1");
    const auto first = bind->Select(remote, "203.0.113.1", GetParam().uid, GetParam().email, "panel/site-a").address;
    ASSERT_TRUE(first);
    EXPECT_EQ(bind->Select(remote, "198.51.100.9", GetParam().uid, GetParam().email, "panel/site-a").address, first);
    EXPECT_NE(bind->Select(remote, "203.0.113.1", GetParam().uid, GetParam().email, "panel/site-b").address, first);
    EXPECT_NE(bind->Select(remote, "203.0.113.1", GetParam().uid ? 1002 : 0, "bob@test", "panel/site-a").address, first);
}
INSTANTIATE_TEST_SUITE_P(IdentitySources, BindUserHash,
    testing::Values(UserKeyCase{1001, "a@test"}, UserKeyCase{0, "alice@test"}));

class BindConfigStrategy : public testing::TestWithParam<const char*> {};
TEST_P(BindConfigStrategy, AcceptsSupportedCandidateStrategy) {
    const auto parsed = ::infra::parse(R"(["127.0.0.1/32", "::1"])" );
    const auto strategy = ::infra::parse(GetParam());
    EXPECT_EQ(::infra::ParseOutboundBindConfig(parsed, &strategy).GetMode(), Mode::Ordered);
}
INSTANTIATE_TEST_SUITE_P(Strategies, BindConfigStrategy,
    testing::Values(R"("random")", R"("ip_hash")", R"("user_hash")"));

struct InvalidConfigCase { const char* value; const char* strategy; };
class InvalidBindConfig : public testing::TestWithParam<InvalidConfigCase> {};
TEST_P(InvalidBindConfig, RejectsInvalidCandidatesAndStrategies) {
    const auto parsed = ::infra::parse(GetParam().value);
    const auto strategy = ::infra::parse(GetParam().strategy);
    EXPECT_THROW((void)::infra::ParseOutboundBindConfig(parsed, &strategy), std::invalid_argument);
}
INSTANTIATE_TEST_SUITE_P(Inputs, InvalidBindConfig, testing::Values(
    InvalidConfigCase{"[]", R"("ip_hash")"}, InvalidConfigCase{"[7]", R"("ip_hash")"},
    InvalidConfigCase{R"(["bad/24"])", R"("ip_hash")"},
    InvalidConfigCase{R"(["::1"])", R"("round-robin")"},
    InvalidConfigCase{R"(["::1"])", R"("hash")"}, InvalidConfigCase{R"("auto")", R"("ip_hash")"}));
}  // namespace

TEST(OutboundBind, OrderedCandidatesPreserveExactAddressInsteadOfFallingThrough) {
    const auto bind = ::transport::OutboundBind::ParseCandidates(entries, Policy::IpHash);
    ASSERT_TRUE(bind);
    EXPECT_TRUE(bind->PrefersIPv6());
    EXPECT_EQ(bind->Select(make_address("198.51.100.1"), "client").address, make_address("192.0.2.4"));
    const std::array<std::string_view, 1> unassigned{"2602:2b5:20:111::1234"};
    const auto exact = ::transport::OutboundBind::ParseCandidates(unassigned, Policy::IpHash);
    ASSERT_TRUE(exact);
    EXPECT_EQ(exact->Select(make_address("2001:db8:1::1"), "client").address, make_address(unassigned[0]));
    EXPECT_FALSE(exact->Select(make_address("198.51.100.1"), "client").address);
}

TEST(OutboundBind, RandomSelectionStaysInRangeAndVaries) {
    const auto bind = ::transport::OutboundBind::ParseCandidates(entries, Policy::Random);
    ASSERT_TRUE(bind);
    const auto remote = make_address("2001:db8:1::1");
    const auto first = bind->Select(remote, "client", 80).address;
    bool different = false;
    for (int i = 0; i < 64; ++i) {
        const auto next = bind->Select(remote, "client", 80).address;
        ASSERT_TRUE(next);
        ASSERT_TRUE(next->is_v6());
        EXPECT_EQ(::net::ip::network_v6(next->to_v6(), 64).network(), ::net::ip::make_address_v6("2602:2b5:20:111::"));
        different |= next != first;
    }
    EXPECT_TRUE(different);
}

TEST(OutboundBind, AutomaticBindingAvoidsInappropriateSourceScope) {
    const auto bind = ::transport::OutboundBind::Parse("auto");
    ASSERT_TRUE(bind);
    const ::tcp::endpoint public_inbound(make_address("192.0.2.10"), 443);
    EXPECT_FALSE(bind->BindAddressFor(&public_inbound, make_address("127.0.0.1")));
    const ::tcp::endpoint link_local(make_address("fe80::1"), 443);
    EXPECT_FALSE(bind->BindAddressFor(&link_local, make_address("2001:db8:1::1")));
}

TEST(OutboundBind, RejectsEmptyCandidateSet) {
    EXPECT_FALSE(::transport::OutboundBind::ParseCandidates(std::span<const std::string_view>{}, Policy::IpHash));
}
