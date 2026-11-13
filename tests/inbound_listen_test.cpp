#include <gtest/gtest.h>
#include "transport/inbound_listen.hpp"
#include <string_view>

namespace {
class AutomaticListen : public testing::TestWithParam<const char*> {};
TEST_P(AutomaticListen, ExposesBothWildcardFamilies) {
    const auto listen = ::transport::InboundListen::Parse(GetParam());
    ASSERT_TRUE(listen);
    ASSERT_EQ(listen->Candidates().size(), 2u);
    EXPECT_TRUE(listen->Candidates()[0].is_v4());
    EXPECT_TRUE(listen->Candidates()[0].is_unspecified());
    EXPECT_TRUE(listen->Candidates()[1].is_v6());
    EXPECT_TRUE(listen->Candidates()[1].is_unspecified());
}
INSTANTIATE_TEST_SUITE_P(Spellings, AutomaticListen, testing::Values("", "auto", "AUTO"));

struct LiteralCase { const char* text; bool ipv4; };
class LiteralListen : public testing::TestWithParam<LiteralCase> {};
TEST_P(LiteralListen, NormalizesLoopbackFamily) {
    const auto listen = ::transport::InboundListen::Parse(GetParam().text);
    ASSERT_TRUE(listen);
    ASSERT_EQ(listen->Candidates().size(), 1u);
    EXPECT_EQ(listen->Candidates()[0].is_v4(), GetParam().ipv4);
    EXPECT_TRUE(listen->Candidates()[0].is_loopback());
}
INSTANTIATE_TEST_SUITE_P(Families, LiteralListen, testing::Values(
    LiteralCase{"127.0.0.1", true}, LiteralCase{"::1", false},
    LiteralCase{"::ffff:127.0.0.1", true}));

class InvalidListen : public testing::TestWithParam<std::string_view> {};
TEST_P(InvalidListen, RejectsNonLiteralAndAmbiguousInputs) {
    EXPECT_FALSE(::transport::InboundListen::Parse(GetParam()));
}
INSTANTIATE_TEST_SUITE_P(Inputs, InvalidListen, testing::Values(
    std::string_view("not-an-ip"), std::string_view("127.0.0.1junk"), std::string_view(" auto"),
    std::string_view("127.0.0.1:9"), std::string_view("[127.0.0.1]"), std::string_view("[::1]"),
    std::string_view("127.0.0.1 "), std::string_view("fe80::1%invalid"),
    std::string_view("127.0.0.1\0ignored", 17), std::string_view("::1\0ignored", 11)));

struct OverlapCase { const char* left; const char* right; bool overlaps; };
class ListenOverlap : public testing::TestWithParam<OverlapCase> {};
TEST_P(ListenOverlap, DetectsConflictsSymmetrically) {
    const auto left = ::transport::InboundListen::Parse(GetParam().left);
    const auto right = ::transport::InboundListen::Parse(GetParam().right);
    ASSERT_TRUE(left);
    ASSERT_TRUE(right);
    EXPECT_EQ(left->Overlaps(*right), GetParam().overlaps);
    EXPECT_EQ(right->Overlaps(*left), GetParam().overlaps);
}
INSTANTIATE_TEST_SUITE_P(Addresses, ListenOverlap, testing::Values(
    OverlapCase{"127.0.0.1", "127.0.0.1", true}, OverlapCase{"127.0.0.1", "127.0.0.2", false},
    OverlapCase{"0.0.0.0", "127.0.0.1", true}, OverlapCase{"::", "::1", true},
    OverlapCase{"::1", "127.0.0.1", false}, OverlapCase{"::", "0.0.0.0", false},
    OverlapCase{"auto", "127.0.0.1", true}, OverlapCase{"auto", "::1", true},
    OverlapCase{"auto", "auto", true}, OverlapCase{"::ffff:127.0.0.1", "127.0.0.1", true},
    OverlapCase{"fe80::1%1", "fe80::1%2", false}));
}  // namespace

