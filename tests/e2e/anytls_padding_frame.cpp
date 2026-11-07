#include "anytls_padding.hpp"
#ifdef CNODE_REFERENCE_ANYTLS_CLIENT
#include "reference_support.hpp"
#endif

namespace cnode::e2e::padding {
namespace {
struct FrameCase {
    const char* name;
    const char* rule;
    std::vector<size_t> opening;
    bool valid;
};
std::vector<FrameCase> FrameCases() {
    std::vector<FrameCase> cases{
        {"OneByte", "1-1", {}, true},
        {"SevenBytes", "7-7", {}, true},
        {"EightBytes", "8-8", {}, true},
        {"BufferMinusOne", "8191-8191", {8095}, true},
        {"BufferSize", "8192-8192", {8096}, true},
        {"BufferPlusOne", "8193-8193", {8097}, true},
        {"TlsSize", "16384-16384", {16288}, true},
        {"Maximum", "65535-65535", {65439}, true},
        {"UpperRange", "65535-65536", {65439}, true},
        {"ReversedRange", "65536-65535", {65439}, true},
        {"SplitThenPad", "1-1,7-7,8-8,8192-8192,c,65535-65535", {8112}, true},
        {"PureMaximum", "256-256,65535-65535", {160, 65535}, true},
        {"PureBufferSize", "256-256,8192-8192", {160, 8192}, true},
        {"CheckBeforeMaximum", "256-256,c,65535-65535", {160}, true},
    };
#ifndef CNODE_REFERENCE_ANYTLS_CLIENT
    // Unencodable policies are sent only to cnode, never to the unmodified Go peer.
    cases.insert(cases.end(), {
        {"ConstantOverflow", "65536-65536", {160}, false},
        {"RangeOverflow", "65534-65537", {160}, false},
        {"OverflowAfterCheck", "256-256,c,65536-65536", {160}, false},
        {"InvalidLastDuplicate", "256-256\n1=65536-65536", {160}, false},
        {"InvalidFirstDuplicate", "65536-65536\n1=256-256", {160}, false},
    });
#endif
    return cases;
}
class AnyTlsFramePadding : public testing::TestWithParam<FrameCase> {
public:
#ifdef CNODE_REFERENCE_ANYTLS_CLIENT
    static void SetUpTestSuite() {
        reference::VerifyAnyTls(CNODE_REFERENCE_ANYTLS_CLIENT, "client");
    }
#endif
};
TEST_P(AnyTlsFramePadding, WireCapacityAndInvalidUpdateIsolationSurviveReconnect) {
    const auto& test = GetParam();
    const std::string candidate = "stop=3\n0=45-45\n1=" + std::string(test.rule) + "\n2=64-64\n";
#ifdef CNODE_REFERENCE_ANYTLS_CLIENT
    constexpr bool reference = true;
    constexpr size_t delta = std::string_view("anytls/0.0.13").size() - std::string_view("cnode").size();
#else
    constexpr bool reference = false;
    constexpr size_t delta = 0;
#endif
    auto expected = test.opening;
    if (!expected.empty()) expected.front() -= delta;
    expected.push_back(42);
    const auto retained = test.valid ? candidate : std::string(Learned);
    const std::vector<size_t> learned_waste{160 - delta, 42};
    const auto observed = PhysicalSessions({
        {std::string(Default), 30, 30, {std::string(Learned)}, std::nullopt},
        {std::string(Learned), 45, 45, {candidate}, learned_waste},
        {retained, 45, 45, {}, expected},
        {retained, 45, 45, {}, expected},
    }, "frame-padding-fixture", reference);
    EXPECT_EQ(observed.size(), 4U);
}
INSTANTIATE_TEST_SUITE_P(WireMatrix, AnyTlsFramePadding, testing::ValuesIn(FrameCases()),
                        [](const testing::TestParamInfo<FrameCase>& info) { return info.param.name; });
} // namespace
} // namespace cnode::e2e::padding
