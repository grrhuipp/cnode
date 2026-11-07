#include "anytls_padding.hpp"

namespace cnode::e2e::padding {
namespace {
struct AuthCase {
    const char* name;
    const char* policy;
    std::optional<std::pair<unsigned, unsigned>> bounds;
};
class AnyTlsAuthPadding : public testing::TestWithParam<AuthCase> {};

TEST_P(AnyTlsAuthPadding, ReconnectUsesLastValidPolicyForAuthenticationAndDigest) {
    const auto& test = GetParam();
    const auto bounds = test.bounds.value_or(std::pair{45U, 45U});
    const std::string accepted = test.bounds ? test.policy : std::string(Learned);
    const size_t samples = bounds == std::pair{45U, 77U} ? 32 : 2;
    std::vector<PhysicalCase> cases{
        {std::string(Default), 30, 30, {std::string(Learned)}, std::nullopt},
        {std::string(Learned), 45, 45, {test.policy}, std::nullopt}};
    for (size_t i = 0; i < samples; ++i)
        cases.push_back({accepted, bounds.first, bounds.second, {}, std::nullopt});
    const auto observations = PhysicalSessions(cases, "auth-policy-fixture");
    ASSERT_EQ(observations.size(), 2 + samples);
    if (samples == 32) {
        std::set<uint16_t> sizes;
        for (size_t i = 2; i < observations.size(); ++i) sizes.insert(observations[i].authentication);
        EXPECT_GE(sizes.size(), 2U) << "range must be sampled rather than reduced to a constant";
    }
}

INSTANTIATE_TEST_SUITE_P(PolicyMatrix, AnyTlsAuthPadding, testing::Values(
    AuthCase{"MissingZero", "stop=3\n1=160-160\n2=80-80\n", std::pair{0U, 0U}},
    AuthCase{"StopOnly", "stop=1\n", std::pair{0U, 0U}},
    AuthCase{"ExplicitZero", "stop=2\n0=0-0\n1=160-160\n", std::pair{0U, 0U}},
    AuthCase{"AuthOnly", "stop=1\n0=45-45\n", std::pair{45U, 45U}},
    AuthCase{"Range", "stop=2\n0=45-77\n1=160-160\n", std::pair{45U, 77U}},
    AuthCase{"ReversedRange", "stop=2\n0=77-45\n1=160-160\n", std::pair{45U, 77U}},
    AuthCase{"UpperBound", "stop=2\n0=65535-65536\n1=160-160\n", std::pair{65535U, 65536U}},
    AuthCase{"ValidDuplicate", "stop=2\n0=45-45\n0=91-91\n1=160-160\n", std::pair{91U, 91U}},
    AuthCase{"ConstantOverflow", "stop=2\n0=65536-65536\n1=160-160\n", std::nullopt},
    AuthCase{"RangeOverflow", "stop=2\n0=65534-65537\n1=160-160\n", std::nullopt},
    AuthCase{"CopyMarker", "stop=2\n0=c,55-55\n1=160-160\n", std::nullopt},
    AuthCase{"MultipleRanges", "stop=2\n0=45-45,50-50\n1=160-160\n", std::nullopt},
    AuthCase{"Negative", "stop=2\n0=-1-10\n1=160-160\n", std::nullopt},
    AuthCase{"Malformed", "stop=2\n0=garbage\n1=160-160\n", std::nullopt},
    AuthCase{"ZeroNonzero", "stop=2\n0=0-10\n1=160-160\n", std::nullopt},
    AuthCase{"EmptyAuth", "stop=2\n0=\n1=160-160\n", std::nullopt},
    AuthCase{"TrailingComma", "stop=2\n0=45-45,\n1=160-160\n", std::nullopt},
    AuthCase{"InvalidLastDuplicate", "stop=2\n0=45-45\n0=bad\n1=160-160\n", std::nullopt},
    AuthCase{"InvalidFirstDuplicate", "stop=2\n0=bad\n0=45-45\n1=160-160\n", std::nullopt}
), [](const testing::TestParamInfo<AuthCase>& info) { return info.param.name; });
} // namespace
} // namespace cnode::e2e::padding
