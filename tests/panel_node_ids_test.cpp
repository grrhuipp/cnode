#include <gtest/gtest.h>

#include "infra/config.hpp"

#include <limits>
#include <stdexcept>

TEST(PanelNodeIds, AcceptsPositiveIdsThroughIntMaximum) {
    const auto ids = ::infra::PanelNodeIds::Parse(::json::array{
        int64_t{1}, uint64_t{static_cast<uint64_t>(std::numeric_limits<int>::max())}});
    EXPECT_FALSE(ids.Empty());
    EXPECT_EQ(ids.Front(), 1);
    ASSERT_EQ(ids.Values().size(), 2);
    EXPECT_EQ(ids.Values()[1], std::numeric_limits<int>::max());
}

TEST(PanelNodeIds, ConstructsSinglePositiveId) {
    const auto ids = ::infra::PanelNodeIds::Single(7);
    ASSERT_EQ(ids.Values().size(), 1);
    EXPECT_EQ(ids.Front(), 7);
}

namespace {
class InvalidPanelNodeIds : public ::testing::TestWithParam<int> {};
TEST_P(InvalidPanelNodeIds, RejectsInvalidNodeSelection) {
    ::json::value value;
    switch (GetParam()) {
    case 0: value = ::json::array{}; break;
    case 1: value = int64_t{1}; break;
    case 2: value = ::json::array{int64_t{-1}}; break;
    case 3: value = ::json::array{int64_t{0}}; break;
    case 4: value = ::json::array{uint64_t{static_cast<uint64_t>(std::numeric_limits<int>::max()) + 1}}; break;
    case 5: value = ::json::array{int64_t{1}, "2"}; break;
    case 6: value = ::json::array{int64_t{1}, int64_t{1}}; break;
    }
    EXPECT_THROW(static_cast<void>(::infra::PanelNodeIds::Parse(value)), std::invalid_argument);
}
INSTANTIATE_TEST_SUITE_P(ConfigurationErrors, InvalidPanelNodeIds,
    ::testing::Values(0, 1, 2, 3, 4, 5, 6), ([](const ::testing::TestParamInfo<int>& info) {
        constexpr const char* names[]{"Empty", "NotArray", "Negative", "Zero", "Overflow", "MixedTypes", "Duplicate"};
        return names[info.param];
    }));
}  // namespace

TEST(PanelNodeIds, RejectsSingleZeroId) {
    EXPECT_THROW(static_cast<void>(::infra::PanelNodeIds::Single(0)), std::invalid_argument);
}
