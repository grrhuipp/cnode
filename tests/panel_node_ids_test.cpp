#include <gtest/gtest.h>

#include "infra/panel_node_ids.hpp"

#include <limits>
#include <stdexcept>

namespace {

bool Rejects(::json::value value) {
    try {
        (void)::PanelNodeIds::Parse(value);
        return false;
    } catch (const std::invalid_argument&) {
        return true;
    }
}

}  // namespace

TEST(PanelNodeIds, Contract) {
    auto valid = ::PanelNodeIds::Parse(::json::array{
        int64_t{1}, uint64_t{static_cast<uint64_t>(std::numeric_limits<int>::max())}});
    ASSERT_FALSE((valid.Empty() || valid.Front() != 1 || valid.Values().size() != 2 ||
        valid.Values()[1] != std::numeric_limits<int>::max()));

    auto single = ::PanelNodeIds::Single(7);
    ASSERT_FALSE((single.Values().size() != 1 || single.Front() != 7));

    ASSERT_FALSE((!Rejects(::json::array{})));
    ASSERT_FALSE((!Rejects(int64_t{1})));
    ASSERT_FALSE((!Rejects(::json::array{int64_t{-1}})));
    ASSERT_FALSE((!Rejects(::json::array{int64_t{0}})));
    ASSERT_FALSE((!Rejects(::json::array{uint64_t{
            static_cast<uint64_t>(std::numeric_limits<int>::max()) + 1}})));
    ASSERT_FALSE((!Rejects(::json::array{int64_t{1}, "2"})));
    ASSERT_FALSE((!Rejects(::json::array{int64_t{1}, int64_t{1}})));

    try {
        (void)::PanelNodeIds::Single(0);
        FAIL() << "node ID zero must be rejected";
    } catch (const std::invalid_argument&) {
    }
}
