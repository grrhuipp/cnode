#include <gtest/gtest.h>

#include "transport/internet/http_headers.hpp"

#include <string_view>

namespace {
struct PathCase { std::string_view configured, requested; bool matches; };
class HttpPathPrefix : public testing::TestWithParam<PathCase> {};
TEST_P(HttpPathPrefix, RequiresSegmentBoundaryForPrefix) {
    const auto& item = GetParam();
    EXPECT_EQ(::transport::internet::detail::PathPrefixMatchesSegment(item.configured, item.requested), item.matches);
}
INSTANTIATE_TEST_SUITE_P(Paths, HttpPathPrefix, testing::Values(
    PathCase{"/api", "/api", true}, PathCase{"/api", "/api/child", true},
    PathCase{"/api", "/api?padding=1", true}, PathCase{"/api", "/apievil", false},
    PathCase{"/api", "/api-v2", false}, PathCase{"/api/", "/api/session", true},
    PathCase{"/api/", "/api", false}, PathCase{"/", "/anything", true},
    PathCase{"", "/anything", true}, PathCase{"/", "relative", false}));

class HttpPathExact : public testing::TestWithParam<PathCase> {};
TEST_P(HttpPathExact, IgnoresQueryWithoutMakingRootAWildcard) {
    const auto& item = GetParam();
    EXPECT_EQ(::transport::internet::detail::PathMatchesExactly(item.configured, item.requested), item.matches);
}
INSTANTIATE_TEST_SUITE_P(Paths, HttpPathExact, testing::Values(
    PathCase{"/up", "/up", true}, PathCase{"/up", "/up?ed=2048", true},
    PathCase{"/up", "/down", false}, PathCase{"/up", "/up/", false},
    PathCase{"/up", "/up/child?ed=2048", false}, PathCase{"/", "/?ed=2048", true},
    PathCase{"", "/", true}, PathCase{"/", "/up", false}, PathCase{"", "/up?ed=2048", false}));
}  // namespace
