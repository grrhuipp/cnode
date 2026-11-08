#include <stdexcept>
#include <gtest/gtest.h>

#include "http_path_match.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

void Require(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << message << '\n';
        ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
    }
}

}  // namespace

TEST(HttpPathMatch, Contract) {
    using ::transport::internet::detail::PathPrefixMatchesSegment;

    Require(PathPrefixMatchesSegment("/api", "/api"), "exact path rejected");
    Require(PathPrefixMatchesSegment("/api", "/api/child"), "child path rejected");
    Require(PathPrefixMatchesSegment("/api", "/api?padding=1"), "query path rejected");
    Require(!PathPrefixMatchesSegment("/api", "/apievil"), "adjacent prefix accepted");
    Require(!PathPrefixMatchesSegment("/api", "/api-v2"), "dash suffix accepted");

    Require(PathPrefixMatchesSegment("/api/", "/api/session"),
            "normalized XHTTP child rejected");
    Require(!PathPrefixMatchesSegment("/api/", "/api"),
            "missing normalized separator accepted");
    Require(PathPrefixMatchesSegment("/", "/anything"), "root path rejected");
    Require(PathPrefixMatchesSegment({}, "/anything"), "empty root path rejected");
    Require(!PathPrefixMatchesSegment("/", "relative"), "relative root path accepted");
}
