#include "http_path_match.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

void Require(bool condition, std::string_view message) {
    if (!condition) {
        std::cerr << message << '\n';
        std::exit(1);
    }
}

}  // namespace

int main() {
    using acpp::transport::internet::detail::PathPrefixMatchesSegment;

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
