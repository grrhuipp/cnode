#include "acppnode/proxy/sniff_config.hpp"

#include <cstdio>

namespace {

bool Require(bool condition, const char* message) {
    if (!condition) std::fprintf(stderr, "%s\n", message);
    return condition;
}

}  // namespace

int main() {
    acpp::SniffConfig config;
    config.domains_excluded = {"Blocked.Example", "safe.example"};

    if (!Require(config.IsDomainExcluded("blocked.example"),
                 "domain exclusions must be ASCII case-insensitive")) return 1;
    if (!Require(config.IsDomainExcluded("SAFE.EXAMPLE"),
                 "uppercase sniffed domains must remain excluded")) return 2;
    if (!Require(!config.IsDomainExcluded("not-safe.example"),
                 "domain exclusions must remain exact names")) return 3;
    if (!Require(config.IsDomainExcluded("blocked.example."),
                 "an absolute DNS name must not bypass domain exclusions")) return 4;
    config.RefreshHotPathFields();
    if (!Require(config.domains_excluded.front() == "blocked.example",
                 "cold-path sniff config must publish canonical exclusions")) return 5;
    return 0;
}
