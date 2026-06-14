#pragma once

#include <cstdint>
#include <regex>

namespace acpp::rule {

struct DetectRule {
    int ID = 0;
    std::regex Pattern;
};

struct DetectResult {
    int64_t UID = 0;
    int RuleID = 0;
};

}  // namespace acpp::rule
