#pragma once

#include <regex>

namespace acpp::rule {

struct DetectRule {
    int ID = 0;
    std::regex Pattern;
};

}  // namespace acpp::rule
