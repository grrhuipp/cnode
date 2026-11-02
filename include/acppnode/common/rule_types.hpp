#pragma once

#include <regex>

namespace acpp::rule {

struct DetectRule {
    std::regex Pattern;
};

}  // namespace acpp::rule
