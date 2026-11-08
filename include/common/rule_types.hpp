#pragma once

#include <regex>

namespace rule {

struct DetectRule {
    std::regex Pattern;
};

}  // namespace rule
