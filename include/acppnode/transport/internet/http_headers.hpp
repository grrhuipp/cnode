#pragma once

#include <string>
#include <unordered_map>

namespace acpp::transport::internet {

using HttpHeaders = std::unordered_map<std::string, std::string>;

}  // namespace acpp::transport::internet
