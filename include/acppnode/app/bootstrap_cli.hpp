#pragma once

#include "acppnode/core/constants.hpp"

#include <ostream>
#include <string>
#include <string_view>

namespace acpp {

enum class CommandLineAction {
    None,
    Help,
    Version,
};

struct CommandLineOptions {
    std::string config_path = std::string(constants::paths::kDefaultConfigFile);
    bool test_mode = false;
    CommandLineAction action = CommandLineAction::None;
};

[[nodiscard]] CommandLineOptions ParseCommandLine(int argc, char* argv[]);
void PrintUsage(std::ostream& out, std::string_view prog);
void PrintVersion(std::ostream& out);

}  // namespace acpp
