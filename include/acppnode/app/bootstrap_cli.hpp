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
    Error,
};

enum class ConfigPathMode {
    Auto,
    File,
    Directory,
};

struct CommandLineOptions {
    std::string config_path = std::string(constants::paths::kDefaultConfigFile);
    ConfigPathMode config_mode = ConfigPathMode::Auto;
    bool test_mode = false;
    CommandLineAction action = CommandLineAction::None;
    std::string error;
};

[[nodiscard]] CommandLineOptions ParseCommandLine(int argc, char* argv[]);
void PrintUsage(std::ostream& out, std::string_view prog);
void PrintVersion(std::ostream& out);

}  // namespace acpp
