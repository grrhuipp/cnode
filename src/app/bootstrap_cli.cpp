#include "acppnode/app/bootstrap_cli.hpp"

#include <iostream>

namespace acpp {

CommandLineOptions ParseCommandLine(int argc, char* argv[]) {
    CommandLineOptions options;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-h" || arg == "--help") && options.action == CommandLineAction::None) {
            options.action = CommandLineAction::Help;
            continue;
        }
        if ((arg == "-v" || arg == "--version") && options.action == CommandLineAction::None) {
            options.action = CommandLineAction::Version;
            continue;
        }
        if (arg == "-t" || arg == "--test") {
            options.test_mode = true;
            continue;
        }
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            options.config_path = argv[++i];
        }
    }

    return options;
}

void PrintUsage(std::ostream& out, std::string_view prog) {
    out << "Usage: " << prog << " [options]\n"
        << "  -c, --config <file>   Config file (default: "
        << constants::paths::kDefaultConfigFile << ")\n"
        << "  -t, --test            Test mode with built-in user\n"
        << "  -h, --help            Show help\n"
        << "  -v, --version         Show version\n";
}

void PrintVersion(std::ostream& out) {
#ifndef BUILD_ID
#define BUILD_ID "dev"
#endif
#ifndef BUILD_CHANNEL
#define BUILD_CHANNEL "release"
#endif
    out << BUILD_CHANNEL << ":" << BUILD_ID << "\n";
}

}  // namespace acpp
