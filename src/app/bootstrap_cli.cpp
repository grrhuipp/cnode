#include "acppnode/app/bootstrap_cli.hpp"

#include <format>
#include <iostream>
#include <utility>

namespace acpp {

namespace {

bool SetError(CommandLineOptions& options, std::string error) {
    options.action = CommandLineAction::Error;
    options.error = std::move(error);
    return false;
}

bool ReadValue(
    CommandLineOptions& options,
    std::string_view option,
    int argc,
    char* argv[],
    int& index) {
    if (index + 1 >= argc) {
        return SetError(options, std::format("Option {} requires a value", option));
    }

    options.config_path = argv[++index];
    return true;
}

}  // namespace

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
        if (arg == "-c" || arg == "--config") {
            if (!ReadValue(options, arg, argc, argv, i)) break;
            options.config_mode = ConfigPathMode::Auto;
            continue;
        }
        if (arg == "--config-file") {
            if (!ReadValue(options, arg, argc, argv, i)) break;
            options.config_mode = ConfigPathMode::File;
            continue;
        }
        if (arg == "-C" || arg == "--config-dir") {
            if (!ReadValue(options, arg, argc, argv, i)) break;
            options.config_mode = ConfigPathMode::Directory;
            continue;
        }
        if (!arg.empty() && arg.front() == '-') {
            SetError(options, std::format("Unknown option: {}", arg));
            break;
        }
        SetError(options, std::format("Unexpected argument: {}", arg));
        break;
    }

    return options;
}

void PrintUsage(std::ostream& out, std::string_view prog) {
    out << "Usage: " << prog << " [options]\n"
        << "  -c, --config <path>       Config file or directory (default: "
        << constants::paths::kDefaultConfigFile << ")\n"
        << "      --config-file <file>  Load one config file; sidecars use its directory\n"
        << "  -C, --config-dir <dir>    Load config.json and sidecars from directory\n"
        << "  -t, --test                Test mode with built-in user\n"
        << "  -h, --help                Show help\n"
        << "  -v, --version             Show version\n"
        << "\n"
        << "Directory mode reads: "
        << constants::paths::kDefaultConfigFile << ", "
        << constants::paths::kInboundFile << ", "
        << constants::paths::kOutboundFile << ", "
        << constants::paths::kRouteFile << "\n";
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
