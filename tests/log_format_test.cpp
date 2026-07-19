#include "acppnode/infra/log.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void Expect(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

std::vector<std::string> ReadLines(const std::filesystem::path& path) {
    std::ifstream input(path);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(input, line)) {
        Expect(!line.empty(), "blank log line");
        lines.push_back(std::move(line));
    }
    return lines;
}

const std::string& FindLine(const std::vector<std::string>& lines,
                            std::string_view marker) {
    for (const auto& line : lines) {
        if (line.find(marker) != std::string::npos) return line;
    }
    throw std::runtime_error("missing expected log line");
}

void CheckTimestamp(std::string_view line) {
    Expect(line.size() > 19, "short log timestamp");
    Expect(line[4] == '/' && line[7] == '/', "timestamp date format");
    Expect(line[10] == ' ' && line[13] == ':' && line[16] == ':',
           "timestamp time format");
}

}  // namespace

int main() {
    const auto directory = std::filesystem::temp_directory_path() /
        "cnode-log-format-contract";
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);

    try {
        Expect(acpp::Log::Init(
            "trace", directory, 1, "access.log", "error.log", false, false),
            "logger initialization failed");

        acpp::Log::WriteSystem(
            acpp::LogLevel::WARN,
            "quoted=\"value\" newline=first\nsecond");
        acpp::Log::WriteConnection(
            acpp::LogLevel::INFO,
            acpp::ConnectionLogContext{.conn_id = 42},
            "dialing tcp:example.com:443");
        acpp::Log::WriteAccess(
            "from 192.0.2.10:52000 accepted tcp:example.com:443 "
            "[vless-in -> direct] email: user@example.com");
        acpp::Log::Shutdown();

        const auto error_lines = ReadLines(directory / "error.log");
        const auto& warning = FindLine(error_lines, "quoted=\"value\"");
        CheckTimestamp(warning);
        Expect(warning.find(" [Warning] ") != std::string::npos,
               "Xray warning level missing");
        Expect(warning.find("newline=first second") != std::string::npos,
               "embedded newline was not normalized");
        Expect(warning.front() != '{', "error log must not be JSON");

        const auto& connection = FindLine(error_lines, "dialing tcp:");
        CheckTimestamp(connection);
        Expect(connection.find(" [Info] [42] ") != std::string::npos,
               "Xray connection context missing");

        const auto access_lines = ReadLines(directory / "access.log");
        Expect(access_lines.size() == 1, "access logger wrote diagnostics");
        CheckTimestamp(access_lines.front());
        Expect(access_lines.front().find(
                   " from 192.0.2.10:52000 accepted tcp:example.com:443 "
                   "[vless-in -> direct] email: user@example.com") !=
               std::string::npos,
               "Xray access format mismatch");
        Expect(access_lines.front().find("[Info]") == std::string::npos,
               "Xray access records must not have severity");
    } catch (const std::exception& error) {
        acpp::Log::Shutdown();
        std::filesystem::remove_all(directory);
        std::cerr << error.what() << '\n';
        return 1;
    }

    std::filesystem::remove_all(directory);
    return 0;
}
