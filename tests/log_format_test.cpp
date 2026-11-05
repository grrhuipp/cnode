#include "acppnode/infra/log.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void Expect(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

std::vector<std::string> ReadLines(const std::filesystem::path& path) {
    std::ifstream input(path);
    Expect(input.is_open(), "log file was not created");
    std::vector<std::string> lines;
    for (std::string line; std::getline(input, line);) {
        Expect(!line.empty(), "blank log record");
        for (const unsigned char ch : line) {
            Expect(ch >= 0x20 && ch != 0x7f, "raw control character in log record");
        }
        lines.push_back(std::move(line));
    }
    return lines;
}

const std::string& FindLine(const std::vector<std::string>& lines,
                            std::string_view marker) {
    for (const auto& line : lines) {
        if (line.find(marker) != std::string::npos) return line;
    }
    throw std::runtime_error("missing log event: " + std::string(marker));
}

bool Contains(const std::vector<std::string>& lines, std::string_view marker) {
    for (const auto& line : lines) {
        if (line.find(marker) != std::string::npos) return true;
    }
    return false;
}

void CheckTimestamp(std::string_view line) {
    Expect(line.size() > 26 && line[4] == '/' && line[7] == '/' &&
           line[10] == ' ' && line[13] == ':' && line[16] == ':' && line[19] == '.',
           "core timestamp must include microseconds");
    Expect(line.substr(20, 6).find_first_not_of("0123456789") == std::string_view::npos,
           "invalid microsecond timestamp");
}

struct StreamCapture {
    std::ostringstream text;
    std::ostream& stream;
    std::streambuf* previous;

    explicit StreamCapture(std::ostream& target)
        : stream(target), previous(stream.rdbuf(text.rdbuf())) {}
    ~StreamCapture() { stream.rdbuf(previous); }
};

struct SessionLogContext {
    struct {
        std::string_view tag;
        int64_t user_id = 0;
    } inbound;
    struct {
        std::string_view tag;
    } outbound;
    uint64_t conn_id = 0;
};

}  // namespace

int main() {
    const auto directory = std::filesystem::temp_directory_path() /
        ("cnode-log-format-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    try {
        StreamCapture console(std::cout);
        StreamCapture errors(std::cerr);
        Expect(acpp::Log::Init("trace", directory, 1,
                              "access.log", "error.log", false, false),
               "logger initialization failed");
        std::string injection = "diagnostic injection\nforged\r\t\x1b";
        injection.push_back('\0');
        acpp::Log::WriteSystem(acpp::LogLevel::WARN, injection);
        acpp::Log::WriteConnection(acpp::LogLevel::WARN,
            SessionLogContext{
                .inbound = {.tag = "vless-in", .user_id = 123},
                .outbound = {.tag = "direct"},
                .conn_id = (1ull << 32) | 7},
            "authenticated outbound failure");
        acpp::Log::WriteConnection(acpp::LogLevel::WARN,
            SessionLogContext{
                .inbound = {.tag = "vless-in", .user_id = 0},
                .outbound = {},
                .conn_id = (2ull << 32) | 7},
            "authentication failed from 192.0.2.10:52000 > invalid credential");
        acpp::Log::WriteConnection(acpp::LogLevel::DEBUG, uint64_t{0},
                                  "diagnostic without connection identity");
        const acpp::PanelLogContext panel{
            .name = "main panel", .host = "https://login:password@panel.example.com:8443/api?key=secret#private",
            .node_id = 1041, .type = "Vless"};
        acpp::Log::WritePanel(acpp::LogLevel::INFO, panel, "node ready");
        acpp::Log::WritePanel(acpp::LogLevel::WARN, panel, "panel request failed");
        acpp::Log::WriteConsole(acpp::LogLevel::ERROR, "fatal startup failure");
        acpp::Log::WriteConsole(acpp::LogLevel::INFO, "quoted \"value\"\\path\nnext");
        acpp::Log::WriteAccess("from 192.0.2.10:52000 accepted tcp:example.com:443 [vless-in -> direct] user:123");
        acpp::Log::WriteAccess("rejected invalid input\nforged-access\x1b");
        acpp::Log::Shutdown();

        const auto diagnostics = ReadLines(directory / "error.log");
        const auto access = ReadLines(directory / "access.log");
        for (const auto& line : diagnostics) CheckTimestamp(line);
        for (const auto& line : access) CheckTimestamp(line);
        const auto& escaped = FindLine(diagnostics, "diagnostic injection");
        Expect(escaped.find("\\nforged\\r\\t\\x1b\\x00") != std::string::npos,
               "diagnostic controls were not escaped");
        const auto& authenticated = FindLine(diagnostics, "authenticated outbound failure");
        Expect(authenticated.find("[4294967303]") != std::string::npos &&
               authenticated.find("[vless-in -> direct] user:123") != std::string::npos,
               "authenticated route or full worker connection identity was lost");
        const auto& rejected = FindLine(diagnostics, "authentication failed from");
        Expect(rejected.find("[8589934599]") != std::string::npos &&
               rejected.find("[vless-in]") != std::string::npos &&
               rejected.find("user:") == std::string::npos,
               "pre-authentication identity must not claim a user or collapse worker IDs");
        Expect(FindLine(diagnostics, "without connection identity").find("[0]") == std::string::npos,
               "missing connection identity must not be fabricated");
        Expect(Contains(diagnostics, "panel request failed") &&
               Contains(diagnostics, "fatal startup failure") &&
               !Contains(diagnostics, "node ready") && !Contains(diagnostics, "accepted tcp:"),
               "diagnostic file routing changed");
        Expect(access.size() == 2 && !Contains(access, "[Warning]") &&
               FindLine(access, "invalid input").find("\\nforged-access\\x1b") != std::string::npos,
               "access facts must stay separate and resist record injection");
        const auto console_text = console.text.str();
        Expect(console_text.find("time=\"") != std::string::npos &&
               console_text.find("level=info msg=\"node ready\"") != std::string::npos &&
               console_text.find("Host=\"https://panel.example.com:8443\" ID=1041 Name=\"main panel\" Type=Vless") != std::string::npos,
               "console panel identity or logfmt structure missing");
        Expect(console_text.find("msg=\"quoted \\\"value\\\"\\\\path\\nnext\"") != std::string::npos,
               "console quoted values must be escaped");
        Expect(console_text.find("authentication failed") == std::string::npos &&
               console_text.find("panel request failed") != std::string::npos &&
               errors.text.str().find("level=error msg=\"fatal startup failure\"") != std::string::npos,
               "console lifecycle/error routing changed");
        for (const auto secret : {"login", "password", "/api", "secret", "private"}) {
            Expect(console_text.find(secret) == std::string::npos &&
                   errors.text.str().find(secret) == std::string::npos &&
                   !Contains(diagnostics, secret), "panel URL credentials leaked");
        }

        Expect(acpp::Log::Init("warning", directory / "filtered", 1,
                              "access.log", "error.log", false, false),
               "filtered logger initialization failed");
        acpp::Log::WriteConsole(acpp::LogLevel::INFO, "hidden console event");
        acpp::Log::WriteSystem(acpp::LogLevel::DEBUG, "hidden diagnostic event");
        acpp::Log::WriteSystem(acpp::LogLevel::WARN, "visible warning");
        acpp::Log::WriteAccess("accepted despite diagnostic severity");
        acpp::Log::Shutdown();
        const auto filtered = ReadLines(directory / "filtered/error.log");
        Expect(filtered.size() == 1 && Contains(filtered, "visible warning") &&
               console.text.str().find("hidden console event") == std::string::npos,
               "configured severity must filter console and diagnostic records");
        Expect(Contains(ReadLines(directory / "filtered/access.log"), "accepted despite"),
               "diagnostic filtering must not discard access facts");

        Expect(acpp::Log::Init("none", directory / "disabled", 1,
                              "access.log", "error.log", false, false),
               "disabled logger initialization failed");
        LOG_CONSOLE_ERROR("hidden ordinary error");
        acpp::Log::WriteConsole(acpp::LogLevel::ERROR, "unconditional fatal startup failure");
        acpp::Log::WriteAccess("rejected despite disabled diagnostics");
        acpp::Log::Shutdown();
        Expect(ReadLines(directory / "disabled/error.log").empty() &&
               errors.text.str().find("hidden ordinary error") == std::string::npos &&
               errors.text.str().find("unconditional fatal startup failure") != std::string::npos,
               "fatal startup failures must remain visible without enabling ordinary diagnostics");
        Expect(Contains(ReadLines(directory / "disabled/access.log"), "rejected despite"),
               "disabled diagnostics must preserve access facts");
    } catch (const std::exception& error) {
        acpp::Log::Shutdown();
        std::filesystem::remove_all(directory);
        std::cerr << error.what() << '\n';
        return 1;
    }
    std::filesystem::remove_all(directory);
    return 0;
}
