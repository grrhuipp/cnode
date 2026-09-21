#include "acppnode/infra/log.hpp"

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

struct SessionLogContext {
    struct {
        std::string_view tag;
        int64_t user_id = 0;
    } inbound;
    uint64_t conn_id = 0;
};

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
            acpp::ConnectionLogContext{.conn_id = 42, .inbound_tag = {}, .user_id = 0},
            "dialing tcp:example.com:443");
        acpp::Log::WriteConnection(
            acpp::LogLevel::WARN,
            SessionLogContext{
                .inbound = {
                    .tag = "jx-ss-shadowsocks-50006",
                    .user_id = 502345929,
                },
                .conn_id = 43,
            },
            "failed to process outbound traffic 192.0.2.10 -> www.sina.com.cn:8080 via direct > connection refused");
        acpp::Log::WriteConnection(
            acpp::LogLevel::WARN,
            SessionLogContext{
                .inbound = {
                    .tag = "jx-ss-shadowsocks-50006",
                    .user_id = 0,
                },
                .conn_id = 44,
            },
            "invalid user");
        acpp::Log::WriteConnection(
            acpp::LogLevel::WARN,
            acpp::ConnectionLogContext{
                .conn_id = (1ull << 32) | 7,
                .inbound_tag = {},
                .user_id = 0},
            "failed to dial example.com:443 > connection refused");
        acpp::Log::WriteAccess(
            "from tcp:192.0.2.10:52000 accepted tcp:example.com:443 "
            "[vless-in -> direct] email: user@example.com");

        std::ostringstream console;
        auto* previous = std::cout.rdbuf(console.rdbuf());
        acpp::Log::WriteConsole(
            acpp::LogLevel::INFO, "Panel jx/1 status: ready");
        std::cout.rdbuf(previous);

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

        const auto& authenticated =
            FindLine(error_lines, "failed to process outbound traffic");
        CheckTimestamp(authenticated);
        Expect(authenticated.find(" [Warning] [43] ") != std::string::npos,
               "authenticated connection context missing");
        Expect(authenticated.find(
                   ": inbound=jx-ss-shadowsocks-50006 user=502345929 "
                   "failed to process outbound traffic 192.0.2.10 -> "
                   "www.sina.com.cn:8080 via direct > connection refused") !=
                   std::string::npos,
               "authenticated connection identity or route fields missing");

        const auto& unauthenticated =
            FindLine(error_lines, "invalid user");
        CheckTimestamp(unauthenticated);
        Expect(unauthenticated.find(" [Warning] [44] ") != std::string::npos,
               "pre-authentication connection format changed");
        Expect(unauthenticated.find(": invalid user") != std::string::npos,
               "pre-authentication message format changed");
        Expect(unauthenticated.find(" user=") == std::string::npos,
               "pre-authentication log exposed an invalid user id");

        const auto& packed =
            FindLine(error_lines, "failed to dial example.com:443");
        Expect(packed.find(" [Warning] [7] ") != std::string::npos,
               "connection id must log the short session sequence");
        Expect(packed.find("[4294967303]") == std::string::npos,
               "connection id must not log the packed worker-local value");

        const auto console_text = console.str();
        Expect(console_text.find("[Info] Panel jx/1 status: ready") !=
                   std::string::npos,
               "console log missing panel status");
        Expect(console_text.find("log_format_test") == std::string::npos,
               "console log must not include source component");

        const auto access_lines = ReadLines(directory / "access.log");
        Expect(access_lines.size() == 1, "access logger wrote diagnostics");
        CheckTimestamp(access_lines.front());
        Expect(access_lines.front().find(
                   " from tcp:192.0.2.10:52000 accepted tcp:example.com:443 "
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
