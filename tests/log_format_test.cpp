#include "acppnode/infra/json.hpp"
#include "acppnode/infra/log.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void Expect(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

acpp::json::object ReadRecord(const std::filesystem::path& path,
                              std::string_view expected_event) {
    std::ifstream input(path);
    std::string line;
    while (std::getline(input, line)) {
        Expect(!line.empty(), "blank line in JSON Lines output");
        auto record = acpp::json::parse(line).as_object();
        if (record.at("event").as_string() == expected_event) {
            return record;
        }
    }
    throw std::runtime_error("missing expected log event");
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
            "quoted=\"value\" newline=first\nsecond",
            "test.system");
        acpp::Log::WriteConnection(
            acpp::LogLevel::INFO,
            acpp::ConnectionLogContext{
                .conn_id = 42,
                .worker_id = 3,
                .inbound = "vmess-main",
            },
            "target=example.com:443",
            "connection.accepted");
        acpp::Log::Shutdown();

        const auto system = ReadRecord(directory / "error.log", "test.system");
        Expect(system.at("channel").as_string() == "system", "system channel");
        Expect(system.at("level").as_string() == "warn", "system level");
        Expect(system.at("event").as_string() == "test.system", "system event");
        Expect(system.at("message").as_string().find('\n') != std::string::npos,
               "escaped newline did not round-trip");
        Expect(system.at("timestamp").as_string().ends_with('Z'), "UTC timestamp");
        Expect(system.contains("component"), "component missing");
        Expect(system.contains("source_line"), "source line missing");

        const auto connection = ReadRecord(
            directory / "access.log", "connection.accepted");
        Expect(connection.at("channel").as_string() == "connection",
               "connection channel");
        Expect(connection.at("event").as_string() == "connection.accepted",
               "connection event");
        Expect(connection.at("conn_id").as_int64() == 42, "connection id");
        Expect(connection.at("worker_id").as_int64() == 3, "worker id");
        Expect(connection.at("inbound").as_string() == "vmess-main", "inbound");
    } catch (const std::exception& error) {
        acpp::Log::Shutdown();
        std::filesystem::remove_all(directory);
        std::cerr << error.what() << '\n';
        return 1;
    } catch (...) {
        acpp::Log::Shutdown();
        std::filesystem::remove_all(directory);
        std::cerr << "unknown log format test failure\n";
        return 1;
    }

    std::filesystem::remove_all(directory);
    return 0;
}
