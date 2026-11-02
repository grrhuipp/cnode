#include "online_report.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

}  // namespace

int main() {
    std::vector<acpp::api::OnlineUser> devices{
        {.UID = 7, .IP = "203.0.113.2"},
        {.UID = 7, .IP = "203.0.113.1"},
        {.UID = 7, .IP = "203.0.113.1"},
        {.UID = 8, .IP = "203.0.113.8"},
        {.UID = 0, .IP = "203.0.113.9"},
    };

    auto report = acpp::api::v2board::BuildOnlineReportPayload(devices, 42);
    Check(report.user_count == 2, "online report did not count unique UIDs");
    Check(report.device_count == 3, "online report did not deduplicate devices");
    Check(report.alive_body.size() == 2, "alive payload user count mismatch");

    const auto& uid7_alive = report.alive_body.at("7").as_array();
    Check(uid7_alive.size() == 2, "alive payload lost a user IP");
    Check(uid7_alive[0].as_string() == "203.0.113.1_42",
          "alive payload is not deterministic");
    Check(uid7_alive[1].as_string() == "203.0.113.2_42",
          "alive payload node suffix mismatch");

    auto empty = acpp::api::v2board::BuildOnlineReportPayload({}, 42);
    Check(empty.user_count == 0 && empty.device_count == 0,
          "empty online snapshot did not report zero");
    Check(empty.alive_body.empty(),
          "empty online snapshot did not build an empty device payload");

    std::cout << "v2board_online_report_test: ok\n";
    return 0;
}
