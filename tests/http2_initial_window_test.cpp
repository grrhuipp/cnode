#include "http2_initial_window.hpp"
#include "http2_settings.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) Fail(message);
}

auto Parse(std::string_view body) {
    const auto parsed = acpp::json::parse(body);
    return acpp::ParseHttp2InitialWindow(parsed.as_object());
}

void CheckInvalid(std::string_view body, std::string_view cause) {
    auto result = Parse(body);
    Check(!result, "invalid HTTP/2 initial window was accepted");
    Check(result.error().find(cause) != std::string::npos,
          "HTTP/2 initial window error lost its cause");
}

}  // namespace

int main() {
    auto absent = Parse(R"({})");
    Check(absent.has_value() && !*absent, "absent window became configured");

    auto zero = Parse(R"({"initialWindowSize":0})");
    Check(zero.has_value() && zero->has_value() && **zero == 0,
          "explicit zero window was lost");

    auto maximum = Parse(R"({"initial_window_size":2147483647})");
    Check(maximum.has_value() && **maximum == acpp::kHttp2MaxInitialWindow,
          "maximum window mismatch");

    auto equal_aliases = Parse(
        R"({"initialWindowSize":65535,"initial_window_size":65535})");
    Check(equal_aliases.has_value() && **equal_aliases == 65535,
          "equal window aliases were rejected");

    CheckInvalid(R"({"initialWindowSize":"65535"})", "must be an integer");
    CheckInvalid(R"({"initialWindowSize":-1})", "between 0 and");
    CheckInvalid(R"({"initialWindowSize":2147483648})", "between 0 and");
    CheckInvalid(R"({"initialWindowSize":1.5})", "must be an integer");
    CheckInvalid(
        R"({"initialWindowSize":65535,"initial_window_size":65536})",
        "must match");

    const auto zero_setting =
        acpp::transport::internet::EncodeInitialWindowSetting(0);
    Check(zero_setting.size() == 6 && zero_setting[0] == 0 &&
              zero_setting[1] == 4 && zero_setting[2] == 0 &&
              zero_setting[3] == 0 && zero_setting[4] == 0 &&
              zero_setting[5] == 0,
          "explicit zero window was omitted from SETTINGS");

    const auto max_setting =
        acpp::transport::internet::EncodeInitialWindowSetting(
            acpp::kHttp2MaxInitialWindow);
    Check(max_setting.size() == 6 && max_setting[2] == 0x7f &&
              max_setting[3] == 0xff && max_setting[4] == 0xff &&
              max_setting[5] == 0xff,
          "maximum window SETTINGS payload mismatch");
    std::cout << "http2_initial_window_test: ok\n";
    return 0;
}
