#include <stdexcept>
#include <gtest/gtest.h>

#include "http2_initial_window.hpp"
#include "http2_settings.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

void Check(bool condition, std::string_view message) {
    if (!condition) Fail(message);
}

auto Parse(std::string_view body) {
    const auto parsed = ::json::parse(body);
    return ::ParseHttp2InitialWindow(parsed.as_object());
}

void CheckInvalid(std::string_view body) {
    auto result = Parse(body);
    Check(!result, "invalid HTTP/2 initial window was accepted");
}

}  // namespace

TEST(Http2InitialWindow, Contract) {
    auto absent = Parse(R"({})");
    Check(absent.has_value() && !*absent, "absent window became configured");

    auto zero = Parse(R"({"initialWindowSize":0})");
    Check(zero.has_value() && zero->has_value() && **zero == 0,
          "explicit zero window was lost");

    auto maximum = Parse(R"({"initialWindowSize":2147483647})");
    Check(maximum.has_value() && **maximum == ::kHttp2MaxInitialWindow,
          "maximum window mismatch");

    CheckInvalid(R"({"initialWindowSize":"65535"})");
    CheckInvalid(R"({"initialWindowSize":-1})");
    CheckInvalid(R"({"initialWindowSize":2147483648})");
    CheckInvalid(R"({"initialWindowSize":1.5})");

    const auto zero_setting =
        ::transport::internet::EncodeInitialWindowSetting(0);
    Check(zero_setting.size() == 6 && zero_setting[0] == 0 &&
              zero_setting[1] == 4 && zero_setting[2] == 0 &&
              zero_setting[3] == 0 && zero_setting[4] == 0 &&
              zero_setting[5] == 0,
          "explicit zero window was omitted from SETTINGS");

    const auto max_setting =
        ::transport::internet::EncodeInitialWindowSetting(
            ::kHttp2MaxInitialWindow);
    Check(max_setting.size() == 6 && max_setting[2] == 0x7f &&
              max_setting[3] == 0xff && max_setting[4] == 0xff &&
              max_setting[5] == 0xff,
          "maximum window SETTINGS payload mismatch");
    std::cout << "http2_initial_window_test: ok\n";
}
