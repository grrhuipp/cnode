#include "anytls_outbound_settings.hpp"

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
    return acpp::proxy::anytls::outbound::ParseSettings(parsed.as_object());
}

void CheckInvalid(std::string_view body, std::string_view cause) {
    auto result = Parse(body);
    Check(!result, "invalid AnyTLS settings were accepted");
    Check(result.error().find(cause) != std::string::npos,
          "AnyTLS settings error lost its cause");
}

void TestValidSettingsAreNormalized() {
    auto defaults = Parse(
        R"({"server":"127.0.0.1","server_port":443,"password":"secret"})");
    Check(defaults.has_value(), "default AnyTLS settings were rejected");
    Check(defaults->idle_session_check_interval.count() == 30,
          "default check interval mismatch");
    Check(defaults->idle_session_timeout.count() == 60,
          "default idle timeout mismatch");
    Check(defaults->min_idle_sessions == 0, "default minimum idle mismatch");
    Check(defaults->literal_address.has_value(), "literal address was not cached");

    auto explicit_values = Parse(
        R"({"address":"example.com","port":8443,"key":"secret","idleSessionCheckInterval":10,"idle_session_check_interval":10,"idleSessionTimeout":20,"minIdleSession":2})");
    Check(explicit_values.has_value(), "valid explicit AnyTLS settings were rejected");
    Check(explicit_values->idle_session_check_interval.count() == 10,
          "explicit check interval mismatch");
    Check(explicit_values->idle_session_timeout.count() == 20,
          "explicit idle timeout mismatch");
    Check(explicit_values->min_idle_sessions == 2,
          "explicit minimum idle mismatch");
}

void TestInvalidSessionSettingsAreRejected() {
    CheckInvalid(
        R"({"server":"example.com","server_port":443,"password":"secret","idleSessionCheckInterval":"30"})",
        "must be an integer");
    CheckInvalid(
        R"({"server":"example.com","server_port":443,"password":"secret","idleSessionTimeout":0})",
        "must be positive");
    CheckInvalid(
        R"({"server":"example.com","server_port":443,"password":"secret","idleSessionTimeout":18446744073709551615})",
        "exceeds the seconds range");
    CheckInvalid(
        R"({"server":"example.com","server_port":443,"password":"secret","minIdleSession":-1})",
        "must not be negative");
    CheckInvalid(
        R"({"server":"example.com","server_port":443,"password":"secret","minIdleSession":"1"})",
        "must be an integer");
    CheckInvalid(
        R"({"server":"example.com","server_port":443,"password":"secret","idleSessionTimeout":60,"idle_session_timeout":61})",
        "must match");
}

}  // namespace

int main() {
    TestValidSettingsAreNormalized();
    TestInvalidSessionSettingsAreRejected();
    std::cout << "anytls_outbound_settings_test: ok\n";
    return 0;
}
