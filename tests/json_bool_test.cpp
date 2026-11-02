#include "json_bool.hpp"

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
    return acpp::ParseJsonBool(
        parsed.as_object(), "camelFlag");
}

void CheckInvalid(std::string_view body) {
    auto result = Parse(body);
    Check(!result, "invalid JSON boolean was accepted");
}

}  // namespace

int main() {
    auto absent = Parse(R"({})");
    Check(absent.has_value() && !*absent, "absent boolean became configured");

    auto explicit_false = Parse(R"({"camelFlag":false})");
    Check(explicit_false.has_value() && explicit_false->has_value() &&
              !**explicit_false,
          "explicit false was lost");

    auto explicit_true = Parse(R"({"camelFlag":true})");
    Check(explicit_true.has_value() && **explicit_true,
          "explicit true was lost");

    CheckInvalid(R"({"camelFlag":"false"})");
    CheckInvalid(R"({"camelFlag":0})");
    CheckInvalid(R"({"camelFlag":null})");

    std::cout << "json_bool_test: ok\n";
    return 0;
}
