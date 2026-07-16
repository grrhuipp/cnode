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
    return acpp::ParseAliasedJsonBool(
        parsed.as_object(), {"camelFlag", "snake_flag"});
}

void CheckInvalid(std::string_view body, std::string_view cause) {
    auto result = Parse(body);
    Check(!result, "invalid JSON boolean was accepted");
    Check(result.error().find(cause) != std::string::npos,
          "JSON boolean error lost its cause");
}

}  // namespace

int main() {
    auto absent = Parse(R"({})");
    Check(absent.has_value() && !*absent, "absent boolean became configured");

    auto explicit_false = Parse(R"({"camelFlag":false})");
    Check(explicit_false.has_value() && explicit_false->has_value() &&
              !**explicit_false,
          "explicit false was lost");

    auto explicit_true = Parse(R"({"snake_flag":true})");
    Check(explicit_true.has_value() && **explicit_true,
          "explicit true was lost");

    auto equal_aliases = Parse(
        R"({"camelFlag":false,"snake_flag":false})");
    Check(equal_aliases.has_value() && equal_aliases->has_value() &&
              !**equal_aliases,
          "equal boolean aliases were rejected");

    CheckInvalid(R"({"camelFlag":"false"})", "must be a boolean");
    CheckInvalid(R"({"camelFlag":0})", "must be a boolean");
    CheckInvalid(R"({"camelFlag":null})", "must be a boolean");
    CheckInvalid(
        R"({"camelFlag":true,"snake_flag":false})", "must match");

    std::cout << "json_bool_test: ok\n";
    return 0;
}
