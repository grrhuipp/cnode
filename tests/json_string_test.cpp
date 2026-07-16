#include "json_string.hpp"

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
    return acpp::ParseAliasedJsonString(
        parsed.as_object(), {"camelText", "snake_text"});
}

void CheckInvalid(std::string_view body, std::string_view cause) {
    auto result = Parse(body);
    Check(!result, "invalid JSON string was accepted");
    Check(result.error().find(cause) != std::string::npos,
          "JSON string error lost its cause");
}

}  // namespace

int main() {
    auto absent = Parse(R"({})");
    Check(absent.has_value() && !*absent, "absent string became configured");

    auto empty = Parse(R"({"camelText":""})");
    Check(empty.has_value() && empty->has_value() && (**empty).empty(),
          "explicit empty string was lost");

    auto value = Parse(R"({"snake_text":"value"})");
    Check(value.has_value() && **value == "value", "string value mismatch");

    auto equal_aliases = Parse(
        R"({"camelText":"same","snake_text":"same"})");
    Check(equal_aliases.has_value() && **equal_aliases == "same",
          "equal string aliases were rejected");

    CheckInvalid(R"({"camelText":123})", "must be a string");
    CheckInvalid(R"({"camelText":null})", "must be a string");
    CheckInvalid(R"({"camelText":false})", "must be a string");
    CheckInvalid(
        R"({"camelText":"one","snake_text":"two"})", "must match");

    std::cout << "json_string_test: ok\n";
    return 0;
}
