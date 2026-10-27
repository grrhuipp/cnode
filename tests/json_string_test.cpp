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
    return acpp::ParseJsonString(
        parsed.as_object(), "camelText");
}

auto ParseArray(std::string_view body) {
    const auto parsed = acpp::json::parse(body);
    return acpp::ParseJsonStringArray(
        parsed.as_object(), "camelList");
}

void CheckInvalid(std::string_view body, std::string_view cause) {
    auto result = Parse(body);
    Check(!result, "invalid JSON string was accepted");
    Check(result.error().find(cause) != std::string::npos,
          "JSON string error lost its cause");
}

void CheckInvalidArray(std::string_view body, std::string_view cause) {
    auto result = ParseArray(body);
    Check(!result, "invalid JSON string array was accepted");
    Check(result.error().find(cause) != std::string::npos,
          "JSON string array error lost its cause");
}

void CheckParseError(std::string_view body) {
    try {
        (void)acpp::json::parse(body);
    } catch (const acpp::json::parse_error&) {
        return;
    }
    Fail("invalid JSON unicode escape was accepted");
}

}  // namespace

int main() {
    auto absent = Parse(R"({})");
    Check(absent.has_value() && !*absent, "absent string became configured");

    auto empty = Parse(R"({"camelText":""})");
    Check(empty.has_value() && empty->has_value() && (**empty).empty(),
          "explicit empty string was lost");

    auto value = Parse(R"({"camelText":"value"})");
    Check(value.has_value() && **value == "value", "string value mismatch");

    CheckInvalid(R"({"camelText":123})", "must be a string");
    CheckInvalid(R"({"camelText":null})", "must be a string");
    CheckInvalid(R"({"camelText":false})", "must be a string");

    auto absent_array = ParseArray(R"({})");
    Check(absent_array.has_value() && !*absent_array,
          "absent string array became configured");

    auto empty_array = ParseArray(R"({"camelList":[]})");
    Check(empty_array.has_value() && empty_array->has_value() &&
              (**empty_array).empty(),
          "explicit empty string array was lost");

    auto array = ParseArray(R"({"camelList":["one","two"]})");
    Check(array.has_value() && **array ==
              std::vector<std::string>({"one", "two"}),
          "string array value mismatch");

    CheckInvalidArray(R"({"camelList":"one"})", "array of strings");
    CheckInvalidArray(R"({"camelList":["one",2]})", "only strings");

    const auto supplementary = acpp::json::parse(R"("\uD83D\uDE00")");
    Check(supplementary.as_string() == "\xF0\x9F\x98\x80",
          "unicode surrogate pair was not decoded as one code point");
    CheckParseError(R"("\uD83D")");
    CheckParseError(R"("\uDE00")");

    std::cout << "json_string_test: ok\n";
    return 0;
}
