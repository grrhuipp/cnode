#include "json_unsigned.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) Fail(message);
}

auto Parse(std::string_view body, uint64_t maximum =
               std::numeric_limits<uint64_t>::max()) {
    const auto parsed = acpp::json::parse(body);
    return acpp::ParseAliasedJsonUint64(
        parsed.as_object(), {"camelValue", "snake_value"}, maximum);
}

void CheckInvalid(std::string_view body, std::string_view cause) {
    auto result = Parse(body);
    Check(!result, "invalid unsigned JSON value was accepted");
    Check(result.error().find(cause) != std::string::npos,
          "unsigned JSON error lost its cause");
}

}  // namespace

int main() {
    auto absent = Parse(R"({})");
    Check(absent.has_value() && !*absent, "absent value became configured");

    auto zero = Parse(R"({"camelValue":0})");
    Check(zero.has_value() && zero->has_value() && **zero == 0,
          "explicit zero was lost");

    auto maximum = Parse(R"({"snake_value":18446744073709551615})");
    Check(maximum.has_value() && **maximum ==
              std::numeric_limits<uint64_t>::max(),
          "uint64 maximum was narrowed");

    auto equal_aliases = Parse(
        R"({"camelValue":60000,"snake_value":60000})");
    Check(equal_aliases.has_value() && **equal_aliases == 60000,
          "equal aliases were rejected");

    auto bounded = Parse(R"({"camelValue":101})", 100);
    Check(!bounded && bounded.error().find("between 0 and 100") !=
                          std::string::npos,
          "configured upper bound was ignored");

    CheckInvalid(R"({"camelValue":"60000"})", "must be an integer");
    CheckInvalid(R"({"camelValue":-1})", "between 0 and");
    CheckInvalid(R"({"camelValue":1.5})", "must be an integer");
    CheckInvalid(R"({"camelValue":1,"snake_value":2})", "must match");

    std::cout << "json_unsigned_test: ok\n";
    return 0;
}
