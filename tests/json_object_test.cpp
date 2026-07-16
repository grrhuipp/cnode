#include "acppnode/infra/json_object.hpp"

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

struct ParsedObject {
    acpp::json::value source;
    std::expected<const acpp::json::object*, std::string> result;

    explicit ParsedObject(std::string_view body)
        : source(acpp::json::parse(body)),
          result(acpp::ParseAliasedJsonObject(
              source.as_object(), {"camelObject", "snake_object"})) {}
};

void CheckInvalid(std::string_view body, std::string_view cause) {
    ParsedObject parsed(body);
    Check(!parsed.result, "invalid JSON object was accepted");
    Check(parsed.result.error().find(cause) != std::string::npos,
          "JSON object error lost its cause");
}

}  // namespace

int main() {
    ParsedObject absent(R"({})");
    Check(absent.result.has_value() && *absent.result == nullptr,
          "absent object became configured");

    ParsedObject object(R"({"snake_object":{"value":1}})");
    Check(object.result.has_value() && *object.result != nullptr &&
              (*object.result)->at("value").as_int64() == 1,
          "object value mismatch");

    ParsedObject equal_aliases(
        R"({"camelObject":{"value":1},"snake_object":{"value":1}})");
    Check(equal_aliases.result.has_value() && *equal_aliases.result != nullptr,
          "equal object aliases were rejected");

    ParsedObject equal_nested_aliases(
        R"({"camelObject":{"nested":[true,{"text":"same"}]},"snake_object":{"nested":[true,{"text":"same"}]}})");
    Check(equal_nested_aliases.result.has_value() &&
              *equal_nested_aliases.result != nullptr,
          "equal nested object aliases were rejected");

    CheckInvalid(R"({"camelObject":[]})", "must be an object");
    CheckInvalid(R"({"camelObject":null})", "must be an object");
    CheckInvalid(
        R"({"camelObject":{"value":1},"snake_object":{"value":2}})",
        "must match");
    CheckInvalid(
        R"({"camelObject":{"nested":[1,2]},"snake_object":{"nested":[1,3]}})",
        "must match");

    std::cout << "json_object_test: ok\n";
    return 0;
}
