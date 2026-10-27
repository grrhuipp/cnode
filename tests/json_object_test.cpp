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
          result(acpp::ParseJsonObject(
              source.as_object(), "camelObject")) {}
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

    ParsedObject object(R"({"camelObject":{"value":1}})");
    Check(object.result.has_value() && *object.result != nullptr &&
              (*object.result)->at("value").as_int64() == 1,
          "object value mismatch");

    ParsedObject ignored_other(R"({"otherObject":{"value":1}})");
    Check(ignored_other.result.has_value() && *ignored_other.result == nullptr,
          "unrelated object key was matched");

    CheckInvalid(R"({"camelObject":[]})", "must be an object");
    CheckInvalid(R"({"camelObject":null})", "must be an object");

    std::cout << "json_object_test: ok\n";
    return 0;
}
