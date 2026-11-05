#include "acppnode/infra/json_field.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) Fail(message);
}

acpp::json::object ParseObject(std::string_view body) {
    return acpp::json::parse(body).as_object();
}

void CheckBool() {
    const auto parse = [](std::string_view body) {
        return acpp::ParseJsonBool(ParseObject(body), "camelFlag");
    };

    auto absent = parse(R"({})");
    Check(absent.has_value() && !*absent, "absent boolean became configured");

    auto explicit_false = parse(R"({"camelFlag":false})");
    Check(explicit_false.has_value() && explicit_false->has_value() &&
              !**explicit_false,
          "explicit false was lost");

    auto explicit_true = parse(R"({"camelFlag":true})");
    Check(explicit_true.has_value() && **explicit_true,
          "explicit true was lost");

    Check(!parse(R"({"camelFlag":"false"})"), "string boolean was accepted");
    Check(!parse(R"({"camelFlag":0})"), "integer boolean was accepted");
    Check(!parse(R"({"camelFlag":null})"), "null boolean was accepted");
}

void CheckString() {
    const auto parse = [](std::string_view body) {
        return acpp::ParseJsonString(ParseObject(body), "camelText");
    };
    const auto parse_array = [](std::string_view body) {
        return acpp::ParseJsonStringArray(ParseObject(body), "camelList");
    };

    auto absent = parse(R"({})");
    Check(absent.has_value() && !*absent, "absent string became configured");

    auto empty = parse(R"({"camelText":""})");
    Check(empty.has_value() && empty->has_value() && (**empty).empty(),
          "explicit empty string was lost");

    auto value = parse(R"({"camelText":"value"})");
    Check(value.has_value() && **value == "value", "string value mismatch");

    Check(!parse(R"({"camelText":123})"), "integer string was accepted");
    Check(!parse(R"({"camelText":null})"), "null string was accepted");
    Check(!parse(R"({"camelText":false})"), "boolean string was accepted");

    auto absent_array = parse_array(R"({})");
    Check(absent_array.has_value() && !*absent_array,
          "absent string array became configured");

    auto empty_array = parse_array(R"({"camelList":[]})");
    Check(empty_array.has_value() && empty_array->has_value() &&
              (**empty_array).empty(),
          "explicit empty string array was lost");

    auto array = parse_array(R"({"camelList":["one","two"]})");
    Check(array.has_value() && **array ==
              std::vector<std::string>({"one", "two"}),
          "string array value mismatch");

    Check(!parse_array(R"({"camelList":"one"})"), "scalar string array was accepted");
    Check(!parse_array(R"({"camelList":["one",2]})"), "mixed string array was accepted");
}

void CheckUnsigned() {
    const auto parse = [](std::string_view body,
                          uint64_t maximum = std::numeric_limits<uint64_t>::max()) {
        return acpp::ParseJsonUint64(ParseObject(body), "camelValue", maximum);
    };

    auto absent = parse(R"({})");
    Check(absent.has_value() && !*absent, "absent value became configured");

    auto zero = parse(R"({"camelValue":0})");
    Check(zero.has_value() && zero->has_value() && **zero == 0,
          "explicit zero was lost");

    auto maximum = parse(R"({"camelValue":18446744073709551615})");
    Check(maximum.has_value() && **maximum ==
              std::numeric_limits<uint64_t>::max(),
          "uint64 maximum was narrowed");

    Check(!parse(R"({"camelValue":101})", 100), "configured upper bound was ignored");
    Check(!parse(R"({"camelValue":"60000"})"), "string integer was accepted");
    Check(!parse(R"({"camelValue":-1})"), "negative integer was accepted");
    Check(!parse(R"({"camelValue":1.5})"), "fractional number was accepted");
}

void CheckPort() {
    using acpp::JsonPortError;
    using acpp::ReadJsonPort;
    using acpp::json::object;

    auto result = ReadJsonPort(object{}, "port");
    Check(result.error == JsonPortError::Missing && result.value == 0,
          "absent port became configured");

    result = ReadJsonPort(object{{"port", int64_t{1}}}, "port");
    Check(result.Valid() && result.value == 1, "minimum port mismatch");

    result = ReadJsonPort(object{{"port", uint64_t{65535}}}, "port");
    Check(result.Valid() && result.value == 65535, "maximum port mismatch");

    for (const auto& out_of_range : {
             object{{"port", int64_t{0}}},
             object{{"port", int64_t{-1}}},
             object{{"port", uint64_t{65536}}},
             object{{"port", std::numeric_limits<uint64_t>::max()}}}) {
        Check(ReadJsonPort(out_of_range, "port").error == JsonPortError::OutOfRange,
              "out-of-range port was not classified as OutOfRange");
    }

    Check(ReadJsonPort(object{{"port", 443.0}}, "port").error ==
              JsonPortError::InvalidType,
          "fractional port was not classified as InvalidType");
    Check(ReadJsonPort(object{{"port", "443"}}, "port").error ==
              JsonPortError::InvalidType,
          "string port was not classified as InvalidType");
}

template <typename Read>
bool Throws(Read read) {
    try {
        (void)read();
    } catch (const std::invalid_argument&) {
        return true;
    }
    return false;
}

void CheckThrowingFallbacks() {
    const auto source = ParseObject(R"({"text":"set","flag":false,"bad":1})");

    Check(acpp::JsonStringOr(source, "text", "fallback") == "set",
          "present string was replaced by fallback");
    Check(acpp::JsonStringOr(source, "missing", "fallback") == "fallback",
          "absent string did not use fallback");
    Check(Throws([&] { return acpp::JsonStringOr(source, "bad", "fallback"); }),
          "wrongly typed string fell back instead of failing");

    Check(!acpp::JsonBoolOr(source, "flag", true),
          "present boolean was replaced by fallback");
    Check(acpp::JsonBoolOr(source, "missing", true),
          "absent boolean did not use fallback");
    Check(Throws([&] { return acpp::JsonBoolOr(source, "bad", true); }),
          "wrongly typed boolean fell back instead of failing");
}

}  // namespace

int main() {
    CheckBool();
    CheckString();
    CheckUnsigned();
    CheckPort();
    CheckThrowingFallbacks();

    std::cout << "json_field_test: ok\n";
    return 0;
}
