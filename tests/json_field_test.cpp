#include <gtest/gtest.h>

#include "infra/json.hpp"

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {


::json::object ParseObject(std::string_view body) {
    return ::json::parse(body).as_object();
}

TEST(JsonField, Bool) {
    const auto parse = [](std::string_view body) {
        return ::ParseJsonBool(ParseObject(body), "camelFlag");
    };

    auto absent = parse(R"({})");
    ASSERT_TRUE((absent.has_value() && !*absent)) << "absent boolean became configured";

    auto explicit_false = parse(R"({"camelFlag":false})");
    ASSERT_TRUE((explicit_false.has_value() && explicit_false->has_value() &&
              !**explicit_false)) << "explicit false was lost";

    auto explicit_true = parse(R"({"camelFlag":true})");
    ASSERT_TRUE((explicit_true.has_value() && **explicit_true)) << "explicit true was lost";

    ASSERT_TRUE((!parse(R"({"camelFlag":"false"})"))) << "string boolean was accepted";
    ASSERT_TRUE((!parse(R"({"camelFlag":0})"))) << "integer boolean was accepted";
    ASSERT_TRUE((!parse(R"({"camelFlag":null})"))) << "null boolean was accepted";
}

TEST(JsonField, String) {
    const auto parse = [](std::string_view body) {
        return ::ParseJsonString(ParseObject(body), "camelText");
    };
    const auto parse_array = [](std::string_view body) {
        return ::ParseJsonStringArray(ParseObject(body), "camelList");
    };

    auto absent = parse(R"({})");
    ASSERT_TRUE((absent.has_value() && !*absent)) << "absent string became configured";

    auto empty = parse(R"({"camelText":""})");
    ASSERT_TRUE((empty.has_value() && empty->has_value() && (**empty).empty())) << "explicit empty string was lost";

    auto value = parse(R"({"camelText":"value"})");
    ASSERT_TRUE((value.has_value() && **value == "value")) << "string value mismatch";

    ASSERT_TRUE((!parse(R"({"camelText":123})"))) << "integer string was accepted";
    ASSERT_TRUE((!parse(R"({"camelText":null})"))) << "null string was accepted";
    ASSERT_TRUE((!parse(R"({"camelText":false})"))) << "boolean string was accepted";

    auto absent_array = parse_array(R"({})");
    ASSERT_TRUE((absent_array.has_value() && !*absent_array)) << "absent string array became configured";

    auto empty_array = parse_array(R"({"camelList":[]})");
    ASSERT_TRUE((empty_array.has_value() && empty_array->has_value() &&
              (**empty_array).empty())) << "explicit empty string array was lost";

    auto array = parse_array(R"({"camelList":["one","two"]})");
    ASSERT_TRUE((array.has_value() && **array ==
              std::vector<std::string>({"one", "two"}))) << "string array value mismatch";

    ASSERT_TRUE((!parse_array(R"({"camelList":"one"})"))) << "scalar string array was accepted";
    ASSERT_TRUE((!parse_array(R"({"camelList":["one",2]})"))) << "mixed string array was accepted";
}

TEST(JsonField, Unsigned) {
    const auto parse = [](std::string_view body,
                          uint64_t maximum = std::numeric_limits<uint64_t>::max()) {
        return ::ParseJsonUint64(ParseObject(body), "camelValue", maximum);
    };

    auto absent = parse(R"({})");
    ASSERT_TRUE((absent.has_value() && !*absent)) << "absent value became configured";

    auto zero = parse(R"({"camelValue":0})");
    ASSERT_TRUE((zero.has_value() && zero->has_value() && **zero == 0)) << "explicit zero was lost";

    auto maximum = parse(R"({"camelValue":18446744073709551615})");
    ASSERT_TRUE((maximum.has_value() && **maximum ==
              std::numeric_limits<uint64_t>::max())) << "uint64 maximum was narrowed";

    ASSERT_TRUE((!parse(R"({"camelValue":101})", 100))) << "configured upper bound was ignored";
    ASSERT_TRUE((!parse(R"({"camelValue":"60000"})"))) << "string integer was accepted";
    ASSERT_TRUE((!parse(R"({"camelValue":-1})"))) << "negative integer was accepted";
    ASSERT_TRUE((!parse(R"({"camelValue":1.5})"))) << "fractional number was accepted";
}

TEST(JsonField, Port) {
    using ::JsonPortError;
    using ::ReadJsonPort;
    using ::json::object;

    auto result = ReadJsonPort(object{}, "port");
    ASSERT_TRUE((result.error == JsonPortError::Missing && result.value == 0)) << "absent port became configured";

    result = ReadJsonPort(object{{"port", int64_t{1}}}, "port");
    ASSERT_TRUE((result.Valid() && result.value == 1)) << "minimum port mismatch";

    result = ReadJsonPort(object{{"port", uint64_t{65535}}}, "port");
    ASSERT_TRUE((result.Valid() && result.value == 65535)) << "maximum port mismatch";

    for (const auto& out_of_range : {
             object{{"port", int64_t{0}}},
             object{{"port", int64_t{-1}}},
             object{{"port", uint64_t{65536}}},
             object{{"port", std::numeric_limits<uint64_t>::max()}}}) {
        ASSERT_TRUE((ReadJsonPort(out_of_range, "port").error == JsonPortError::OutOfRange)) << "out-of-range port was not classified as OutOfRange";
    }

    ASSERT_TRUE((ReadJsonPort(object{{"port", 443.0}}, "port").error ==
              JsonPortError::InvalidType)) << "fractional port was not classified as InvalidType";
    ASSERT_TRUE((ReadJsonPort(object{{"port", "443"}}, "port").error ==
              JsonPortError::InvalidType)) << "string port was not classified as InvalidType";
}


TEST(JsonField, ThrowingFallbacks) {
    const auto source = ParseObject(R"({"text":"set","flag":false,"bad":1})");

    ASSERT_TRUE((::JsonStringOr(source, "text", "fallback") == "set")) << "present string was replaced by fallback";
    ASSERT_TRUE((::JsonStringOr(source, "missing", "fallback") == "fallback")) << "absent string did not use fallback";
    EXPECT_THROW((void)::JsonStringOr(source, "bad", "fallback"), std::invalid_argument);

    ASSERT_TRUE((!::JsonBoolOr(source, "flag", true))) << "present boolean was replaced by fallback";
    ASSERT_TRUE((::JsonBoolOr(source, "missing", true))) << "absent boolean did not use fallback";
    EXPECT_THROW((void)::JsonBoolOr(source, "bad", true), std::invalid_argument);
}

}  // namespace

