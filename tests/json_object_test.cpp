#include <stdexcept>
#include <gtest/gtest.h>

#include "infra/json_field.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>
#include <utility>

namespace {

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

void Check(bool condition, std::string_view message) {
    if (!condition) Fail(message);
}

struct ParsedObject {
    ::json::value source;
    tl::expected<const ::json::object*, std::string> result;

    explicit ParsedObject(std::string_view body)
        : source(::json::parse(body)),
          result(::ParseJsonObject(
              source.as_object(), "camelObject")) {}
};

void CheckInvalid(std::string_view body) {
    ParsedObject parsed(body);
    Check(!parsed.result, "invalid JSON object was accepted");
}

using ::json::KeyComparison;

void CheckKeyComparisonModes() {
    const auto insensitive = ::json::parse(
        R"({"CaMeLKey":1,"camel_key":2,"\u00c4":3,"\u00e4":4})",
        KeyComparison::AsciiCaseInsensitive);
    const auto& object = insensitive.as_object();
    Check(object.contains("CAMELKEY") && object.at("camelKey").as_int64() == 1,
          "ASCII case-insensitive lookup failed");
    Check(object.at("CAMEL_KEY").as_int64() == 2 && object.size() == 4,
          "underscores or non-ASCII characters were folded");
    Check(object.at("\xc3\x84").as_int64() == 3 &&
              object.at("\xc3\xa4").as_int64() == 4,
          "non-ASCII keys lost their distinct values");
    const std::string_view bounded_key = "xCAMELKEYx";
    Check(object.if_contains(bounded_key.substr(1, 8)) != nullptr,
          "heterogeneous lookup required a null-terminated string");
    Check(!object.contains("camel") && !object.contains("camelKeyExtra") &&
              !object.contains("missing"),
          "key comparison accepted a prefix or unrelated key");

    for (const auto& sensitive : {
             ::json::parse(R"({"CaMeLKey":1,"camelKey":2})"),
             ::json::parse(R"({"CaMeLKey":1,"camelKey":2})",
                               KeyComparison::CaseSensitive)}) {
        Check(sensitive.as_object().size() == 2 &&
                  sensitive.as_object().at("CaMeLKey").as_int64() == 1 &&
                  sensitive.as_object().at("camelKey").as_int64() == 2 &&
                  !sensitive.as_object().contains("CAMELKEY"),
              "case-insensitive parsing leaked into ordinary JSON");
    }
    ::json::object constructed;
    constructed["Key"] = 1;
    constructed["key"] = 2;
    const ::json::object initialized{{"Key", 1}, {"key", 2}};
    Check(constructed.size() == 2 && initialized.size() == 2,
          "ordinary object construction became case-insensitive");
}

void CheckNestedKeyComparison() {
    auto parsed = ::json::parse(
        R"({"SeTTings":{"PaNeLs":[{"DeEp":{"VaLuE":"UnChanged"}}]},"Empty":{}})",
        KeyComparison::AsciiCaseInsensitive);
    auto* settings = parsed.as_object().if_contains("settings");
    Check(settings != nullptr, "mutable case-insensitive lookup failed");
    auto& panels = settings->as_object().at("PANELS").as_array();
    auto& deep = panels[0].as_object().at("deep").as_object();
    deep["VALUE"] = "UpdatedValue";
    Check(deep.size() == 1 && deep.begin()->first == "value",
          "subscript inserted an equivalent key or lost lowercase storage");
    const auto& constant = parsed;
    const auto* found = constant.as_object().at("SETTINGS").as_object()
                            .at("panels").as_array()[0].as_object()
                            .at("DEEP").as_object().if_contains("VALUE");
    Check(found != nullptr && found->as_string() == "UpdatedValue",
          "nested array object lost case-insensitive lookup");
    auto& empty = parsed.as_object().at("EMPTY").as_object();
    empty["NewKey"] = 1;
    Check(empty.at("newkey").as_int64() == 1 && empty.begin()->first == "newkey",
          "empty parsed object lost its comparator or key normalization");

    const auto array_root = ::json::parse(
        R"([[{"MiXeD":true}]])", KeyComparison::AsciiCaseInsensitive);
    Check(array_root.as_array()[0].as_array()[0].as_object().at("mixed").as_bool(),
          "objects in root arrays lost their comparison mode");
}

void CheckCopiesAndMoves() {
    const auto original = ::json::parse(
        R"({"Outer":[{"Inner":"OriginalValue"}]})",
        KeyComparison::AsciiCaseInsensitive);
    auto copied = original;
    auto moved = std::move(copied);
    ::json::value copy_assigned;
    copy_assigned = original;
    ::json::value move_assigned;
    move_assigned = std::move(copy_assigned);
    for (const auto* item : {&original, &std::as_const(moved)}) {
        Check(item->as_object().at("outer").as_array()[0].as_object()
                  .at("INNER").as_string() == "OriginalValue",
              "value copy or move construction lost the comparator");
    }
    Check(move_assigned.as_object().at("OUTER").as_array()[0].as_object()
              .at("inner").as_string() == "OriginalValue",
          "value assignment lost a nested comparator");
    moved.as_object().at("outer").as_array()[0].as_object()["inner"] = "Changed";
    Check(original.as_object().at("outer").as_array()[0].as_object()
              .at("inner").as_string() == "OriginalValue",
          "copied value shared mutable object storage");

    ::json::object copied_object(original.as_object());
    ::json::object moved_object(std::move(copied_object));
    ::json::object assigned_object;
    assigned_object = original.as_object();
    ::json::object moved_assigned_object;
    moved_assigned_object = std::move(assigned_object);
    Check(moved_object.contains("OUTER") && moved_assigned_object.contains("outer"),
          "object copy or move lost its comparator");
    moved_assigned_object = ::json::object{{"Mixed", 1}};
    Check(moved_assigned_object.contains("Mixed") &&
              !moved_assigned_object.contains("MIXED"),
          "object move assignment retained the old comparison mode");
    const ::json::object sensitive{{"Mixed", 1}};
    moved_object = sensitive;
    Check(moved_object.contains("Mixed") && !moved_object.contains("MIXED"),
          "object copy assignment retained the old comparison mode");

    auto self_object = ::json::parse(
        R"({"child":{"GrandChild":"Kept"},"sibling":1})",
        KeyComparison::AsciiCaseInsensitive).as_object();
    self_object = std::move(self_object["child"].as_object());
    Check(self_object.size() == 1 &&
              self_object.at("GRANDCHILD").as_string() == "Kept",
          "self-contained object move assignment corrupted nested storage");

    auto self_copied_object = ::json::parse(
        R"({"child":{"GrandChild":"Copied"},"sibling":2})",
        KeyComparison::AsciiCaseInsensitive).as_object();
    self_copied_object = self_copied_object["child"].as_object();
    Check(self_copied_object.size() == 1 &&
              self_copied_object.at("GRANDCHILD").as_string() == "Copied",
          "self-contained object copy assignment corrupted nested storage");

    auto self_array = ::json::parse(R"([["KeptElement",42],"Sibling"])").as_array();
    self_array = std::move(self_array[0].as_array());
    Check(self_array.size() == 2 &&
              self_array[0].as_string() == "KeptElement" &&
              self_array[1].as_int64() == 42,
          "self-contained array move assignment corrupted nested storage");

    auto self_copied_array = ::json::parse(R"([["CopiedElement",7],"Sibling"])").as_array();
    self_copied_array = self_copied_array[0].as_array();
    Check(self_copied_array.size() == 2 &&
              self_copied_array[0].as_string() == "CopiedElement" &&
              self_copied_array[1].as_int64() == 7,
          "self-contained array copy assignment corrupted nested storage");

    Check(::json::value(int64_t{42}) == ::json::value(uint64_t{42}) &&
              ::json::value(uint64_t{0}) == ::json::value(int64_t{0}) &&
              ::json::value(int64_t{-1}) != ::json::value(uint64_t{1}) &&
              ::json::value(int64_t{-1}) !=
                  ::json::value(static_cast<uint64_t>(-1)),
          "signed/unsigned integer value equality was inconsistent");
    Check(::json::parse(R"({"b":[1,true,"x"],"a":null})") ==
              ::json::parse(R"({"a":null,"b":[1,true,"x"]})") &&
              ::json::parse(R"({"a":1})") != ::json::parse(R"({"a":2})"),
          "structural value equality failed on objects or arrays");
}

void CheckDuplicateKeys() {
    for (const auto body : {
             R"({"Key":1,"key":2})",
             R"({"key":1,"key":2})",
             R"({"":1,"":2})",
             R"({"Key":1,"\u006bey":2})",
             R"({"Nested":{"Key":1,"KEY":2}})",
             R"([{"Key":1,"KEY":2}])"}) {
        try {
            (void)::json::parse(body, KeyComparison::AsciiCaseInsensitive);
            Fail("case-insensitive parser accepted a duplicate key");
        } catch (const ::json::parse_error&) {
        }
    }
    for (const auto body : {
             R"({"key":1,"key":2})",
             R"({"users":[{"id":1,"uuid":"a","uuid":"b"}]})"}) {
        try {
            (void)::json::parse(body);
            Fail("case-sensitive parser accepted a duplicate key");
        } catch (const ::json::parse_error&) {
        }
    }
    const auto distinct_case = ::json::parse(R"({"Key":1,"key":2})");
    Check(distinct_case.as_object().size() == 2,
          "case-sensitive parser merged keys differing only in case");
    const auto siblings = ::json::parse(
        R"([{"Key":1},{"KEY":2}])", KeyComparison::AsciiCaseInsensitive);
    Check(siblings.as_array()[0].as_object().at("key").as_int64() == 1 &&
              siblings.as_array()[1].as_object().at("key").as_int64() == 2,
          "keys in different objects were treated as duplicates");
}

void CheckNestingDepth() {
    const auto nested = [](size_t depth) {
        return std::string(depth, '[') + std::string(depth, ']');
    };
    Check(::json::parse(nested(128)).is_array(),
          "nesting at the depth limit was rejected");
    for (const std::string& body : {nested(129), std::string(1'000'000, '[')}) {
        try {
            (void)::json::parse(body);
            Fail("nesting beyond the depth limit was accepted");
        } catch (const ::json::parse_error& error) {
            Check(std::string_view(error.what()).find("nesting too deep") !=
                      std::string_view::npos,
                  "deep nesting was rejected for the wrong reason");
        }
    }
    std::string nested_objects;
    for (size_t i = 1; i < 127; ++i) nested_objects += R"({"k":)";
    nested_objects += "{}" + std::string(126, '}');
    const std::string siblings = "[" + nested(127) + "," + nested_objects + "," +
                                 nested_objects + "]";
    Check(::json::parse(siblings).is_array(),
          "depth accounting leaked across closed containers");
}

void CheckNormalizedKeysAndValues() {
    const std::string_view text = R"({"MiXeD-Key":"VaLuE/ABC_def"})";
    const auto parsed = ::json::parse(text, KeyComparison::AsciiCaseInsensitive);
    Check(parsed.as_object().begin()->first == "mixed-key" &&
              parsed.as_object().at("MiXeD-Key").as_string() == "VaLuE/ABC_def",
          "case-insensitive parsing failed to normalize only the key");
    Check(::json::serialize(parsed) == R"({"mixed-key":"VaLuE/ABC_def"})",
          "serialization lost lowercase key storage or original string value");
    Check(::json::serialize(::json::parse(text)) == text,
          "ordinary JSON parsing changed original key or value spelling");

    auto object = ::json::object(KeyComparison::AsciiCaseInsensitive);
    object["SuBscript"] = "MixedValue";
    auto [entry, inserted] = object.insert_or_assign("InSert", "OtherValue");
    Check(inserted && entry->first == "insert" &&
              object.at("SUBSCRIPT").as_string() == "MixedValue",
          "object insertion failed to normalize keys independently of parsing");
    Check(::json::serialize(object) ==
              R"({"insert":"OtherValue","subscript":"MixedValue"})",
          "programmatic insertion retained uppercase key storage");
}

void CheckUnicodeEscapes() {
    const auto supplementary = ::json::parse(R"("\uD83D\uDE00")");
    Check(supplementary.as_string() == "\xF0\x9F\x98\x80",
          "unicode surrogate pair was not decoded as one code point");
    for (const std::string_view lone_surrogate : {R"("\uD83D")", R"("\uDE00")"}) {
        bool rejected = false;
        try {
            (void)::json::parse(lone_surrogate);
        } catch (const ::json::parse_error&) {
            rejected = true;
        }
        Check(rejected, "invalid JSON unicode escape was accepted");
    }
}

}  // namespace

TEST(JsonObject, Contract) {
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

    CheckInvalid(R"({"camelObject":[]})");
    CheckInvalid(R"({"camelObject":null})");

    CheckKeyComparisonModes();
    CheckNestedKeyComparison();
    CheckCopiesAndMoves();
    CheckDuplicateKeys();
    CheckNestingDepth();
    CheckNormalizedKeysAndValues();
    CheckUnicodeEscapes();

    std::cout << "json_object_test: ok\n";
}
