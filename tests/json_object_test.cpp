#include "acppnode/infra/json_object.hpp"

#include <cstdlib>
#include <iostream>
#include <string_view>
#include <utility>

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

using acpp::json::KeyComparison;

void CheckKeyComparisonModes() {
    const auto insensitive = acpp::json::parse(
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
             acpp::json::parse(R"({"CaMeLKey":1,"camelKey":2})"),
             acpp::json::parse(R"({"CaMeLKey":1,"camelKey":2})",
                               KeyComparison::CaseSensitive)}) {
        Check(sensitive.as_object().size() == 2 &&
                  sensitive.as_object().at("CaMeLKey").as_int64() == 1 &&
                  sensitive.as_object().at("camelKey").as_int64() == 2 &&
                  !sensitive.as_object().contains("CAMELKEY"),
              "case-insensitive parsing leaked into ordinary JSON");
    }
    acpp::json::object constructed;
    constructed["Key"] = 1;
    constructed["key"] = 2;
    const acpp::json::object initialized{{"Key", 1}, {"key", 2}};
    Check(constructed.size() == 2 && initialized.size() == 2,
          "ordinary object construction became case-insensitive");
}

void CheckNestedKeyComparison() {
    auto parsed = acpp::json::parse(
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

    const auto array_root = acpp::json::parse(
        R"([[{"MiXeD":true}]])", KeyComparison::AsciiCaseInsensitive);
    Check(array_root.as_array()[0].as_array()[0].as_object().at("mixed").as_bool(),
          "objects in root arrays lost their comparison mode");
}

void CheckCopiesAndMoves() {
    const auto original = acpp::json::parse(
        R"({"Outer":[{"Inner":"OriginalValue"}]})",
        KeyComparison::AsciiCaseInsensitive);
    auto copied = original;
    auto moved = std::move(copied);
    acpp::json::value copy_assigned;
    copy_assigned = original;
    acpp::json::value move_assigned;
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

    acpp::json::object copied_object(original.as_object());
    acpp::json::object moved_object(std::move(copied_object));
    acpp::json::object assigned_object;
    assigned_object = original.as_object();
    acpp::json::object moved_assigned_object;
    moved_assigned_object = std::move(assigned_object);
    Check(moved_object.contains("OUTER") && moved_assigned_object.contains("outer"),
          "object copy or move lost its comparator");
    moved_assigned_object = acpp::json::object{{"Mixed", 1}};
    Check(moved_assigned_object.contains("Mixed") &&
              !moved_assigned_object.contains("MIXED"),
          "object move assignment retained the old comparison mode");
    const acpp::json::object sensitive{{"Mixed", 1}};
    moved_object = sensitive;
    Check(moved_object.contains("Mixed") && !moved_object.contains("MIXED"),
          "object copy assignment retained the old comparison mode");
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
            (void)acpp::json::parse(body, KeyComparison::AsciiCaseInsensitive);
            Fail("case-insensitive parser accepted a duplicate key");
        } catch (const acpp::json::parse_error& error) {
            const std::string_view message = error.what();
            Check(message.find("duplicate object key") != std::string_view::npos &&
                      message.find("at byte ") != std::string_view::npos,
                  "duplicate key diagnostic lost its cause or location");
        }
    }
    const auto repeated = acpp::json::parse(R"({"key":1,"key":2})");
    Check(repeated.as_object().size() == 1 &&
              repeated.as_object().at("key").as_int64() == 2,
          "ordinary JSON duplicate-key behavior changed");
    const auto siblings = acpp::json::parse(
        R"([{"Key":1},{"KEY":2}])", KeyComparison::AsciiCaseInsensitive);
    Check(siblings.as_array()[0].as_object().at("key").as_int64() == 1 &&
              siblings.as_array()[1].as_object().at("key").as_int64() == 2,
          "keys in different objects were treated as duplicates");
}

void CheckNormalizedKeysAndValues() {
    const std::string_view text = R"({"MiXeD-Key":"VaLuE/ABC_def"})";
    const auto parsed = acpp::json::parse(text, KeyComparison::AsciiCaseInsensitive);
    Check(parsed.as_object().begin()->first == "mixed-key" &&
              parsed.as_object().at("MiXeD-Key").as_string() == "VaLuE/ABC_def",
          "case-insensitive parsing failed to normalize only the key");
    Check(acpp::json::serialize(parsed) == R"({"mixed-key":"VaLuE/ABC_def"})",
          "serialization lost lowercase key storage or original string value");
    Check(acpp::json::serialize(acpp::json::parse(text)) == text,
          "ordinary JSON parsing changed original key or value spelling");

    auto object = acpp::json::object(KeyComparison::AsciiCaseInsensitive);
    object["SuBscript"] = "MixedValue";
    auto [entry, inserted] = object.insert_or_assign("InSert", "OtherValue");
    Check(inserted && entry->first == "insert" &&
              object.at("SUBSCRIPT").as_string() == "MixedValue",
          "object insertion failed to normalize keys independently of parsing");
    Check(acpp::json::serialize(object) ==
              R"({"insert":"OtherValue","subscript":"MixedValue"})",
          "programmatic insertion retained uppercase key storage");
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

    CheckKeyComparisonModes();
    CheckNestedKeyComparison();
    CheckCopiesAndMoves();
    CheckDuplicateKeys();
    CheckNormalizedKeysAndValues();

    std::cout << "json_object_test: ok\n";
    return 0;
}
