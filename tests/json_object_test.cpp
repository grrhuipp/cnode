#include <gtest/gtest.h>

#include "infra/json.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace {
using ::json::KeyComparison;

struct ParsedObject {
    ::json::value source;
    tl::expected<const ::json::object*, std::string> result;

    explicit ParsedObject(std::string_view body)
        : source(::json::parse(body)),
          result(::ParseJsonObject(source.as_object(), "camelObject")) {}
};

TEST(JsonObject, MissingOptionalObjectRemainsUnconfigured) {
    const ParsedObject absent(R"({})");
    ASSERT_TRUE(absent.result);
    EXPECT_EQ(*absent.result, nullptr);
    const ParsedObject unrelated(R"({"otherObject":{"value":1}})");
    ASSERT_TRUE(unrelated.result);
    EXPECT_EQ(*unrelated.result, nullptr);
}

TEST(JsonObject, ReadsConfiguredObject) {
    const ParsedObject parsed(R"({"camelObject":{"value":1}})");
    ASSERT_TRUE(parsed.result);
    ASSERT_NE(*parsed.result, nullptr);
    EXPECT_EQ((*parsed.result)->at("value").as_int64(), 1);
}

class InvalidOptionalObject : public ::testing::TestWithParam<const char*> {};
TEST_P(InvalidOptionalObject, RejectsConfiguredNonObject) {
    const ParsedObject parsed(GetParam());
    EXPECT_FALSE(parsed.result);
}
INSTANTIATE_TEST_SUITE_P(ConfigurationErrors, InvalidOptionalObject,
    ::testing::Values(R"({"camelObject":[]})", R"({"camelObject":null})"));

TEST(JsonObject, AsciiInsensitiveLookupPreservesNonAsciiAndKeyBoundaries) {
    const auto parsed = ::json::parse(
        R"({"CaMeLKey":1,"camel_key":2,"\u00c4":3,"\u00e4":4})",
        KeyComparison::AsciiCaseInsensitive);
    const auto& object = parsed.as_object();
    EXPECT_TRUE(object.contains("CAMELKEY"));
    EXPECT_EQ(object.at("camelKey").as_int64(), 1);
    EXPECT_EQ(object.at("CAMEL_KEY").as_int64(), 2);
    EXPECT_EQ(object.size(), 4);
    EXPECT_EQ(object.at("\xc3\x84").as_int64(), 3);
    EXPECT_EQ(object.at("\xc3\xa4").as_int64(), 4);
    const std::string_view bounded_key = "xCAMELKEYx";
    EXPECT_NE(object.if_contains(bounded_key.substr(1, 8)), nullptr);
    EXPECT_FALSE(object.contains("camel"));
    EXPECT_FALSE(object.contains("camelKeyExtra"));
    EXPECT_FALSE(object.contains("missing"));
}

TEST(JsonObject, OrdinaryParsingAndConstructionRemainCaseSensitive) {
    for (const auto& parsed : {
             ::json::parse(R"({"CaMeLKey":1,"camelKey":2})"),
             ::json::parse(R"({"CaMeLKey":1,"camelKey":2})", KeyComparison::CaseSensitive)}) {
        const auto& object = parsed.as_object();
        EXPECT_EQ(object.size(), 2);
        EXPECT_EQ(object.at("CaMeLKey").as_int64(), 1);
        EXPECT_EQ(object.at("camelKey").as_int64(), 2);
        EXPECT_FALSE(object.contains("CAMELKEY"));
    }
    ::json::object constructed;
    constructed["Key"] = 1;
    constructed["key"] = 2;
    const ::json::object initialized{{"Key", 1}, {"key", 2}};
    EXPECT_EQ(constructed.size(), 2);
    EXPECT_EQ(initialized.size(), 2);
}

TEST(JsonObject, NestedObjectsAndInsertionsRetainComparisonMode) {
    auto parsed = ::json::parse(
        R"({"SeTTings":{"PaNeLs":[{"DeEp":{"VaLuE":"UnChanged"}}]},"Empty":{}})",
        KeyComparison::AsciiCaseInsensitive);
    auto* settings = parsed.as_object().if_contains("settings");
    ASSERT_NE(settings, nullptr);
    auto& deep = settings->as_object().at("PANELS").as_array()[0].as_object()
                     .at("deep").as_object();
    deep["VALUE"] = "UpdatedValue";
    EXPECT_EQ(deep.size(), 1);
    EXPECT_EQ(deep.begin()->first, "value");
    const auto& constant = parsed;
    const auto* found = constant.as_object().at("SETTINGS").as_object()
                            .at("panels").as_array()[0].as_object()
                            .at("DEEP").as_object().if_contains("VALUE");
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->as_string(), "UpdatedValue");
    auto& empty = parsed.as_object().at("EMPTY").as_object();
    empty["NewKey"] = 1;
    EXPECT_EQ(empty.at("newkey").as_int64(), 1);
    EXPECT_EQ(empty.begin()->first, "newkey");
    const auto array_root = ::json::parse(
        R"([[{"MiXeD":true}]])", KeyComparison::AsciiCaseInsensitive);
    EXPECT_TRUE(array_root.as_array()[0].as_array()[0].as_object().at("mixed").as_bool());
}

TEST(JsonObject, TransferringValuesPreservesNestedComparisonMode) {
    const auto original = ::json::parse(
        R"({"Outer":[{"Inner":"OriginalValue"}]})", KeyComparison::AsciiCaseInsensitive);
    auto copied = original;
    auto moved = std::move(copied);
    ::json::value copy_assigned;
    copy_assigned = original;
    ::json::value move_assigned;
    move_assigned = std::move(copy_assigned);
    EXPECT_EQ(moved.as_object().at("outer").as_array()[0].as_object()
                  .at("INNER").as_string(), "OriginalValue");
    EXPECT_EQ(move_assigned.as_object().at("OUTER").as_array()[0].as_object()
                  .at("inner").as_string(), "OriginalValue");
    ::json::object copied_object(original.as_object());
    ::json::object moved_object(std::move(copied_object));
    ::json::object assigned_object;
    assigned_object = original.as_object();
    ::json::object moved_assigned_object;
    moved_assigned_object = std::move(assigned_object);
    EXPECT_TRUE(moved_object.contains("OUTER"));
    EXPECT_TRUE(moved_assigned_object.contains("outer"));
    moved_assigned_object = ::json::object{{"Mixed", 1}};
    EXPECT_TRUE(moved_assigned_object.contains("Mixed"));
    EXPECT_FALSE(moved_assigned_object.contains("MIXED"));
    const ::json::object sensitive{{"Mixed", 1}};
    moved_object = sensitive;
    EXPECT_TRUE(moved_object.contains("Mixed"));
    EXPECT_FALSE(moved_object.contains("MIXED"));
}

TEST(JsonObject, AssigningContainedObjectPreservesStorageAndComparisonMode) {
    auto moved = ::json::parse(
        R"({"child":{"GrandChild":"Kept"},"sibling":1})",
        KeyComparison::AsciiCaseInsensitive).as_object();
    moved = std::move(moved["child"].as_object());
    EXPECT_EQ(moved.size(), 1);
    EXPECT_EQ(moved.at("GRANDCHILD").as_string(), "Kept");
    auto copied = ::json::parse(
        R"({"child":{"GrandChild":"Copied"},"sibling":2})",
        KeyComparison::AsciiCaseInsensitive).as_object();
    copied = copied["child"].as_object();
    EXPECT_EQ(copied.size(), 1);
    EXPECT_EQ(copied.at("GRANDCHILD").as_string(), "Copied");
}

TEST(JsonObject, AssigningContainedArrayPreservesElements) {
    auto moved = ::json::parse(R"([["KeptElement",42],"Sibling"])").as_array();
    moved = std::move(moved[0].as_array());
    ASSERT_EQ(moved.size(), 2);
    EXPECT_EQ(moved[0].as_string(), "KeptElement");
    EXPECT_EQ(moved[1].as_int64(), 42);
    auto copied = ::json::parse(R"([["CopiedElement",7],"Sibling"])").as_array();
    copied = copied[0].as_array();
    ASSERT_EQ(copied.size(), 2);
    EXPECT_EQ(copied[0].as_string(), "CopiedElement");
    EXPECT_EQ(copied[1].as_int64(), 7);
}

TEST(JsonObject, IntegerEqualityRespectsSignedRange) {
    EXPECT_EQ(::json::value(int64_t{42}), ::json::value(uint64_t{42}));
    EXPECT_EQ(::json::value(uint64_t{0}), ::json::value(int64_t{0}));
    EXPECT_NE(::json::value(int64_t{-1}), ::json::value(uint64_t{1}));
    EXPECT_NE(::json::value(int64_t{-1}), ::json::value(static_cast<uint64_t>(-1)));
}

TEST(JsonObject, StructuralEqualityIgnoresObjectOrderButNotValues) {
    EXPECT_EQ(::json::parse(R"({"b":[1,true,"x"],"a":null})"),
              ::json::parse(R"({"a":null,"b":[1,true,"x"]})"));
    EXPECT_NE(::json::parse(R"({"a":1})"), ::json::parse(R"({"a":2})"));
}

class DuplicateInsensitiveKey : public ::testing::TestWithParam<const char*> {};
TEST_P(DuplicateInsensitiveKey, RejectsAmbiguousKeys) {
    EXPECT_THROW(static_cast<void>(::json::parse(GetParam(), KeyComparison::AsciiCaseInsensitive)), ::json::parse_error);
}
INSTANTIATE_TEST_SUITE_P(DuplicateKeys, DuplicateInsensitiveKey, ::testing::Values(
    R"({"Key":1,"key":2})", R"({"key":1,"key":2})", R"({"":1,"":2})",
    R"({"Key":1,"\u006bey":2})", R"({"Nested":{"Key":1,"KEY":2}})",
    R"([{"Key":1,"KEY":2}])"));

class DuplicateSensitiveKey : public ::testing::TestWithParam<const char*> {};
TEST_P(DuplicateSensitiveKey, RejectsDuplicateKeys) {
    EXPECT_THROW(static_cast<void>(::json::parse(GetParam())), ::json::parse_error);
}
INSTANTIATE_TEST_SUITE_P(DuplicateKeys, DuplicateSensitiveKey, ::testing::Values(
    R"({"key":1,"key":2})", R"({"users":[{"id":1,"uuid":"a","uuid":"b"}]})"));

TEST(JsonObject, KeysInSiblingObjectsAreIndependent) {
    const auto siblings = ::json::parse(
        R"([{"Key":1},{"KEY":2}])", KeyComparison::AsciiCaseInsensitive);
    EXPECT_EQ(siblings.as_array()[0].as_object().at("key").as_int64(), 1);
    EXPECT_EQ(siblings.as_array()[1].as_object().at("key").as_int64(), 2);
}

TEST(JsonObject, EnforcesNestingDepthWithoutLeakingAcrossSiblings) {
    const auto nested = [](size_t depth) {
        return std::string(depth, '[') + std::string(depth, ']');
    };
    EXPECT_TRUE(::json::parse(nested(128)).is_array());
    EXPECT_THROW(static_cast<void>(::json::parse(nested(129))), ::json::parse_error);
    EXPECT_THROW(static_cast<void>(::json::parse(std::string(1'000'000, '['))), ::json::parse_error);
    std::string nested_objects;
    for (size_t i = 1; i < 127; ++i) nested_objects += R"({"k":)";
    nested_objects += "{}" + std::string(126, '}');
    const std::string siblings = "[" + nested(127) + "," + nested_objects + "," + nested_objects + "]";
    EXPECT_TRUE(::json::parse(siblings).is_array());
}

TEST(JsonObject, NormalizesKeysWithoutChangingOpaqueStringValues) {
    const std::string_view text = R"({"MiXeD-Key":"VaLuE/ABC_def"})";
    const auto parsed = ::json::parse(text, KeyComparison::AsciiCaseInsensitive);
    EXPECT_EQ(parsed.as_object().begin()->first, "mixed-key");
    EXPECT_EQ(parsed.as_object().at("MiXeD-Key").as_string(), "VaLuE/ABC_def");
    const auto serialized = ::json::parse(::json::serialize(parsed));
    EXPECT_EQ(serialized.as_object().at("mixed-key").as_string(), "VaLuE/ABC_def");
    const auto ordinary = ::json::parse(::json::serialize(::json::parse(text)));
    EXPECT_EQ(ordinary.as_object().at("MiXeD-Key").as_string(), "VaLuE/ABC_def");
    auto object = ::json::object(KeyComparison::AsciiCaseInsensitive);
    object["SuBscript"] = "MixedValue";
    auto [entry, inserted] = object.insert_or_assign("InSert", "OtherValue");
    EXPECT_TRUE(inserted);
    EXPECT_EQ(entry->first, "insert");
    EXPECT_EQ(object.at("SUBSCRIPT").as_string(), "MixedValue");
    const auto stored = ::json::parse(::json::serialize(object));
    EXPECT_EQ(stored.as_object().at("insert").as_string(), "OtherValue");
    EXPECT_EQ(stored.as_object().at("subscript").as_string(), "MixedValue");
}

TEST(JsonObject, DecodesUnicodeSurrogatePair) {
    EXPECT_EQ(::json::parse(R"("\uD83D\uDE00")").as_string(), "\xF0\x9F\x98\x80");
}

class LoneSurrogate : public ::testing::TestWithParam<const char*> {};
TEST_P(LoneSurrogate, RejectsInvalidUnicodeEscape) {
    EXPECT_THROW(static_cast<void>(::json::parse(GetParam())), ::json::parse_error);
}
INSTANTIATE_TEST_SUITE_P(InvalidUnicode, LoneSurrogate,
    ::testing::Values(R"("\uD83D")", R"("\uDE00")"));
}  // namespace
