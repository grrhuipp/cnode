#include <gtest/gtest.h>

#include "api/panel_wire.hpp"
#include <limits>
#include <string_view>

namespace {

auto Parse(std::string_view body) {
    const auto parsed = ::infra::parse(body);
    return ::api::ParseUserList(parsed.as_object());
}

TEST(V2BoardUserListJson, ValidUsersAreNormalized) {
    auto result = Parse(
        R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls-rprx-vision","speed_limit":8,"device_limit":3,"email":"user@example.com"},{"id":8,"uuid":"11111111-1111-1111-1111-111111111111","speed_limit":null,"device_limit":null},{"id":9,"uuid":"22222222-2222-2222-2222-222222222222","speed_limit":140737488355327,"device_limit":4294967295}]})");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 3);
    EXPECT_EQ((*result)[0].UUID, "b831381d-6324-4d53-ad4f-8cda48b30811");
    EXPECT_EQ((*result)[1].UUID, "11111111-1111-1111-1111-111111111111");
    EXPECT_EQ((*result)[0].SpeedLimit, 1024ULL * 1024ULL);
    EXPECT_EQ((*result)[0].DeviceLimit, 3);
    EXPECT_EQ((*result)[0].Flow, "xtls-rprx-vision");
    EXPECT_EQ((*result)[0].Email, "user@example.com");
    EXPECT_EQ((*result)[1].SpeedLimit, 0);
    EXPECT_EQ((*result)[1].DeviceLimit, 0);
    EXPECT_EQ((*result)[2].SpeedLimit, std::numeric_limits<uint64_t>::max() - 131071);
    EXPECT_EQ((*result)[2].DeviceLimit, std::numeric_limits<uint32_t>::max());

}

TEST(V2BoardUserListJson, EmptyUserListIsAccepted) {
    auto empty = Parse(R"({"users":[]})");
    ASSERT_TRUE(empty.has_value());
    EXPECT_TRUE(empty->empty());
}

TEST(V2BoardUserListJson, InvalidLimitsAreRejected) {
    EXPECT_FALSE(Parse(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","speed_limit":140737488355328}]})").has_value());
    EXPECT_FALSE(Parse(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","device_limit":4294967296}]})").has_value());
    EXPECT_FALSE(Parse(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","speed_limit":-1}]})").has_value());
    EXPECT_FALSE(Parse(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","device_limit":"+1"}]})").has_value());
    EXPECT_FALSE(Parse(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","speed_limit":"1.5"}]})").has_value());
}

TEST(V2BoardUserListJson, Xv2BoardUserTypesAreCompatible) {
    auto result = Parse(
        R"({"users":[{"id":"7","uuid":"B831381D-6324-4D53-AD4F-8CDA48B30811","flow":"XTLS-RPRX-VISION","speed_limit":"8","device_limit":"3"}]})");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->size(), 1);
    EXPECT_EQ((*result)[0].UID, 7);
    EXPECT_EQ((*result)[0].SpeedLimit, 1024ULL * 1024ULL);
    EXPECT_EQ((*result)[0].DeviceLimit, 3);
    EXPECT_EQ((*result)[0].Flow, "xtls-rprx-vision");
    EXPECT_EQ((*result)[0].UUID, "B831381D-6324-4D53-AD4F-8CDA48B30811");
}

TEST(V2BoardUserListJson, MalformedUsersAreRejected) {
    EXPECT_FALSE(Parse(R"({})").has_value());
    EXPECT_FALSE(Parse(R"({"users":null})").has_value());
    EXPECT_FALSE(Parse(R"({"users":[1]})").has_value());
    EXPECT_FALSE(Parse(R"({"users":[{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]})").has_value());
    EXPECT_FALSE(Parse(R"({"users":[{"id":7}]})").has_value());
}

TEST(V2BoardUserListJson, DuplicateUserIdsAreRejected) {
    EXPECT_FALSE(Parse(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"},{"id":7,"uuid":"11111111-1111-1111-1111-111111111111"}]})").has_value());
}

TEST(V2BoardUserListJson, ControlCharactersInUserFieldsAreRejected) {
    EXPECT_FALSE(Parse(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","email":"bad\n@example.com"}]})").has_value());
    EXPECT_FALSE(Parse(R"({"users":[{"id":7,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","flow":"xtls\r\n"}]})").has_value());
}

}  // namespace

