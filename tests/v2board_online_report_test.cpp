#include <gtest/gtest.h>
#include "api/panel_wire.hpp"
#include <vector>

TEST(V2BoardOnlineReport, GroupsDeviceAddressesByUserWithNodeSuffix) {
    const std::vector<::api::OnlineUser> devices{
        {.UID = 7, .IP = "203.0.113.1"}, {.UID = 7, .IP = "203.0.113.2"},
        {.UID = 8, .IP = "203.0.113.8"}};
    const auto report = ::api::BuildOnlineReportPayload(devices, 42);
    EXPECT_EQ(report.user_count, 2u);
    EXPECT_EQ(report.device_count, 3u);
    ASSERT_FALSE(report.alive_json.empty());
    const auto parsed = ::infra::parse(report.alive_json);
    ASSERT_TRUE(parsed.is_object());
    const auto& body = parsed.as_object();
    ASSERT_EQ(body.size(), 2u);
    const auto& alive = body.at("7").as_array();
    ASSERT_EQ(alive.size(), 2u);
    EXPECT_EQ(alive[0].as_string(), "203.0.113.1_42");
    EXPECT_EQ(alive[1].as_string(), "203.0.113.2_42");
    const auto& other = body.at("8").as_array();
    ASSERT_EQ(other.size(), 1u);
    EXPECT_EQ(other[0].as_string(), "203.0.113.8_42");
}

TEST(V2BoardOnlineReport, EmptySnapshotClearsReportedDevices) {
    const auto report = ::api::BuildOnlineReportPayload({}, 42);
    EXPECT_EQ(report.user_count, 0u);
    EXPECT_EQ(report.device_count, 0u);
    EXPECT_TRUE(report.alive_json.empty());
}
