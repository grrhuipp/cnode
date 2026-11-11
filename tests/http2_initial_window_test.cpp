#include <gtest/gtest.h>
#include "infra/config.hpp"
#include "transport/internet/http2_session.hpp"
#include <string>
#include <string_view>

namespace {
auto Parse(std::string_view body) {
    const auto parsed = ::json::parse(body);
    return ::ParseHttp2InitialWindow(parsed.as_object());
}

TEST(Http2InitialWindow, MissingWindowDoesNotOverridePeerNegotiation) {
    const auto result = Parse(R"({})");
    ASSERT_TRUE(result.has_value());
    EXPECT_FALSE(result->has_value());
}

class Http2InitialWindowValue : public testing::TestWithParam<uint32_t> {};
TEST_P(Http2InitialWindowValue, PreservesConfiguredWindowAndEncodesSettings) {
    const auto value = GetParam();
    const auto result = Parse(std::string("{\"initialWindowSize\":") + std::to_string(value) + "}");
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->has_value());
    EXPECT_EQ(**result, value);
    const auto setting = ::transport::internet::EncodeInitialWindowSetting(value);
    ASSERT_EQ(setting.size(), 6u);
    EXPECT_EQ(setting[0], 0);
    EXPECT_EQ(setting[1], 4);
    for (size_t index = 0; index < 4; ++index)
        EXPECT_EQ(static_cast<uint8_t>(setting[index + 2]),
                  static_cast<uint8_t>(value >> (24 - 8 * index)));
}
INSTANTIATE_TEST_SUITE_P(Boundaries, Http2InitialWindowValue,
    testing::Values(0u, static_cast<uint32_t>(::kHttp2MaxInitialWindow)));

class InvalidHttp2InitialWindow : public testing::TestWithParam<const char*> {};
TEST_P(InvalidHttp2InitialWindow, RejectsInvalidConfiguredWindow) {
    EXPECT_FALSE(Parse(GetParam()).has_value());
}
INSTANTIATE_TEST_SUITE_P(TypeAndRange, InvalidHttp2InitialWindow, testing::Values(
    R"({"initialWindowSize":"65535"})", R"({"initialWindowSize":-1})",
    R"({"initialWindowSize":2147483648})", R"({"initialWindowSize":1.5})"));
} // namespace
