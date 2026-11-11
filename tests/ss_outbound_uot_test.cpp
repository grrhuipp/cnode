#include <gtest/gtest.h>

#include "infra/config.hpp"
#include "proxy/uot/uot.hpp"

#include <string_view>

namespace {

std::optional<proxy::uot::Version> Parse(std::string_view fields) {
    auto source = json::parse(fields, json::KeyComparison::AsciiCaseInsensitive);
    source.as_object()["address"] = "example.com";
    source.as_object()["password"] = "secret";
    return std::get<infra::ShadowsocksSettings>(
        infra::ParseOutboundSettings("shadowsocks", source.as_object())).uot_version;
}

TEST(SsOutboundUot, ExplicitVersionsAreNormalized) {
    using proxy::uot::Version;
    EXPECT_EQ(Parse(R"({"uot":true,"uotVersion":1})"), Version::V1);
    EXPECT_EQ(Parse(R"({"uot":true,"uotVersion":2})"), Version::V2);
    EXPECT_EQ(Parse(R"({"uot":{"enabled":true,"version":2}})"), Version::V2);
    EXPECT_EQ(Parse(R"({"uot":{"version":1}})"), Version::V1);
    EXPECT_FALSE(Parse(R"({"uot":false})"));
    EXPECT_FALSE(Parse(R"({"uot":{"enabled":false}})"));
}

TEST(SsOutboundUot, InvalidOrAmbiguousPoliciesAreRejected) {
    for (const auto body : {
        R"({"uot":true,"uotVersion":3})", R"({"uot":"true"})",
        R"({"uot":{"enabled":true,"version":3}})",
        R"({"uot":{"enabled":1,"version":2}})", R"({"uotVersion":2})",
        R"({"uot":1})", R"({"uot":false,"uotVersion":2})",
        R"({"uot":{"enabled":false,"version":2}})",
        R"({"uot":{"version":1},"uotVersion":1})",
        R"({"uot":{"enabled":true,"unknown":2}})"}) {
        SCOPED_TRACE(body);
        EXPECT_THROW(Parse(body), std::invalid_argument);
    }
}

}  // namespace
