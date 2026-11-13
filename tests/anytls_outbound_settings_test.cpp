#include <gtest/gtest.h>

#include "infra/config.hpp"

#include <string>
#include <string_view>

namespace {

infra::AnyTlsSettings Parse(std::string_view body) {
    const auto source = infra::parse(body, infra::KeyComparison::AsciiCaseInsensitive);
    return std::get<infra::AnyTlsSettings>(infra::ParseOutboundSettings("anytls", source.as_object()));
}

TEST(AnytlsOutboundSettings, SessionPolicyIsNormalized) {
    const auto settings = Parse(
        R"({"address":"example.com","port":8443,"password":"secret","idleSessionCheckInterval":10,"idleSessionTimeout":20,"minIdleSession":2})");
    EXPECT_EQ(settings.idle_session_check_interval, std::chrono::seconds(10));
    EXPECT_EQ(settings.idle_session_timeout, std::chrono::seconds(20));
    EXPECT_EQ(settings.min_idle_sessions, 2u);
}

TEST(AnytlsOutboundSettings, PasswordHashPreservesEmbeddedNull) {
    struct Case { std::string_view password; std::string_view hash; };
    for (const auto& test : {
        Case{"secret", "2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"},
        Case{R"(abc\u0000def)", "516a5e926ce20c5f4d80f00e1a01abdf14986def6588d6abeed9fce090bc660c"}}) {
        const auto settings = Parse(std::string(R"({"address":"127.0.0.1","port":443,"password":")") +
                                    std::string(test.password) + R"("})");
        constexpr std::string_view hex = "0123456789abcdef";
        std::string actual;
        for (const auto byte : settings.password_hash) {
            actual += hex[byte >> 4];
            actual += hex[byte & 15];
        }
        EXPECT_EQ(actual, test.hash);
    }
}

TEST(AnytlsOutboundSettings, InvalidSessionPoliciesAreRejected) {
    for (const auto field : {
        R"("idleSessionCheckInterval":9223372036854775807)",
        R"("idleSessionTimeout":9223372036854775807)",
        R"("idleSessionCheckInterval":"30")", R"("idleSessionTimeout":0)",
        R"("idleSessionTimeout":18446744073709551615)",
        R"("minIdleSession":-1)", R"("minIdleSession":"1")", R"("minIdleSessions":1)"}) {
        SCOPED_TRACE(field);
        EXPECT_THROW(Parse(std::string(R"({"address":"example.com","port":443,"password":"secret",)") + field + '}'),
                     std::invalid_argument);
    }
}

}  // namespace
