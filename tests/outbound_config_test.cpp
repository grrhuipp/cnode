#include <gtest/gtest.h>

#include "infra/config.hpp"
#include "proxy/vmess/vmess_crypto.hpp"

#include <string>
#include <string_view>
#include <type_traits>

namespace {

static_assert(std::is_aggregate_v<infra::FreedomSettings>);
static_assert(std::is_aggregate_v<infra::BlackholeSettings>);
static_assert(std::is_aggregate_v<infra::ShadowsocksSettings>);
static_assert(std::is_aggregate_v<infra::TrojanSettings>);
static_assert(std::is_aggregate_v<infra::VlessSettings>);
static_assert(std::is_aggregate_v<infra::VmessSettings>);
static_assert(std::is_aggregate_v<infra::AnyTlsSettings>);

infra::OutboundSettings Parse(std::string_view protocol, std::string_view body) {
    const auto source = json::parse(body, json::KeyComparison::AsciiCaseInsensitive);
    return infra::ParseOutboundSettings(protocol, source.as_object());
}

TEST(OutboundConfig, VlessCustomIdMapsToDocumentedUuid) {
    const auto custom = std::get<infra::VlessSettings>(Parse("vless",
        R"({"address":"example.com","id":"我爱🍉老师1314","encryption":"none"})"));
    const auto uuid = std::get<infra::VlessSettings>(Parse("vless",
        R"({"vnext":[{"address":"example.com","users":[{"id":"5783a3e7-e373-51cd-8642-c83782b807c5","encryption":"none"}]}]})"));
    EXPECT_EQ(custom.id, uuid.id);
}

TEST(OutboundConfig, PacketEncodingsRemainDistinct) {
    struct Case { std::string_view spelling; infra::PacketEncoding encoding; };
    for (const auto& test : {
        Case{"none", infra::PacketEncoding::None},
        Case{"packetaddr", infra::PacketEncoding::PacketAddr},
        Case{"XUDP", infra::PacketEncoding::Xudp}}) {
        const auto settings = std::get<infra::VlessSettings>(Parse("vless",
            std::string(R"({"address":"example.com","id":"custom","packetEncoding":")") +
            std::string(test.spelling) + R"("})"));
        EXPECT_EQ(settings.packet_encoding, test.encoding);
    }
    for (const auto encoding : {"raw", "packet", "packet-addr"}) {
        EXPECT_THROW(Parse("vless", std::string(R"({"address":"example.com","id":"custom","packetEncoding":")") +
                           encoding + R"("})"), std::invalid_argument);
    }
}

TEST(OutboundConfig, NestedSchemasDoNotFallbackToTopLevelCredentials) {
    for (const auto body : {
        R"({"vnext":[{"address":"example.com","users":[{"uuid":"custom"}]}]})",
        R"({"vnext":[{"address":"example.com","users":[{"id":"custom"}]}],"encryption":"none"})",
        R"({"vnext":[{"address":"example.com","users":[{"id":"custom"}]}],"packetEncoding":"xudp"})",
        R"({"vnext":[{"address":"example.com","users":[{"id":"custom"}]}],"address":"other.example"})",
        R"({"address":"example.com","uuid":"custom"})"}) {
        SCOPED_TRACE(body);
        EXPECT_THROW(Parse("vless", body), std::invalid_argument);
    }
    EXPECT_THROW(Parse("shadowsocks", R"({"address":"example.com","key":"secret"})"), std::invalid_argument);
    EXPECT_THROW(Parse("trojan", R"({"servers":[{"address":"example.com","password":"secret"}],"password":"other"})"),
                 std::invalid_argument);
}

TEST(OutboundConfig, VmessUsesItsOwnSecurityNamesAndRetainsImplementedModes) {
    struct Case { std::string_view spelling; proxy::vmess::Security security; };
    for (const auto& test : {
        Case{"chacha20-poly1305", proxy::vmess::Security::CHACHA20_POLY1305},
        Case{"none", proxy::vmess::Security::NONE}, Case{"zero", proxy::vmess::Security::ZERO}}) {
        const auto settings = std::get<infra::VmessSettings>(Parse("vmess",
            std::string(R"({"address":"example.com","id":"b831381d-6324-4d53-ad4f-8cda48b30811","security":")") +
            std::string(test.spelling) + R"("})"));
        EXPECT_EQ(settings.security, test.security);
    }
    EXPECT_THROW(Parse("vmess",
        R"({"address":"example.com","id":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"chacha20-ietf-poly1305"})"),
        std::invalid_argument);
}

struct InvalidSettings { const char* protocol; const char* body; };
class InvalidOutboundSettings : public testing::TestWithParam<InvalidSettings> {};
TEST_P(InvalidOutboundSettings, RejectsUnknownKeysAtEverySchemaLayer) {
    const auto& test = GetParam();
    EXPECT_THROW(Parse(test.protocol, test.body), std::invalid_argument);
}
INSTANTIATE_TEST_SUITE_P(LocalSchema, InvalidOutboundSettings, testing::Values(
    InvalidSettings{"freedom", R"({"domainStratgey":"UseIP"})"},
    InvalidSettings{"blackhole", R"({"response":{"type":"http","status":403}})"},
    InvalidSettings{"blackhole", R"({"unknown":true})"},
    InvalidSettings{"anytls", R"({"address":"example.com","port":443,"password":"secret","unknown":true})"},
    InvalidSettings{"trojan", R"({"servers":[{"address":"example.com","password":"secret","unknown":true}]})"},
    InvalidSettings{"shadowsocks", R"({"servers":[{"address":"example.com","password":"secret","unknown":true}]})"},
    InvalidSettings{"shadowsocks", R"({"address":"example.com","password":"secret","uot":{"version":2,"unknown":true}})"},
    InvalidSettings{"vless", R"({"vnext":[{"address":"example.com","unknown":true,"users":[{"id":"custom"}]}]})"},
    InvalidSettings{"vless", R"({"vnext":[{"address":"example.com","users":[{"id":"custom","unknown":true}]}]})"},
    InvalidSettings{"vmess", R"({"vnext":[{"address":"example.com","users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","unknown":true}]}]})"}
));

TEST(OutboundConfig, EndpointValidationRejectsWrongTypesAndAmbiguousArrays) {
    for (const auto body : {
        R"({"address":"example.com","port":"443","password":"secret"})",
        R"({"address":"example.com","port":0,"password":"secret"})",
        R"({"address":"example.com:443","password":"secret"})",
        R"({"servers":null})", R"({"servers":[]})", R"({"servers":[null]})",
        R"({"servers":[{"address":"one.example","password":"secret"},{"address":"two.example","password":"secret"}]})"}) {
        EXPECT_THROW(Parse("trojan", body), std::invalid_argument);
    }
}

TEST(OutboundConfig, FreedomOnlyAcceptsHandlerLevelBinding) {
    const auto source = json::parse(
        R"({"protocol":"freedom","settings":{"sendThrough":"auto"}})",
        json::KeyComparison::AsciiCaseInsensitive);
    EXPECT_THROW(infra::OutboundSourceConfig::FromJson(source.as_object()), std::invalid_argument);
}

}  // namespace
