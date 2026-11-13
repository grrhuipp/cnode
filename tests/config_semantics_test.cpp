#include <gtest/gtest.h>

#include "infra/config.hpp"
#include "common/constants.hpp"
#include <vector>

namespace {

::infra::OutboundSourceConfig Outbound(const char* tag) {
    ::infra::OutboundSourceConfig outbound;
    outbound.tag = tag;
    outbound.protocol = "test";
    return outbound;
}

::infra::RouteRuleConfig Rule(const char* tag) {
    ::infra::RouteRuleConfig rule;
    rule.domain_suffix.push_back("example.com");
    rule.outbound_tag = tag;
    return rule;
}

::infra::StaticInboundConfig Inbound(
    const char* tag, const char* listen, uint16_t port) {
    ::infra::StaticInboundConfig inbound;
    inbound.tags.push_back(tag);
    inbound.protocol = "vmess";
    inbound.listen = *::transport::InboundListen::Parse(listen);
    inbound.port = port;
    return inbound;
}

}  // namespace

TEST(ConfigSemantics, RequiresAtLeastOneOutbound) {
    EXPECT_EQ(infra::ValidateOutboundSelectionSemantics({}, {}, {}).error,
              infra::ConfigSemanticError::NoOutbounds);
}

TEST(ConfigSemantics, RejectsEmptyOutboundTag) {
    const std::vector outbounds{Outbound("")};
    const auto result = infra::ValidateOutboundSelectionSemantics(outbounds, {}, {});
    EXPECT_EQ(result.error, infra::ConfigSemanticError::EmptyOutboundTag);
    EXPECT_EQ(result.index, 0U);
}

TEST(ConfigSemantics, ReportsBothIdentityAndPositionOfDuplicateOutbound) {
    const std::vector outbounds{Outbound("direct"), Outbound("direct")};
    const auto result = infra::ValidateOutboundSelectionSemantics(outbounds, {}, {});
    EXPECT_EQ(result.error, infra::ConfigSemanticError::DuplicateOutboundTag);
    EXPECT_EQ(result.index, 1U);
    EXPECT_EQ(result.tag, "direct");
}

TEST(ConfigSemantics, RejectsEmptyRouteOutboundTag) {
    const std::vector outbounds{Outbound("direct")};
    const std::vector rules{Rule("")};
    const auto result = infra::ValidateOutboundSelectionSemantics(outbounds, rules, {});
    EXPECT_EQ(result.error, infra::ConfigSemanticError::EmptyRouteOutboundTag);
    EXPECT_EQ(result.index, 0U);
}

TEST(ConfigSemantics, ReportsFirstUnresolvedRouteWithoutSkippingValidRules) {
    const std::vector outbounds{Outbound("direct"), Outbound("blackhole")};
    const std::vector rules{Rule("direct"), Rule("missing"), Rule("other-missing")};
    const auto result = infra::ValidateOutboundSelectionSemantics(outbounds, rules, {});
    EXPECT_EQ(result.error, infra::ConfigSemanticError::UnknownRouteOutboundTag);
    EXPECT_EQ(result.index, 1U);
    EXPECT_EQ(result.tag, "missing");
}

TEST(ConfigSemantics, AcceptsRoutesReferencingConfiguredOutbounds) {
    const std::vector outbounds{Outbound("direct"), Outbound("blackhole")};
    const std::vector rules{Rule("direct"), Rule("blackhole")};
    EXPECT_TRUE(infra::ValidateOutboundSelectionSemantics(outbounds, rules, {}).Ok());
}

TEST(ConfigSemantics, RejectsZeroInboundPort) {
    const std::vector inbounds{Inbound("first", "127.0.0.1", 0)};
    const auto result = infra::ValidateStaticInboundSemantics(inbounds);
    EXPECT_EQ(result.error, infra::StaticInboundSemanticError::InvalidPort);
    EXPECT_EQ(result.index, 0U);
}

TEST(ConfigSemantics, RejectsEmptyInboundTag) {
    const std::vector inbounds{Inbound("", "127.0.0.1", 12001)};
    const auto result = infra::ValidateStaticInboundSemantics(inbounds);
    EXPECT_EQ(result.error, infra::StaticInboundSemanticError::EmptyTag);
    EXPECT_EQ(result.index, 0U);
}

TEST(ConfigSemantics, DuplicateInboundTagsConflictAcrossDistinctEndpoints) {
    const std::vector inbounds{
        Inbound("same", "127.0.0.1", 12001),
        Inbound("same", "127.0.0.2", 12001)};
    const auto result = infra::ValidateStaticInboundSemantics(inbounds);
    EXPECT_EQ(result.error, infra::StaticInboundSemanticError::DuplicateTag);
    EXPECT_EQ(result.index, 1U);
    EXPECT_EQ(result.conflicting_index, 0U);
    EXPECT_EQ(result.detail, "same");
}

namespace {
struct InboundEndpointCase {
    const char* name;
    const char* first;
    uint16_t first_port;
    const char* second;
    uint16_t second_port;
    bool conflicts;
};
class InboundEndpointSemantics : public testing::TestWithParam<InboundEndpointCase> {};
}  // namespace

TEST_P(InboundEndpointSemantics, DetectsOverlapIndependentlyOfDeclarationOrder) {
    const auto& test = GetParam();
    for (bool reverse : {false, true}) {
        SCOPED_TRACE(reverse);
        std::vector inbounds{
            Inbound("first", test.first, test.first_port),
            Inbound("second", test.second, test.second_port)};
        if (reverse) std::swap(inbounds[0], inbounds[1]);
        const auto result = infra::ValidateStaticInboundSemantics(inbounds);
        if (test.conflicts) {
            EXPECT_EQ(result.error, infra::StaticInboundSemanticError::DuplicateEndpoint);
            EXPECT_EQ(result.index, 1U);
            EXPECT_EQ(result.conflicting_index, 0U);
        } else {
            EXPECT_TRUE(result.Ok());
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    ListenBoundaries, InboundEndpointSemantics,
    testing::Values(
        InboundEndpointCase{"SameAddress", "127.0.0.1", 12001, "127.0.0.1", 12001, true},
        InboundEndpointCase{"AutoAndWildcard", "auto", 12001, "0.0.0.0", 12001, true},
        InboundEndpointCase{"AutoAndSpecific", "auto", 12001, "127.0.0.1", 12001, true},
        InboundEndpointCase{"WildcardAndSpecific", "0.0.0.0", 12001, "127.0.0.1", 12001, true},
        InboundEndpointCase{"DistinctAddresses", "127.0.0.1", 12001, "127.0.0.2", 12001, false},
        InboundEndpointCase{"Ipv6OnlyAndIpv4", "::", 12001, "127.0.0.1", 12001, false},
        InboundEndpointCase{"DistinctPorts", "auto", 12002, "127.0.0.1", 12001, false}),
    [](const testing::TestParamInfo<InboundEndpointCase>& test) { return test.param.name; });

TEST(ConfigSemantics, PanelTagsDistinguishPanelAndNodeIdentity) {
    const auto first = common::BuildPanelNodeTag("same-panel", 1, "vmess", 12001);
    EXPECT_NE(first, common::BuildPanelNodeTag("same-panel", 2, "vmess", 12001));
    EXPECT_NE(first, common::BuildPanelNodeTag("other-panel", 1, "vmess", 12001));
}

TEST(ConfigSemantics, StaticInboundCannotClaimPanelNamespace) {
    auto inbound = Inbound("first", "127.0.0.1", 12001);
    inbound.tags[0] = common::BuildPanelNodeTag("same-panel", 1, "vmess", 12001);
    const std::vector inbounds{inbound};
    const auto result = infra::ValidateStaticInboundSemantics(inbounds);
    EXPECT_EQ(result.error, infra::StaticInboundSemanticError::ReservedTag);
    EXPECT_EQ(result.detail, inbound.tags[0]);
}

TEST(ConfigSemantics, StaticOutboundCannotClaimPanelNamespace) {
    auto outbound = Outbound("direct");
    outbound.tag = common::BuildPanelNodeTag("same-panel", 1, "vmess", 12001);
    const std::vector outbounds{outbound};
    const auto result = infra::ValidateOutboundSelectionSemantics(outbounds, {}, {});
    EXPECT_EQ(result.error, infra::ConfigSemanticError::ReservedOutboundTag);
    EXPECT_EQ(result.tag, outbound.tag);
}

TEST(ConfigSemantics, AcceptsConfiguredForcedOutboundAndExplicitRouting) {
    const std::vector outbounds{Outbound("direct"), Outbound("blackhole")};
    std::vector inbounds{Inbound("forced", "127.0.0.1", 12001)};
    inbounds[0].outbound_tag = "blackhole";
    EXPECT_TRUE(infra::ValidateOutboundSelectionSemantics(outbounds, {}, inbounds).Ok());
    inbounds[0].outbound_tag.reset();
    EXPECT_TRUE(infra::ValidateOutboundSelectionSemantics(outbounds, {}, inbounds).Ok());
}

TEST(ConfigSemantics, RejectsEmptyForcedOutbound) {
    const std::vector outbounds{Outbound("direct")};
    std::vector inbounds{Inbound("forced", "127.0.0.1", 12001)};
    inbounds[0].outbound_tag = "";
    const auto result = infra::ValidateOutboundSelectionSemantics(outbounds, {}, inbounds);
    EXPECT_EQ(result.error, infra::ConfigSemanticError::EmptyStaticInboundOutboundTag);
    EXPECT_EQ(result.index, 0U);
}

TEST(ConfigSemantics, RejectsUnknownForcedOutbound) {
    const std::vector outbounds{Outbound("direct")};
    std::vector inbounds{Inbound("forced", "127.0.0.1", 12001)};
    inbounds[0].outbound_tag = "missing";
    const auto result = infra::ValidateOutboundSelectionSemantics(outbounds, {}, inbounds);
    EXPECT_EQ(result.error, infra::ConfigSemanticError::UnknownStaticInboundOutboundTag);
    EXPECT_EQ(result.index, 0U);
    EXPECT_EQ(result.tag, "missing");
}

TEST(ConfigSemantics, ConnectionIdleUsesCanonicalKeyAndRejectsMisspelling) {
    const auto canonical = infra::parse(
        R"({"connIdle":17})", infra::KeyComparison::AsciiCaseInsensitive);
    EXPECT_EQ(infra::TimeoutsConfig::FromJson(canonical.as_object()).IdleTimeout(),
              std::chrono::seconds(17));
    const auto misspelled = infra::parse(
        R"({"idle":17})", infra::KeyComparison::AsciiCaseInsensitive);
    EXPECT_THROW(infra::TimeoutsConfig::FromJson(misspelled.as_object()), std::invalid_argument);
}

TEST(ConfigSemantics, UnknownNestedKeysCannotSilentlySelectDefaults) {
    const auto config = [](std::string_view text) {
        return infra::parse(text, infra::KeyComparison::AsciiCaseInsensitive).as_object();
    };
    EXPECT_FALSE(infra::ParseConfig(config(R"({"worker":1})")));
    EXPECT_FALSE(infra::ParseConfig(config(R"({"timeouts":{"connIdel":17}})")));
    EXPECT_THROW(infra::DnsConfig::FromJson(config(R"({"cacheSzie":64})")), std::invalid_argument);
    EXPECT_THROW(infra::LimitsConfig::FromJson(config(R"({"ipBan":{"enable":true}})")),
                 std::invalid_argument);
    EXPECT_THROW(infra::StaticInboundConfig::FromJson(config(
        R"({"port":1080,"protocol":"vmess","settings":{"client":[]}})")),
                 std::invalid_argument);
    EXPECT_THROW(infra::PanelConfig::FromJson(config(R"({"apiHots":"https://example.com"})")),
                 std::invalid_argument);
}

TEST(ConfigSemantics, LogSeverityIsNormalizedBeforeRuntimeInitialization) {
    const auto accepted = infra::parse(
        R"({"loglevel":"WARNING"})", infra::KeyComparison::AsciiCaseInsensitive);
    EXPECT_EQ(infra::LogConfig::FromJson(accepted.as_object()).level, infra::LogLevel::WARN);
    const auto alias = infra::parse(
        R"({"loglevel":"warn"})", infra::KeyComparison::AsciiCaseInsensitive);
    EXPECT_THROW(infra::LogConfig::FromJson(alias.as_object()), std::invalid_argument);
}

TEST(ConfigSemantics, DownloadEndpointKeysAreNotAcceptedAsOrdinaryStreamSettings) {
    const auto ordinary = infra::parse(
        R"({"network":"xhttp","address":"example.com","port":443})",
        infra::KeyComparison::AsciiCaseInsensitive);
    EXPECT_THROW((void)infra::ParseStreamSettings(ordinary.as_object(), transport::StreamEndpointRole::Outbound),
                 std::invalid_argument);
    const auto split = infra::parse(
        R"({"network":"xhttp","xhttpSettings":{"mode":"stream-up","downloadSettings":{
            "address":"example.com","port":443,"network":"xhttp",
            "xhttpSettings":{"path":"/download","mode":"stream-up"}}}})",
        infra::KeyComparison::AsciiCaseInsensitive);
    const auto settings = infra::ParseStreamSettings(split.as_object(), transport::StreamEndpointRole::Outbound);
    ASSERT_TRUE(settings.xhttp.download_settings);
    EXPECT_TRUE(settings.xhttp.download_settings->stream_settings.IsXHttp());
    EXPECT_EQ(settings.xhttp.download_settings->stream_settings.xhttp.normalized_path, "/download/");
}

namespace {
struct StaticClientFieldCase {
    const char* name;
    const char* protocol;
    const char* credential_field;
    const char* invalid_field;
};
class StaticClientSchema : public testing::TestWithParam<StaticClientFieldCase> {};
}  // namespace

TEST_P(StaticClientSchema, RejectsIgnoredOrAmbiguousCredentialFields) {
    const auto& test = GetParam();
    auto source = infra::parse(R"({"port":443,"settings":{"clients":[{}]}})");
    source.as_object()["protocol"] = test.protocol;
    auto& client = source.as_object().at("settings").as_object()
        .at("clients").as_array()[0].as_object();
    constexpr const char* credential = "b831381d-6324-4d53-ad4f-8cda48b30811";
    client[test.credential_field] = credential;
    const auto normalized = infra::StaticInboundConfig::FromJson(source.as_object());
    ASSERT_EQ(normalized.users.size(), 1U);
    EXPECT_EQ(normalized.users.front().credential, credential);
    client[test.invalid_field] = "other-credential";
    EXPECT_THROW((void)infra::StaticInboundConfig::FromJson(source.as_object()), std::invalid_argument);
}

INSTANTIATE_TEST_SUITE_P(
    CredentialBoundaries, StaticClientSchema,
    testing::Values(
        StaticClientFieldCase{"VmessFlow", "vmess", "id", "flow"},
        StaticClientFieldCase{"VlessPassword", "vless", "id", "password"},
        StaticClientFieldCase{"AnytlsId", "anytls", "password", "id"}),
    [](const testing::TestParamInfo<StaticClientFieldCase>& test) { return test.param.name; });
