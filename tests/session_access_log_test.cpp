#include <gtest/gtest.h>

#include "common/session.hpp"

#include <asio/ip/address.hpp>

#include <string>

namespace {
class SessionAccessLog : public ::testing::Test {
protected:
    void SetUp() override {
        ctx.inbound.source_addr = ::net::ip::make_address("192.0.2.10");
        ctx.inbound.source_port = 52000;
        ctx.inbound.tag = "panel/hj-anytls/1041/anytls/55911";
        ctx.inbound.user_id = 714443;
        ctx.inbound.user_email = "panel/hj-anytls/1041|714443|714443";
        ctx.outbound.target = ::common::TargetAddress("example.com", 443);
        ctx.outbound.tag = "direct";
        ctx.outbound.connected_local_addr = ::net::ip::make_address("2602:2b5:20:111::abcd");
    }
    ::common::Context ctx;
};

TEST_F(SessionAccessLog, ReportsEndpointsRouteVerifiedIdentityAndActualLocalAddress) {
    const auto access = ::common::FormatAccessLog(ctx);
    EXPECT_NE(access.find("192.0.2.10:52000"), std::string::npos);
    EXPECT_NE(access.find("tcp:example.com:443"), std::string::npos);
    EXPECT_NE(access.find("[panel/hj-anytls/1041/anytls/55911 -> direct]"), std::string::npos);
    EXPECT_NE(access.find(" user:714443 "), std::string::npos);
    EXPECT_NE(access.find(" email:panel/hj-anytls/1041|714443|714443 "), std::string::npos);
    EXPECT_NE(access.find(" sendThrough:2602:2b5:20:111::abcd"), std::string::npos);
}

TEST_F(SessionAccessLog, ReportsRouteOnlySniffProtocolAndTarget) {
    ctx.content.network = ::common::Network::UDP;
    ctx.content.protocol = "quic";
    ctx.outbound.target =
        ::common::TargetAddress(::net::ip::make_address("198.18.1.96"), 443);
    ctx.outbound.route_target =
        ::common::TargetAddress("chatgpt.com", 443);

    const auto access = ::common::FormatAccessLog(ctx);

    EXPECT_NE(
        access.find(
            "accepted udp:198.18.1.96:443 "
            "[panel/hj-anytls/1041/anytls/55911 -> direct] "
            "sniff:quic|chatgpt.com:443 user:714443"),
        std::string::npos);
}

TEST_F(SessionAccessLog, ReportsSniffTargetAfterDestinationOverride) {
    ctx.content.protocol = "tls";
    ctx.outbound.original_target =
        ::common::TargetAddress(::net::ip::make_address("198.18.1.96"), 443);
    ctx.outbound.target = ::common::TargetAddress("chatgpt.com", 443);

    const auto access = ::common::FormatAccessLog(ctx);

    EXPECT_NE(
        access.find("sniff:tls|chatgpt.com:443 user:714443"),
        std::string::npos);
}

TEST_F(SessionAccessLog, ReportsRecognizedProtocolWithoutDestinationOverride) {
    ctx.content.protocol = "bittorrent";

    const auto access = ::common::FormatAccessLog(ctx);

    EXPECT_NE(
        access.find("sniff:bittorrent user:714443"),
        std::string::npos);
    EXPECT_EQ(access.find("sniff:bittorrent|"), std::string::npos);
}

TEST_F(SessionAccessLog, ForwardedOriginDoesNotReplaceVerifiedLocalIdentity) {
    ctx.inbound.ApplyForwardedMetadata(::common::ForwardedMetadata{
        .user_id = 1001,
        .user_email = "alice@origin.example",
        .client_ip = ::net::ip::make_address("203.0.113.88"),
        .inbound_tag = "panel/site-a/10/vless/443",
    });
    const auto access = ::common::FormatAccessLog(ctx);
    EXPECT_NE(access.find(" origin:203.0.113.88|panel/site-a/10/vless/443|1001|alice@origin.example "), std::string::npos);
    EXPECT_NE(access.find(" user:714443 "), std::string::npos);
    EXPECT_NE(access.find(" email:panel/hj-anytls/1041|714443|714443 "), std::string::npos);
    EXPECT_NE(access.find(" sendThrough:2602:2b5:20:111::abcd"), std::string::npos);
}

TEST_F(SessionAccessLog, PartialForwardedMetadataReplacesRatherThanMergesOrigin) {
    ctx.inbound.ApplyForwardedMetadata(::common::ForwardedMetadata{
        .user_id = 1001,
        .user_email = "alice@origin.example",
        .client_ip = ::net::ip::make_address("203.0.113.88"),
        .inbound_tag = "panel/site-a/10/vless/443",
    });
    ::common::ForwardedMetadata partial;
    partial.user_email = "bob@origin.example";
    ctx.inbound.ApplyForwardedMetadata(partial);
    EXPECT_TRUE(ctx.inbound.origin_tag.empty());
    EXPECT_EQ(ctx.inbound.origin_user_id, 0);
    EXPECT_EQ(ctx.inbound.origin_user_email, "bob@origin.example");
    EXPECT_TRUE(ctx.inbound.origin_source_addr.is_unspecified());
    EXPECT_TRUE(ctx.inbound.origin_source_ip.empty());
}

TEST_F(SessionAccessLog, EmptyForwardedMetadataClearsPreviousOrigin) {
    ctx.inbound.ApplyForwardedMetadata(::common::ForwardedMetadata{
        .user_id = 1001,
        .user_email = "alice@origin.example",
        .client_ip = ::net::ip::make_address("203.0.113.88"),
        .inbound_tag = "panel/site-a/10/vless/443",
    });
    ctx.inbound.ApplyForwardedMetadata(::common::ForwardedMetadata{});
    EXPECT_FALSE(ctx.inbound.HasOriginIdentity());
    EXPECT_TRUE(ctx.inbound.origin_source_addr.is_unspecified());
    EXPECT_TRUE(ctx.inbound.origin_source_ip.empty());
}

TEST_F(SessionAccessLog, SelfAliasedSubstreamInitializationPreservesIdentityAndResetsContent) {
    ctx.worker_id = 7;
    ctx.content.speed_limit = 123456;
    ctx.content.network = ::common::Network::UDP;
    ctx.content.protocol = "quic";
    ctx.InitSubstreamFrom(ctx, 53000);
    EXPECT_EQ(ctx.worker_id, 7);
    EXPECT_EQ(ctx.inbound.source_port, 53000);
    EXPECT_EQ(ctx.inbound.tag, "panel/hj-anytls/1041/anytls/55911");
    EXPECT_EQ(ctx.outbound.tag, "direct");
    EXPECT_EQ(ctx.content.speed_limit, 123456);
    EXPECT_EQ(ctx.content.network, ::common::Network::TCP);
    EXPECT_TRUE(ctx.content.protocol.empty());
}

TEST_F(SessionAccessLog, NumericEmailDoesNotDuplicateVerifiedUserId) {
    ctx.inbound.user_email = "714443";
    const auto access = ::common::FormatAccessLog(ctx);
    EXPECT_NE(access.find(" user:714443 "), std::string::npos);
    EXPECT_EQ(access.find("email:"), std::string::npos);
}

TEST_F(SessionAccessLog, StaticEmailDoesNotInventUserIdOrLocalAddress) {
    ctx.inbound.user_id = 0;
    ctx.inbound.user_email = "user@example.com";
    ctx.outbound.connected_local_addr.reset();
    const auto access = ::common::FormatAccessLog(ctx);
    EXPECT_NE(access.find(" email:user@example.com"), std::string::npos);
    EXPECT_EQ(access.find(" user:"), std::string::npos);
    EXPECT_EQ(access.find("sendThrough:"), std::string::npos);
}

TEST_F(SessionAccessLog, AdmissionRejectionPreservesAuthenticatedStaticEmail) {
    ctx.inbound.user_id = 0;
    ctx.inbound.user_email = "user@example.com";
    const auto access = ::common::FormatAccessLog(ctx, ::common::AccessStatus::Rejected, "device limit exceeded");
    EXPECT_NE(access.find(" email:user@example.com"), std::string::npos);
    EXPECT_EQ(access.find(" user:"), std::string::npos);
}

TEST_F(SessionAccessLog, PreauthenticationRejectionOmitsUnverifiedIdentityAndRoute) {
    ctx.inbound.user_id = 0;
    ctx.inbound.user_email.clear();
    ctx.outbound.target = {};
    ctx.outbound.tag = {};
    const auto access = ::common::FormatAccessLog(ctx, ::common::AccessStatus::Rejected, "authentication failed");
    EXPECT_NE(access.find("192.0.2.10:52000"), std::string::npos);
    EXPECT_NE(access.find("[panel/hj-anytls/1041/anytls/55911]"), std::string::npos);
    EXPECT_EQ(access.find("user:"), std::string::npos);
    EXPECT_EQ(access.find("email:"), std::string::npos);
    EXPECT_EQ(access.find("tcp:"), std::string::npos);
    EXPECT_EQ(access.find(" -> "), std::string::npos);
}

TEST_F(SessionAccessLog, RejectionDoesNotExposeMalformedDestination) {
    ctx.outbound.target = ::common::TargetAddress("invalid host", 443);
    const auto access = ::common::FormatAccessLog(ctx, ::common::AccessStatus::Rejected, "invalid target");
    EXPECT_EQ(access.find("invalid host"), std::string::npos);
    EXPECT_EQ(access.find("tcp:"), std::string::npos);
}

TEST_F(SessionAccessLog, AdmissionRejectionPreservesVerifiedUserAndDestination) {
    ctx.inbound.user_email = "714443";
    const auto access = ::common::FormatAccessLog(ctx, ::common::AccessStatus::Rejected, "device limit exceeded");
    EXPECT_NE(access.find("tcp:example.com:443"), std::string::npos);
    EXPECT_NE(access.find("user:714443"), std::string::npos);
}

TEST_F(SessionAccessLog, Ipv6EndpointPortsHaveUnambiguousBoundaries) {
    ctx.inbound.source_ip = "2001:db8::1";
    ctx.outbound.target = ::common::TargetAddress("2001:db8::2", 65535);
    const auto access = ::common::FormatAccessLog(ctx);
    EXPECT_NE(access.find("[2001:db8::1]:52000"), std::string::npos);
    EXPECT_NE(access.find("tcp:[2001:db8::2]:65535"), std::string::npos);
}

TEST_F(SessionAccessLog, NormalizesIpv4MappedEndpointIdentity) {
    ctx.inbound.source_addr = ::net::ip::make_address("::ffff:192.0.2.1");
    ctx.outbound.target = ::common::TargetAddress(::net::ip::make_address("::ffff:198.51.100.1"), 443);
    const auto access = ::common::FormatAccessLog(ctx);
    EXPECT_NE(access.find("192.0.2.1:52000"), std::string::npos);
    EXPECT_NE(access.find("tcp:198.51.100.1:443"), std::string::npos);
}

TEST_F(SessionAccessLog, MissingPreauthenticationFieldsDoNotInventIdentity) {
    ctx.inbound.source_addr = ::net::ip::address{};
    ctx.inbound.user_id = 0;
    ctx.inbound.user_email.clear();
    ctx.outbound.target = {};
    const auto access = ::common::FormatAccessLog(ctx, ::common::AccessStatus::Rejected, "connection limit exceeded");
    EXPECT_EQ(access.find("email:"), std::string::npos);
    EXPECT_EQ(access.find("user:"), std::string::npos);
}
}  // namespace
