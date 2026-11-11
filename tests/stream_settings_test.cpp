#include <gtest/gtest.h>

#include "transport/internet/stream_settings.hpp"

TEST(StreamSettings, ParsesSupportedNetworkAndSecurityNames) {
    struct NetworkCase { const char* name; transport::internet::NetworkMode mode; };
    for (const auto& item : {
            NetworkCase{"TCP", transport::internet::NetworkMode::Tcp}, {"raw", transport::internet::NetworkMode::Tcp},
            {"WS", transport::internet::NetworkMode::Ws}, {"WebSocket", transport::internet::NetworkMode::Ws},
            {"HTTPUpgrade", transport::internet::NetworkMode::HttpUpgrade}, {"gRPC", transport::internet::NetworkMode::Grpc},
            {"HTTP", transport::internet::NetworkMode::Http}, {"h2", transport::internet::NetworkMode::Http},
            {"XHTTP", transport::internet::NetworkMode::XHttp}, {"splithttp", transport::internet::NetworkMode::XHttp},
            {"unknown", transport::internet::NetworkMode::Unsupported}}) {
        EXPECT_EQ(transport::internet::ParseNetworkMode(item.name), item.mode) << item.name;
    }
    EXPECT_EQ(transport::internet::ParseSecurityMode("NONE"), transport::internet::SecurityMode::None);
    EXPECT_EQ(transport::internet::ParseSecurityMode("TLS"), transport::internet::SecurityMode::Tls);
    EXPECT_EQ(transport::internet::ParseSecurityMode("Reality"), transport::internet::SecurityMode::Reality);
    EXPECT_EQ(transport::internet::ParseSecurityMode("unknown"), transport::internet::SecurityMode::Unsupported);
}

TEST(StreamSettings, AlpnSelectionFollowsTransportAndSecurityRequirements) {
    struct AlpnCase {
        transport::internet::NetworkMode network;
        transport::internet::SecurityMode security;
        transport::internet::XHttpMode mode;
        bool force_http2;
        bool h2;
    };
    for (const auto& item : {
            AlpnCase{transport::internet::NetworkMode::Grpc, transport::internet::SecurityMode::Tls, transport::internet::XHttpMode::Auto, false, true},
            {transport::internet::NetworkMode::Grpc, transport::internet::SecurityMode::None, transport::internet::XHttpMode::Auto, false, false},
            {transport::internet::NetworkMode::Http, transport::internet::SecurityMode::None, transport::internet::XHttpMode::Auto, true, true},
            {transport::internet::NetworkMode::Http, transport::internet::SecurityMode::None, transport::internet::XHttpMode::Auto, false, false},
            {transport::internet::NetworkMode::Http, transport::internet::SecurityMode::Tls, transport::internet::XHttpMode::Auto, false, true},
            {transport::internet::NetworkMode::XHttp, transport::internet::SecurityMode::None, transport::internet::XHttpMode::Auto, false, true},
            {transport::internet::NetworkMode::XHttp, transport::internet::SecurityMode::None, transport::internet::XHttpMode::PacketUp, false, false},
            {transport::internet::NetworkMode::XHttp, transport::internet::SecurityMode::Tls, transport::internet::XHttpMode::PacketUp, false, true},
            {transport::internet::NetworkMode::XHttp, transport::internet::SecurityMode::Reality, transport::internet::XHttpMode::Auto, false, false}}) {
        transport::internet::StreamSettings source;
        source.network_mode = item.network;
        source.security_mode = item.security;
        source.http.force_http2 = item.force_http2;
        source.xhttp.mode = item.mode;
        const auto result = transport::internet::NormalizeStreamSettings(source);
        EXPECT_EQ(result.tls.alpn, (item.h2 ? std::vector<std::string>{"h2"} :
                                           std::vector<std::string>{}));
    }
}

TEST(StreamSettings, GrpcAddsRequiredH2WhileHttpPreservesExplicitAlpn) {
    transport::internet::StreamSettings source;
    source.network_mode = transport::internet::NetworkMode::Grpc;
    source.security_mode = transport::internet::SecurityMode::Tls;
    source.tls.alpn = {"http/1.1"};
    EXPECT_EQ(transport::internet::NormalizeStreamSettings(source).tls.alpn, (std::vector<std::string>{"h2", "http/1.1"}));
    source.network_mode = transport::internet::NetworkMode::Http;
    EXPECT_EQ(transport::internet::NormalizeStreamSettings(source).tls.alpn, source.tls.alpn);
}

TEST(StreamSettings, OutboundFallbackCannotReplaceExplicitTlsIdentityOrAlpn) {
    const std::vector<std::string> alpn{"custom"};
    const transport::internet::OutboundStreamDefaults defaults{
        .require_tls = true, .fallback_server_name = "fallback.example",
        .allow_insecure = true, .alpn = alpn};
    transport::internet::StreamSettings source;
    source.network_mode = transport::internet::NetworkMode::Grpc;
    EXPECT_EQ(transport::internet::NormalizeOutboundStreamSettings(source, defaults).tls.alpn,
              (std::vector<std::string>{"h2"}));
    source.network_mode = transport::internet::NetworkMode::Tcp;
    source.tls.server_name = "explicit.example";
    source.tls.alpn = {"explicit"};
    const auto result = transport::internet::NormalizeOutboundStreamSettings(source, defaults);
    EXPECT_EQ(result.tls.server_name, "explicit.example");
    EXPECT_EQ(result.tls.alpn, (std::vector<std::string>{"explicit"}));
}

TEST(StreamSettings, RealityConstrainsTlsTo13) {
    transport::internet::StreamSettings source;
    source.security_mode = transport::internet::SecurityMode::Reality;
    source.tls.min_version = transport::internet::TlsVersion::V1_2;
    source.tls.max_version = transport::internet::TlsVersion::V1_2;
    const auto result = transport::internet::NormalizeStreamSettings(source);
    EXPECT_EQ(result.tls.min_version, transport::internet::TlsVersion::V1_3);
    EXPECT_EQ(result.tls.max_version, transport::internet::TlsVersion::V1_3);
}

TEST(StreamSettings, ProtocolRequestPathsIncludeOnlyTheirWireComponents) {
    transport::internet::XHttpConfig xhttp;
    xhttp.path = "demo?x=1";
    EXPECT_EQ(xhttp.NormalizedPath(), "/demo/");
    transport::internet::GrpcConfig grpc;
    grpc.service_name = "service";
    EXPECT_EQ(grpc.RequestPath(), "/service/Tun");
    grpc.multi_mode = true;
    EXPECT_EQ(grpc.RequestPath(), "/service/TunMulti");
}

TEST(StreamSettings, ExplicitHttpUpgradeHostOverridesHeader) {
    transport::internet::StreamSettings source;
    source.network_mode = transport::internet::NetworkMode::HttpUpgrade;
    source.http_upgrade.headers.emplace("Host", "header.example");
    EXPECT_EQ(transport::internet::NormalizeStreamSettings(source).configured_http_host, "header.example");
    source.http_upgrade.host = "field.example";
    EXPECT_EQ(transport::internet::NormalizeStreamSettings(source).configured_http_host, "field.example");
}

TEST(StreamSettings, XHttpAutoModeUsesSecurityAndSeparateDownload) {
    struct ModeCase { transport::internet::SecurityMode security; bool download; transport::internet::XHttpMode expected; };
    for (const auto& item : {
            ModeCase{transport::internet::SecurityMode::None, false, transport::internet::XHttpMode::PacketUp},
            {transport::internet::SecurityMode::Tls, false, transport::internet::XHttpMode::StreamUp},
            {transport::internet::SecurityMode::Reality, false, transport::internet::XHttpMode::StreamOne},
            {transport::internet::SecurityMode::Reality, true, transport::internet::XHttpMode::StreamUp}}) {
        transport::internet::StreamSettings source;
        source.network_mode = transport::internet::NetworkMode::XHttp;
        source.security_mode = item.security;
        if (item.download) source.xhttp.download_settings = std::make_shared<transport::internet::XHttpDownloadSettings>();
        EXPECT_EQ(transport::internet::ResolveXHttpOutboundMode(transport::internet::NormalizeStreamSettings(source)), item.expected);
    }
}
