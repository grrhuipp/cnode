#include <gtest/gtest.h>

#include "transport/stream_settings.hpp"
TEST(StreamSettings, ParsesSupportedNetworkAndSecurityNames) {
    struct NetworkCase { const char* name; transport::NetworkMode mode; };
    for (const auto& item : {
            NetworkCase{"TCP", transport::NetworkMode::Tcp}, {"raw", transport::NetworkMode::Tcp},
            {"WS", transport::NetworkMode::Ws}, {"WebSocket", transport::NetworkMode::Ws},
            {"HTTPUpgrade", transport::NetworkMode::HttpUpgrade}, {"gRPC", transport::NetworkMode::Grpc},
            {"HTTP", transport::NetworkMode::Http}, {"h2", transport::NetworkMode::Http},
            {"XHTTP", transport::NetworkMode::XHttp}, {"splithttp", transport::NetworkMode::XHttp},
            {"unknown", transport::NetworkMode::Unsupported}}) {
        EXPECT_EQ(transport::ParseNetworkMode(item.name), item.mode) << item.name;
    }
    EXPECT_EQ(transport::ParseSecurityMode("NONE"), transport::SecurityMode::None);
    EXPECT_EQ(transport::ParseSecurityMode("TLS"), transport::SecurityMode::Tls);
    EXPECT_EQ(transport::ParseSecurityMode("Reality"), transport::SecurityMode::Reality);
    EXPECT_EQ(transport::ParseSecurityMode("unknown"), transport::SecurityMode::Unsupported);
}

TEST(StreamSettings, AlpnSelectionFollowsTransportAndSecurityRequirements) {
    struct AlpnCase {
        transport::NetworkMode network;
        transport::SecurityMode security;
        transport::XHttpMode mode;
        bool force_http2;
        bool h2;
    };
    for (const auto& item : {
            AlpnCase{transport::NetworkMode::Grpc, transport::SecurityMode::Tls, transport::XHttpMode::Auto, false, true},
            {transport::NetworkMode::Grpc, transport::SecurityMode::None, transport::XHttpMode::Auto, false, false},
            {transport::NetworkMode::Http, transport::SecurityMode::None, transport::XHttpMode::Auto, true, true},
            {transport::NetworkMode::Http, transport::SecurityMode::None, transport::XHttpMode::Auto, false, false},
            {transport::NetworkMode::Http, transport::SecurityMode::Tls, transport::XHttpMode::Auto, false, true},
            {transport::NetworkMode::XHttp, transport::SecurityMode::None, transport::XHttpMode::Auto, false, true},
            {transport::NetworkMode::XHttp, transport::SecurityMode::None, transport::XHttpMode::PacketUp, false, false},
            {transport::NetworkMode::XHttp, transport::SecurityMode::Tls, transport::XHttpMode::PacketUp, false, true},
            {transport::NetworkMode::XHttp, transport::SecurityMode::Reality, transport::XHttpMode::Auto, false, false}}) {
        transport::StreamSettings source;
        source.network_mode = item.network;
        source.security_mode = item.security;
        source.http.force_http2 = item.force_http2;
        source.xhttp.mode = item.mode;
        const auto result = transport::NormalizeStreamSettings(source);
        EXPECT_EQ(result.tls.alpn, (item.h2 ? std::vector<std::string>{"h2"} :
                                           std::vector<std::string>{}));
    }
}

TEST(StreamSettings, GrpcAddsRequiredH2WhileHttpPreservesExplicitAlpn) {
    transport::StreamSettings source;
    source.network_mode = transport::NetworkMode::Grpc;
    source.security_mode = transport::SecurityMode::Tls;
    source.tls.alpn = {"http/1.1"};
    EXPECT_EQ(transport::NormalizeStreamSettings(source).tls.alpn, (std::vector<std::string>{"h2", "http/1.1"}));
    source.network_mode = transport::NetworkMode::Http;
    EXPECT_EQ(transport::NormalizeStreamSettings(source).tls.alpn, source.tls.alpn);
}

TEST(StreamSettings, OutboundFallbackCannotReplaceExplicitTlsIdentityOrAlpn) {
    const std::vector<std::string> alpn{"custom"};
    const transport::OutboundStreamDefaults defaults{
        .require_tls = true, .fallback_server_name = "fallback.example",
        .allow_insecure = true, .alpn = alpn};
    transport::StreamSettings source;
    source.network_mode = transport::NetworkMode::Grpc;
    EXPECT_EQ(transport::NormalizeOutboundStreamSettings(source, defaults).tls.alpn,
              (std::vector<std::string>{"h2"}));
    source.network_mode = transport::NetworkMode::Tcp;
    source.tls.server_name = "explicit.example";
    source.tls.alpn = {"explicit"};
    const auto result = transport::NormalizeOutboundStreamSettings(source, defaults);
    EXPECT_EQ(result.tls.server_name, "explicit.example");
    EXPECT_EQ(result.tls.alpn, (std::vector<std::string>{"explicit"}));
}

TEST(StreamSettings, RealityConstrainsTlsTo13) {
    transport::StreamSettings source;
    source.security_mode = transport::SecurityMode::Reality;
    source.tls.min_version = transport::TlsVersion::V1_2;
    source.tls.max_version = transport::TlsVersion::V1_2;
    const auto result = transport::NormalizeStreamSettings(source);
    EXPECT_EQ(result.tls.min_version, transport::TlsVersion::V1_3);
    EXPECT_EQ(result.tls.max_version, transport::TlsVersion::V1_3);
}

TEST(StreamSettings, ProtocolRequestPathsIncludeOnlyTheirWireComponents) {
    transport::XHttpConfig xhttp;
    xhttp.path = "demo?x=1";
    EXPECT_EQ(xhttp.NormalizedPath(), "/demo/");
    transport::GrpcConfig grpc;
    grpc.service_name = "service";
    EXPECT_EQ(grpc.RequestPath(), "/service/Tun");
    grpc.multi_mode = true;
    EXPECT_EQ(grpc.RequestPath(), "/service/TunMulti");
}

TEST(StreamSettings, ExplicitHttpUpgradeHostOverridesHeader) {
    transport::StreamSettings source;
    source.network_mode = transport::NetworkMode::HttpUpgrade;
    source.http_upgrade.headers.emplace("Host", "header.example");
    EXPECT_EQ(transport::NormalizeStreamSettings(source).configured_http_host, "header.example");
    source.http_upgrade.host = "field.example";
    EXPECT_EQ(transport::NormalizeStreamSettings(source).configured_http_host, "field.example");
}

TEST(StreamSettings, XHttpAutoModeUsesSecurityAndSeparateDownload) {
    struct ModeCase { transport::SecurityMode security; bool download; transport::XHttpMode expected; };
    for (const auto& item : {
            ModeCase{transport::SecurityMode::None, false, transport::XHttpMode::PacketUp},
            {transport::SecurityMode::Tls, false, transport::XHttpMode::StreamUp},
            {transport::SecurityMode::Reality, false, transport::XHttpMode::StreamOne},
            {transport::SecurityMode::Reality, true, transport::XHttpMode::StreamUp}}) {
        transport::StreamSettings source;
        source.network_mode = transport::NetworkMode::XHttp;
        source.security_mode = item.security;
        if (item.download) source.xhttp.download_settings = std::make_shared<transport::XHttpDownloadSettings>();
        EXPECT_EQ(transport::ResolveXHttpOutboundMode(transport::NormalizeStreamSettings(source)), item.expected);
    }
}
