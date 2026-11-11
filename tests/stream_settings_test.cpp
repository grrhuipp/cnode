#include <gtest/gtest.h>

#include "transport/internet/stream_settings.hpp"

TEST(StreamSettings, ParsesSupportedNetworkAndSecurityNames) {
    struct NetworkCase { const char* name; NetworkMode mode; };
    for (const auto& item : {
            NetworkCase{"TCP", NetworkMode::Tcp}, {"raw", NetworkMode::Tcp},
            {"WS", NetworkMode::Ws}, {"WebSocket", NetworkMode::Ws},
            {"HTTPUpgrade", NetworkMode::HttpUpgrade}, {"gRPC", NetworkMode::Grpc},
            {"HTTP", NetworkMode::Http}, {"h2", NetworkMode::Http},
            {"XHTTP", NetworkMode::XHttp}, {"splithttp", NetworkMode::XHttp},
            {"unknown", NetworkMode::Unsupported}}) {
        EXPECT_EQ(ParseNetworkMode(item.name), item.mode) << item.name;
    }
    EXPECT_EQ(ParseSecurityMode("NONE"), SecurityMode::None);
    EXPECT_EQ(ParseSecurityMode("TLS"), SecurityMode::Tls);
    EXPECT_EQ(ParseSecurityMode("Reality"), SecurityMode::Reality);
    EXPECT_EQ(ParseSecurityMode("unknown"), SecurityMode::Unsupported);
}

TEST(StreamSettings, AlpnSelectionFollowsTransportAndSecurityRequirements) {
    struct AlpnCase {
        NetworkMode network;
        SecurityMode security;
        XHttpMode mode;
        bool force_http2;
        bool h2;
    };
    for (const auto& item : {
            AlpnCase{NetworkMode::Grpc, SecurityMode::Tls, XHttpMode::Auto, false, true},
            {NetworkMode::Grpc, SecurityMode::None, XHttpMode::Auto, false, false},
            {NetworkMode::Http, SecurityMode::None, XHttpMode::Auto, true, true},
            {NetworkMode::Http, SecurityMode::None, XHttpMode::Auto, false, false},
            {NetworkMode::Http, SecurityMode::Tls, XHttpMode::Auto, false, true},
            {NetworkMode::XHttp, SecurityMode::None, XHttpMode::Auto, false, true},
            {NetworkMode::XHttp, SecurityMode::None, XHttpMode::PacketUp, false, false},
            {NetworkMode::XHttp, SecurityMode::Tls, XHttpMode::PacketUp, false, true},
            {NetworkMode::XHttp, SecurityMode::Reality, XHttpMode::Auto, false, false}}) {
        StreamSettings source;
        source.network_mode = item.network;
        source.security_mode = item.security;
        source.http.force_http2 = item.force_http2;
        source.xhttp.mode = item.mode;
        const auto result = NormalizeStreamSettings(source);
        EXPECT_EQ(result.tls.alpn, (item.h2 ? std::vector<std::string>{"h2"} :
                                           std::vector<std::string>{}));
    }
}

TEST(StreamSettings, GrpcAddsRequiredH2WhileHttpPreservesExplicitAlpn) {
    StreamSettings source;
    source.network_mode = NetworkMode::Grpc;
    source.security_mode = SecurityMode::Tls;
    source.tls.alpn = {"http/1.1"};
    EXPECT_EQ(NormalizeStreamSettings(source).tls.alpn, (std::vector<std::string>{"h2", "http/1.1"}));
    source.network_mode = NetworkMode::Http;
    EXPECT_EQ(NormalizeStreamSettings(source).tls.alpn, source.tls.alpn);
}

TEST(StreamSettings, OutboundFallbackCannotReplaceExplicitTlsIdentityOrAlpn) {
    const std::vector<std::string> alpn{"custom"};
    const OutboundStreamDefaults defaults{
        .require_tls = true, .fallback_server_name = "fallback.example",
        .allow_insecure = true, .alpn = alpn};
    StreamSettings source;
    source.network_mode = NetworkMode::Grpc;
    EXPECT_EQ(NormalizeOutboundStreamSettings(source, defaults).tls.alpn,
              (std::vector<std::string>{"h2"}));
    source.network_mode = NetworkMode::Tcp;
    source.tls.server_name = "explicit.example";
    source.tls.alpn = {"explicit"};
    const auto result = NormalizeOutboundStreamSettings(source, defaults);
    EXPECT_EQ(result.tls.server_name, "explicit.example");
    EXPECT_EQ(result.tls.alpn, (std::vector<std::string>{"explicit"}));
}

TEST(StreamSettings, RealityConstrainsTlsTo13) {
    StreamSettings source;
    source.security_mode = SecurityMode::Reality;
    source.tls.min_version = TlsVersion::V1_2;
    source.tls.max_version = TlsVersion::V1_2;
    const auto result = NormalizeStreamSettings(source);
    EXPECT_EQ(result.tls.min_version, TlsVersion::V1_3);
    EXPECT_EQ(result.tls.max_version, TlsVersion::V1_3);
}

TEST(StreamSettings, ProtocolRequestPathsIncludeOnlyTheirWireComponents) {
    XHttpConfig xhttp;
    xhttp.path = "demo?x=1";
    EXPECT_EQ(xhttp.NormalizedPath(), "/demo/");
    GrpcConfig grpc;
    grpc.service_name = "service";
    EXPECT_EQ(grpc.RequestPath(), "/service/Tun");
    grpc.multi_mode = true;
    EXPECT_EQ(grpc.RequestPath(), "/service/TunMulti");
}

TEST(StreamSettings, ExplicitHttpUpgradeHostOverridesHeader) {
    StreamSettings source;
    source.network_mode = NetworkMode::HttpUpgrade;
    source.http_upgrade.headers.emplace("Host", "header.example");
    EXPECT_EQ(NormalizeStreamSettings(source).configured_http_host, "header.example");
    source.http_upgrade.host = "field.example";
    EXPECT_EQ(NormalizeStreamSettings(source).configured_http_host, "field.example");
}

TEST(StreamSettings, XHttpAutoModeUsesSecurityAndSeparateDownload) {
    struct ModeCase { SecurityMode security; bool download; XHttpMode expected; };
    for (const auto& item : {
            ModeCase{SecurityMode::None, false, XHttpMode::PacketUp},
            {SecurityMode::Tls, false, XHttpMode::StreamUp},
            {SecurityMode::Reality, false, XHttpMode::StreamOne},
            {SecurityMode::Reality, true, XHttpMode::StreamUp}}) {
        StreamSettings source;
        source.network_mode = NetworkMode::XHttp;
        source.security_mode = item.security;
        if (item.download) source.xhttp.download_settings = std::make_shared<XHttpDownloadSettings>();
        EXPECT_EQ(ResolveXHttpOutboundMode(NormalizeStreamSettings(source)), item.expected);
    }
}
