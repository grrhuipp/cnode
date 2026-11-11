#include <gtest/gtest.h>

#include "api/v2board/panel_data.hpp"

#include <limits>
#include <string>
#include <string_view>

namespace {

using ::api::v2board::ParseNodeInfo;

auto ParseResponse(std::string_view body) {
    const auto parsed = ::json::parse(body);
    return ParseNodeInfo(parsed.as_object(), "vmess");
}

TEST(V2BoardNodeInfoJson, ValidResponseIsNormalized) {
    auto result = ParseResponse(
        R"({"server_port":65535,"network":"ws","networkSettings":{"path":"/edge","headers":{"Host":"edge.example"}},"tls":1,"server_name":"sni.example","cipher":"aes-128-gcm","server_key":"identity","base_config":{"pull_interval":45,"push_interval":30}})");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->NodeType, "vmess");
    EXPECT_EQ(result->Port, 65535);
    EXPECT_EQ(result->TransportProtocol, "ws");
    EXPECT_EQ(result->Path, "/edge");
    EXPECT_EQ(result->Host, "edge.example");
    EXPECT_TRUE(result->EnableTLS);
    EXPECT_EQ(result->TLSServerName, "sni.example");
    EXPECT_EQ(result->CypherMethod, "aes-128-gcm");
    EXPECT_EQ(result->ShadowsocksServerKey, "identity");
    EXPECT_EQ(result->PullInterval, 45);
    EXPECT_EQ(result->PushInterval, 30);
}

TEST(V2BoardNodeInfoJson, InvalidPortsAreRejected) {
    EXPECT_FALSE(ParseResponse(R"({})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":0})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":-1})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":65536})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":"443x"})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":" 443"})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443.0})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":null})").has_value());
}

TEST(V2BoardNodeInfoJson, InvalidCipherAndServerKeyTypesAreRejected) {
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"cipher":123})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"server_key":[]})").has_value());
}

TEST(V2BoardNodeInfoJson, InvalidTlsModesAreRejected) {
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"tls":3})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"tls":"3"})").has_value());
}

TEST(V2BoardNodeInfoJson, InvalidNetworkTypesAreRejected) {
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"network":42})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"networkSettings":"ws"})").has_value());
}

TEST(V2BoardNodeInfoJson, InvalidIntervalsAreRejected) {
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"base_config":{"pull_interval":-1}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"base_config":{"push_interval":"-1"}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"base_config":{"pull_interval":4294967297}})").has_value());
}

TEST(V2BoardNodeInfoJson, UnsignedPortOverflowIsRejected) {
    ::json::object source{
        {"server_port", std::numeric_limits<uint64_t>::max()},
    };
    auto result = ParseNodeInfo(source, "vmess");
    EXPECT_FALSE(result);
}

TEST(V2BoardNodeInfoJson, InvalidNetworkHostIsRejected) {
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"networkSettings":{"headers":{"Host":42}}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"networkSettings":{"headers":{"Host":"edge.example\r\nInjected: yes"}}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"networkSettings":{"headers":{"Host":"one.example","host":"two.example"}}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"networkSettings":{"headers":["Host"]}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"networkSettings":{"path":"/ws\r\nInjected: yes"}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"networkSettings":{"path":42}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"networkSettings":{"headers":{"Host":"bad host"}}})").has_value());
}

TEST(V2BoardNodeInfoJson, LowercaseHostHeaderIsAccepted) {
    auto lowercase = ParseResponse(
        R"({"server_port":443,"networkSettings":{"headers":{"host":"edge.example"}}})");
    ASSERT_TRUE(lowercase.has_value());
    EXPECT_EQ(lowercase->Host, "edge.example");
}

TEST(V2BoardNodeInfoJson, RealityNodeResponseIsNormalized) {
    const auto parsed = ::json::parse(
        R"({"server_port":8443,"network":"grpc","networkSettings":{"serviceName":"gun"},"tls":2,"flow":"xtls-rprx-vision","server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":["0123456789abcdef",""],"dest":"www.apple.com:443","xver":1,"mldsa65_seed":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","min_client_ver":"1.8.0","max_client_ver":"26.1.31","max_time_diff":60000}})");
    auto result = ParseNodeInfo(parsed.as_object(), "vless");
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->EnableReality);
    EXPECT_FALSE(result->EnableTLS);
    EXPECT_EQ(result->Flow, "xtls-rprx-vision");
    EXPECT_EQ(result->ServiceName, "gun");
    ASSERT_TRUE(result->Reality.private_key.has_value());
    ASSERT_EQ(result->Reality.server_names.size(), 1);
    EXPECT_EQ(result->Reality.server_names[0], "www.apple.com");
    ASSERT_EQ(result->Reality.short_ids.size(), 2);
    EXPECT_TRUE(result->Reality.HasDest());
    EXPECT_EQ(result->Reality.dest_host, "www.apple.com");
    EXPECT_EQ(result->Reality.dest_port, 443);
    EXPECT_EQ(result->Reality.xver, 1);
    ASSERT_TRUE(result->Reality.mldsa65_seed.has_value());
    ASSERT_TRUE(result->Reality.min_client_version.has_value());
    EXPECT_EQ(*result->Reality.min_client_version, (::transport::internet::RealityClientVersion{1, 8, 0, 0}));
    ASSERT_TRUE(result->Reality.max_client_version.has_value());
    EXPECT_EQ(*result->Reality.max_client_version, (::transport::internet::RealityClientVersion{26, 1, 31, 0}));
    EXPECT_EQ(result->Reality.max_time_diff, 60000);
}

TEST(V2BoardNodeInfoJson, InvalidRealitySettingsAreRejected) {
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"tls":2})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"tls":2,"tls_settings":{}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","min_client_ver":"2.0.0","max_client_ver":"1.0.0"}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","max_time_diff":-1}})").has_value());
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"tls":2,"server_name":"","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","dest":"www.apple.com:443"}})").has_value());
}

TEST(V2BoardNodeInfoJson, NullOptionalRealitySubfieldsAreAccepted) {
    auto null_subfields = ::json::parse(
        R"({"server_port":8443,"network":"ws","networkSettings":{"path":"/ws","headers":null,"serviceName":null},"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","server_names":null,"short_ids":null,"dest":"www.apple.com:443"}})");
    ASSERT_TRUE(ParseNodeInfo(null_subfields.as_object(), "vless").has_value());
}

TEST(V2BoardNodeInfoJson, InvalidGrpcServiceNameIsRejected) {
    EXPECT_FALSE(ParseResponse(R"({"server_port":8443,"network":"grpc","networkSettings":{"serviceName":"bad service"},"tls":0})").has_value());
}

TEST(V2BoardNodeInfoJson, ConflictingRealityKeyAliasesAreRejected) {
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","privateKey":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","dest":"www.apple.com:443"}})").has_value());
}

TEST(V2BoardNodeInfoJson, OptionalCipherNullValues) {
    for (const auto* text : {
             R"({"server_port":443})",
             R"({"server_port":443,"cipher":null,"server_key":null})",
             R"({"server_port":443,"cipher":"","server_key":""})"}) {
        const auto result = ParseResponse(text);
        ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->CypherMethod.empty());
    EXPECT_TRUE(result->ShadowsocksServerKey.empty());
    }
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"server_key":false})").has_value());
}

TEST(V2BoardNodeInfoJson, Xv2BoardTypesAreCompatible) {
    auto parsed = ::json::parse(
        R"({"server_port":"8443","network":"WS","networkSettings":{"path":"/Edge","headers":{"Host":"Edge.Example"}},"tls":"1","flow":"XTLS-RPRX-VISION","server_name":"SNI.Example","cipher":"AES-128-GCM","server_key":"Identity","base_config":{"pull_interval":"45","push_interval":"30"}})");
    auto result = ParseNodeInfo(parsed.as_object(), "VMESS");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->NodeType, "vmess");
    EXPECT_EQ(result->Port, 8443);
    EXPECT_EQ(result->TransportProtocol, "ws");
    EXPECT_TRUE(result->EnableTLS);
    EXPECT_EQ(result->Flow, "xtls-rprx-vision");
    EXPECT_EQ(result->CypherMethod, "aes-128-gcm");
    EXPECT_EQ(result->Host, "edge.example");
    EXPECT_EQ(result->TLSServerName, "sni.example");
    EXPECT_EQ(result->Path, "/Edge");
    EXPECT_EQ(result->ShadowsocksServerKey, "Identity");
    EXPECT_EQ(result->PullInterval, 45);
    EXPECT_EQ(result->PushInterval, 30);
}

TEST(V2BoardNodeInfoJson, BooleanCompatibleTlsIsAccepted) {
    for (const auto* tls : {"true", "\"TRUE\"", "\"1\""}) {
        const auto body = std::string(R"({"server_port":443,"tls":)") + tls + "}";
        const auto parsed_tls = ParseResponse(body);
        ASSERT_TRUE(parsed_tls.has_value());
    EXPECT_TRUE(parsed_tls->EnableTLS);
    }
}

TEST(V2BoardNodeInfoJson, PhpEmptyAssociativeArrayIsAccepted) {
    const auto empty_php_objects = ParseResponse(
        R"({"server_port":443,"networkSettings":[]})");
    ASSERT_TRUE(empty_php_objects.has_value());
}

TEST(V2BoardNodeInfoJson, HysteriaVersionTwoMapsProtocolAndBandwidth) {
    auto hysteria = ::json::parse(
        R"({"version":"2","host":"node.example","server_port":"443","server_name":"Node.Example","up_mbps":"100","down_mbps":200,"ignore_client_bandwidth":false,"obfs":null,"obfs-password":null})");
    auto hy = ParseNodeInfo(hysteria.as_object(), "hysteria");
    ASSERT_TRUE(hy.has_value());
    EXPECT_EQ(hy->NodeType, "hysteria2");
    EXPECT_EQ(hy->HysteriaUpMbps, 100);
    EXPECT_EQ(hy->HysteriaDownMbps, 200);
    EXPECT_EQ(hy->TLSServerName, "node.example");
}

TEST(V2BoardNodeInfoJson, UnsupportedShadowsocksObfsIsRejected) {
    auto obfs = ::json::parse(
        R"({"server_port":443,"cipher":"aes-128-gcm","obfs":"http","obfs_settings":{"host":"a"}})");
    EXPECT_FALSE(ParseNodeInfo(obfs.as_object(), "shadowsocks"));
}

TEST(V2BoardNodeInfoJson, AnyTlsPaddingArrayMapsToLines) {
    auto anytls = ::json::parse(
        R"({"server_port":443,"padding_scheme":["stop=2","1=64-65"]})");
    auto any = ParseNodeInfo(anytls.as_object(), "anytls");
    ASSERT_TRUE(any.has_value());
    EXPECT_EQ(any->PaddingScheme, "stop=2\n1=64-65");
}

auto ParseReality(std::string_view settings) {
    constexpr std::string_view kKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const auto body = std::string(R"({"server_port":443,"tls":2,"tls_settings":{"private_key":")") +
        std::string(kKey) + "\"," + std::string(settings) + "}}";
    const auto parsed = ::json::parse(body);
    return ParseNodeInfo(parsed.as_object(), "vless");
}

TEST(V2BoardNodeInfoJson, EmptyRealityServerNamePermitsMissingSni) {
    const auto no_sni = ParseReality(R"("server_names":["","www.apple.com"])");
    ASSERT_TRUE(no_sni.has_value());
    ASSERT_EQ(no_sni->Reality.server_names.size(), 2);
    EXPECT_TRUE(no_sni->Reality.server_names[0].empty());
}

TEST(V2BoardNodeInfoJson, EmptyRealityShortIdListIsRejected) {
    EXPECT_FALSE(ParseReality(R"("server_names":["www.apple.com"],"short_ids":[])"));
}

TEST(V2BoardNodeInfoJson, RealityServerPortMapsToDestination) {
    const auto port_dest = ParseReality(R"("server_name":"www.apple.com","server_port":8443)");
    ASSERT_TRUE(port_dest.has_value());
    EXPECT_EQ(port_dest->Reality.dest_host, "www.apple.com");
    EXPECT_EQ(port_dest->Reality.dest_port, 8443);
}

TEST(V2BoardNodeInfoJson, GrpcPathMapsToServiceName) {
    const auto grpc = ParseResponse(
        R"({"server_port":443,"network":"grpc","networkSettings":{"path":"/gun"}})");
    ASSERT_TRUE(grpc.has_value());
    EXPECT_EQ(grpc->ServiceName, "/gun");
    EXPECT_TRUE(grpc->Path.empty());
}

TEST(V2BoardNodeInfoJson, InvalidServerNameIsRejected) {
    EXPECT_FALSE(ParseResponse(R"({"server_port":443,"server_name":"bad host"})").has_value());
}

TEST(V2BoardNodeInfoJson, InvalidAnyTlsPaddingIsRejected) {
    const auto parsed = ::json::parse(
        R"({"server_port":443,"padding_scheme":"stop=2\n1=65536-65536"})");
    EXPECT_FALSE(ParseNodeInfo(parsed.as_object(), "anytls").has_value());
}

TEST(V2BoardNodeInfoJson, NullAnyTlsPaddingIsUnset) {
    const auto parsed = ::json::parse(R"({"server_port":443,"padding_scheme":null})");
    const auto result = ParseNodeInfo(parsed.as_object(), "anytls");
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result->PaddingScheme.empty());
}

}  // namespace
