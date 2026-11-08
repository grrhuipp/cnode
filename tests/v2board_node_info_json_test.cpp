#include <stdexcept>
#include <gtest/gtest.h>

#include "node_info_json.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>

namespace {

using ::api::v2board::ParseNodeInfo;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    ADD_FAILURE() << "contract assertion failed; see diagnostic above"; throw std::runtime_error("contract assertion failed");
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

auto ParseResponse(std::string_view body) {
    const auto parsed = ::json::parse(body);
    return ParseNodeInfo(parsed.as_object(), "vmess");
}

void CheckInvalid(std::string_view body) {
    auto result = ParseResponse(body);
    Check(!result, "invalid node response was accepted");
}

TEST(V2BoardNodeInfoJson, ValidResponseIsNormalized) {
    auto result = ParseResponse(
        R"({"server_port":65535,"network":"ws","networkSettings":{"path":"/edge","headers":{"Host":"edge.example"}},"tls":1,"server_name":"sni.example","cipher":"aes-128-gcm","server_key":"identity","base_config":{"pull_interval":45,"push_interval":30}})");
    Check(result.has_value(), "valid node response was rejected");
    Check(result->NodeType == "vmess", "node type mismatch");
    Check(result->Port == 65535, "server port mismatch");
    Check(result->TransportProtocol == "ws", "network mismatch");
    Check(result->Path == "/edge", "network path mismatch");
    Check(result->Host == "edge.example", "network host mismatch");
    Check(result->EnableTLS, "tls flag mismatch");
    Check(result->TLSServerName == "sni.example", "server name mismatch");
    Check(result->CypherMethod == "aes-128-gcm", "cipher mismatch");
    Check(result->ShadowsocksServerKey == "identity", "server key mismatch");
    Check(result->PullInterval == 45, "pull interval mismatch");
    Check(result->PushInterval == 30, "push interval mismatch");
}

TEST(V2BoardNodeInfoJson, InvalidPortsAreRejected) {
    CheckInvalid(R"({})");
    CheckInvalid(R"({"server_port":0})");
    CheckInvalid(R"({"server_port":-1})");
    CheckInvalid(R"({"server_port":65536})");
    CheckInvalid(R"({"server_port":"443x"})");
    CheckInvalid(R"({"server_port":" 443"})");
    CheckInvalid(R"({"server_port":443.0})");
    CheckInvalid(R"({"server_port":null})");
    CheckInvalid(R"({"server_port":443,"cipher":123})");
    CheckInvalid(R"({"server_port":443,"server_key":[]})");
    CheckInvalid(R"({"server_port":443,"server_key":false})");
    CheckInvalid(R"({"server_port":443,"tls":3})");
    CheckInvalid(R"({"server_port":443,"tls":"3"})");
    CheckInvalid(R"({"server_port":443,"network":42})");
    CheckInvalid(R"({"server_port":443,"networkSettings":"ws"})");
    CheckInvalid(R"({"server_port":443,"base_config":{"pull_interval":-1}})");
    CheckInvalid(R"({"server_port":443,"base_config":{"push_interval":"-1"}})");
    CheckInvalid(R"({"server_port":443,"base_config":{"pull_interval":4294967297}})");

    ::json::object source{
        {"server_port", std::numeric_limits<uint64_t>::max()},
    };
    auto result = ParseNodeInfo(source, "vmess");
    Check(!result, "uint64 overflow node port was accepted");
}

TEST(V2BoardNodeInfoJson, InvalidNetworkHostIsRejected) {
    CheckInvalid(R"({"server_port":443,"networkSettings":{"headers":{"Host":42}}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"headers":{"Host":"edge.example\r\nInjected: yes"}}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"headers":{"Host":"one.example","host":"two.example"}}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"headers":["Host"]}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"path":"/ws\r\nInjected: yes"}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"path":42}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"headers":{"Host":"bad host"}}})");

    auto lowercase = ParseResponse(
        R"({"server_port":443,"networkSettings":{"headers":{"host":"edge.example"}}})");
    Check(lowercase.has_value() && lowercase->Host == "edge.example",
          "lowercase panel Host header was not normalized");
}

TEST(V2BoardNodeInfoJson, RealityNodeResponseIsNormalized) {
    const auto parsed = ::json::parse(
        R"({"server_port":8443,"network":"grpc","networkSettings":{"serviceName":"gun"},"tls":2,"flow":"xtls-rprx-vision","server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","short_id":["0123456789abcdef",""],"dest":"www.apple.com:443","xver":1,"mldsa65_seed":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","min_client_ver":"1.8.0","max_client_ver":"26.1.31","max_time_diff":60000}})");
    auto result = ParseNodeInfo(parsed.as_object(), "vless");
    Check(result.has_value(), "valid REALITY node response was rejected");
    Check(result->EnableReality && !result->EnableTLS, "REALITY mode flag mismatch");
    Check(result->Flow == "xtls-rprx-vision", "node flow mismatch");
    Check(result->ServiceName == "gun", "grpc serviceName mismatch");
    Check(result->Reality.private_key.has_value(), "REALITY private key missing");
    Check(result->Reality.server_names.size() == 1 &&
              result->Reality.server_names[0] == "www.apple.com",
          "REALITY server_name mismatch");
    Check(result->Reality.short_ids.size() == 2, "REALITY short_ids count mismatch");
    Check(result->Reality.HasDest() &&
              result->Reality.dest_host == "www.apple.com" &&
              result->Reality.dest_port == 443 &&
              result->Reality.xver == 1,
          "REALITY dest/xver mismatch");
    Check(result->Reality.mldsa65_seed.has_value(), "REALITY mldsa65_seed missing");
    Check(result->Reality.min_client_version.has_value() &&
              *result->Reality.min_client_version ==
                  ::transport::internet::RealityClientVersion{1, 8, 0, 0},
          "REALITY min_client_version mismatch");
    Check(result->Reality.max_client_version.has_value() &&
              *result->Reality.max_client_version ==
                  ::transport::internet::RealityClientVersion{26, 1, 31, 0},
          "REALITY max_client_version mismatch");
    Check(result->Reality.max_time_diff == 60000,
          "REALITY max_time_diff mismatch");

    CheckInvalid(R"({"server_port":443,"tls":2})");
    CheckInvalid(R"({"server_port":443,"tls":2,"tls_settings":{}})");
    CheckInvalid(R"({"server_port":443,"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","min_client_ver":"2.0.0","max_client_ver":"1.0.0"}})");
    CheckInvalid(R"({"server_port":443,"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","max_time_diff":-1}})");
    CheckInvalid(R"({"server_port":443,"tls":2,"server_name":"","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","dest":"www.apple.com:443"}})");
    auto null_subfields = ::json::parse(
        R"({"server_port":8443,"network":"ws","networkSettings":{"path":"/ws","headers":null,"serviceName":null},"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","server_names":null,"short_ids":null,"dest":"www.apple.com:443"}})");
    Check(ParseNodeInfo(null_subfields.as_object(), "vless").has_value(),
          "valid REALITY node with null optional subfields was rejected");
    CheckInvalid(R"({"server_port":8443,"network":"grpc","networkSettings":{"serviceName":"bad service"},"tls":0})");
    CheckInvalid(R"({"server_port":443,"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","privateKey":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","dest":"www.apple.com:443"}})");
}

TEST(V2BoardNodeInfoJson, OptionalCipherNullValues) {
    for (const auto* text : {
             R"({"server_port":443})",
             R"({"server_port":443,"cipher":null,"server_key":null})",
             R"({"server_port":443,"cipher":"","server_key":""})"}) {
        const auto result = ParseResponse(text);
        Check(result.has_value() && result->CypherMethod.empty() &&
                  result->ShadowsocksServerKey.empty(),
              "optional cipher/server_key absence/null/empty must remain unset");
    }
    CheckInvalid(R"({"server_port":443,"cipher":42})");
    CheckInvalid(R"({"server_port":443,"server_key":false})");
}

TEST(V2BoardNodeInfoJson, Xv2BoardTypesAreCompatible) {
    auto parsed = ::json::parse(
        R"({"server_port":"8443","network":"WS","networkSettings":{"path":"/Edge","headers":{"Host":"Edge.Example"}},"tls":"1","flow":"XTLS-RPRX-VISION","server_name":"SNI.Example","cipher":"AES-128-GCM","server_key":"Identity","base_config":{"pull_interval":"45","push_interval":"30"}})");
    auto result = ParseNodeInfo(parsed.as_object(), "VMESS");
    Check(result.has_value(), "string integers and mixed-case enums were rejected");
    Check(result->NodeType == "vmess" && result->Port == 8443 &&
              result->TransportProtocol == "ws" && result->EnableTLS &&
              result->Flow == "xtls-rprx-vision" &&
              result->CypherMethod == "aes-128-gcm" &&
              result->Host == "edge.example" &&
              result->TLSServerName == "sni.example" &&
              result->Path == "/Edge" && result->ShadowsocksServerKey == "Identity" &&
              result->PullInterval == 45 && result->PushInterval == 30,
          "panel enum, hostname and opaque value normalization mismatch");

    for (const auto* tls : {"true", "\"TRUE\"", "\"1\""}) {
        const auto body = std::string(R"({"server_port":443,"tls":)") + tls + "}";
        const auto parsed_tls = ParseResponse(body);
        Check(parsed_tls && parsed_tls->EnableTLS, "boolean-compatible tls was rejected");
    }
    const auto empty_php_objects = ParseResponse(
        R"({"server_port":443,"networkSettings":[]})");
    Check(empty_php_objects.has_value(), "PHP empty associative array was rejected");

    auto hysteria = ::json::parse(
        R"({"version":"2","host":"node.example","server_port":"443","server_name":"Node.Example","up_mbps":"100","down_mbps":200,"ignore_client_bandwidth":false,"obfs":null,"obfs-password":null})");
    auto hy = ParseNodeInfo(hysteria.as_object(), "hysteria");
    Check(hy && hy->NodeType == "hysteria2" && hy->HysteriaUpMbps == 100 &&
              hy->HysteriaDownMbps == 200 && hy->TLSServerName == "node.example",
          "xv2board Hysteria config mismatch");
    auto obfs = ::json::parse(
        R"({"server_port":443,"cipher":"aes-128-gcm","obfs":"http","obfs_settings":{"host":"a"}})");
    Check(!ParseNodeInfo(obfs.as_object(), "shadowsocks"),
          "unsupported Shadowsocks obfs was silently ignored");

    auto anytls = ::json::parse(
        R"({"server_port":443,"padding_scheme":["stop=2","1=64-65"]})");
    auto any = ParseNodeInfo(anytls.as_object(), "anytls");
    Check(any && any->PaddingScheme == "stop=2\n1=64-65", "AnyTLS padding mismatch");
}

// The panel maps onto the same validators as local configuration.
TEST(V2BoardNodeInfoJson, SharedFieldContract) {
    constexpr std::string_view kKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const auto reality = [&](std::string_view settings) {
        const auto body = std::string(R"({"server_port":443,"tls":2,"tls_settings":{"private_key":")") +
            std::string(kKey) + "\"," + std::string(settings) + "}}";
        const auto parsed = ::json::parse(body);
        return ParseNodeInfo(parsed.as_object(), "vless");
    };
    const auto no_sni = reality(R"("server_names":["","www.apple.com"])");
    Check(no_sni && no_sni->Reality.server_names.size() == 2 &&
              no_sni->Reality.server_names[0].empty(),
          "REALITY empty serverNames entry must permit missing SNI");
    Check(no_sni && no_sni->Reality.short_ids.size() == 1 &&
              no_sni->Reality.short_ids[0] == ::transport::internet::RealityShortId{},
          "missing panel short id must map to the empty short id");
    Check(!reality(R"("server_names":["www.apple.com"],"short_ids":[])"),
          "an empty short id list must be rejected");
    const auto port_dest = reality(R"("server_name":"www.apple.com","server_port":8443)");
    Check(port_dest && port_dest->Reality.dest_host == "www.apple.com" &&
              port_dest->Reality.dest_port == 8443,
          "server_port must map to dest on the first server name");

    const auto grpc = ParseResponse(
        R"({"server_port":443,"network":"grpc","networkSettings":{"path":"/gun"}})");
    Check(grpc && grpc->ServiceName == "/gun" && grpc->Path.empty(),
          "gRPC path must map to serviceName");
    const auto ws = ParseResponse(R"({"server_port":443,"network":"ws"})");
    Check(ws && ws->Path == "/", "transport path must default to /");
    CheckInvalid(R"({"server_port":443,"server_name":"bad host"})");

    const auto padding = [](std::string_view value) {
        const auto parsed = ::json::parse(
            std::string(R"({"server_port":443,"padding_scheme":)") + std::string(value) + "}");
        return ParseNodeInfo(parsed.as_object(), "anytls");
    };
    Check(!padding(R"("stop=2\n1=65536-65536")"), "invalid padding must be rejected at parse");
    const auto unset = padding("null");
    Check(unset && unset->PaddingScheme.empty(), "null padding must stay unset");
}

}  // namespace

