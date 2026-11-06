#include "node_info_json.hpp"

#include <cstdlib>
#include <iostream>
#include <limits>
#include <string_view>

namespace {

using acpp::api::v2board::ParseNodeInfo;

[[noreturn]] void Fail(std::string_view message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        Fail(message);
    }
}

auto ParseResponse(std::string_view body) {
    const auto parsed = acpp::json::parse(body);
    return ParseNodeInfo(parsed.as_object(), "vmess");
}

void CheckInvalid(std::string_view body) {
    auto result = ParseResponse(body);
    Check(!result, "invalid node response was accepted");
}

void TestValidResponseIsNormalized() {
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

void TestInvalidPortsAreRejected() {
    CheckInvalid(R"({})");
    CheckInvalid(R"({"server_port":0})");
    CheckInvalid(R"({"server_port":-1})");
    CheckInvalid(R"({"server_port":65536})");
    CheckInvalid(R"({"server_port":"443"})");
    CheckInvalid(R"({"server_port":443.0})");
    CheckInvalid(R"({"server_port":null})");
    CheckInvalid(R"({"server_port":443,"cipher":123})");
    CheckInvalid(R"({"server_port":443,"server_key":[]})");
    CheckInvalid(R"({"server_port":443,"server_key":false})");
    CheckInvalid(R"({"server_port":443,"tls":3})");
    CheckInvalid(R"({"server_port":443,"tls":"1"})");
    CheckInvalid(R"({"server_port":443,"network":42})");
    CheckInvalid(R"({"server_port":443,"networkSettings":"ws"})");
    CheckInvalid(R"({"server_port":443,"base_config":{"pull_interval":-1}})");
    CheckInvalid(R"({"server_port":443,"base_config":{"push_interval":"60"}})");
    CheckInvalid(R"({"server_port":443,"base_config":{"pull_interval":4294967297}})");

    acpp::json::object source{
        {"server_port", std::numeric_limits<uint64_t>::max()},
    };
    auto result = ParseNodeInfo(source, "vmess");
    Check(!result, "uint64 overflow node port was accepted");
}

void TestInvalidNetworkHostIsRejected() {
    CheckInvalid(R"({"server_port":443,"networkSettings":{"headers":{"Host":42}}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"headers":{"Host":"edge.example\r\nInjected: yes"}}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"headers":{"Host":"one.example","host":"two.example"}}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"headers":[]}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"path":"/ws\r\nInjected: yes"}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"path":42}})");
    CheckInvalid(R"({"server_port":443,"networkSettings":{"headers":{"Host":"bad host"}}})");

    auto lowercase = ParseResponse(
        R"({"server_port":443,"networkSettings":{"headers":{"host":"edge.example"}}})");
    Check(lowercase.has_value() && lowercase->Host == "edge.example",
          "lowercase panel Host header was not normalized");
}

void TestRealityNodeResponseIsNormalized() {
    const auto parsed = acpp::json::parse(
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
                  acpp::transport::internet::RealityClientVersion{1, 8, 0, 0},
          "REALITY min_client_version mismatch");
    Check(result->Reality.max_client_version.has_value() &&
              *result->Reality.max_client_version ==
                  acpp::transport::internet::RealityClientVersion{26, 1, 31, 0},
          "REALITY max_client_version mismatch");
    Check(result->Reality.max_time_diff == 60000,
          "REALITY max_time_diff mismatch");

    CheckInvalid(R"({"server_port":443,"tls":2})");
    CheckInvalid(R"({"server_port":443,"tls":2,"tls_settings":{}})");
    CheckInvalid(R"({"server_port":443,"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","min_client_ver":"2.0.0","max_client_ver":"1.0.0"}})");
    CheckInvalid(R"({"server_port":443,"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","max_time_diff":-1}})");
    CheckInvalid(R"({"server_port":443,"tls":2,"server_name":"","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","dest":"www.apple.com:443"}})");
    auto null_subfields = acpp::json::parse(
        R"({"server_port":8443,"network":"ws","networkSettings":{"path":"/ws","headers":null,"serviceName":null},"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","server_names":null,"short_ids":null,"dest":"www.apple.com:443"}})");
    Check(ParseNodeInfo(null_subfields.as_object(), "vless").has_value(),
          "valid REALITY node with null optional subfields was rejected");
    CheckInvalid(R"({"server_port":8443,"network":"grpc","networkSettings":{"serviceName":"bad service"},"tls":0})");
    CheckInvalid(R"({"server_port":443,"tls":2,"server_name":"www.apple.com","tls_settings":{"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","privateKey":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB","dest":"www.apple.com:443"}})");
}

void TestOptionalCipherNullValues() {
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

}  // namespace

int main() {
    TestValidResponseIsNormalized();
    TestInvalidPortsAreRejected();
    TestInvalidNetworkHostIsRejected();
    TestRealityNodeResponseIsNormalized();
    TestOptionalCipherNullValues();
    std::cout << "v2board_node_info_json_test: ok\n";
    return 0;
}
