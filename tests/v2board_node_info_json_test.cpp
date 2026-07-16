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
    return ParseNodeInfo(parsed.as_object(), 7, "vmess");
}

void CheckInvalid(std::string_view body, std::string_view expected_error) {
    auto result = ParseResponse(body);
    Check(!result, "invalid node response was accepted");
    Check(result.error().find(expected_error) != std::string::npos,
          "node response error lost its cause");
}

void TestValidResponseIsNormalized() {
    auto result = ParseResponse(
        R"({"server_port":65535,"network":"ws","networkSettings":{"path":"/edge","headers":{"Host":"edge.example"}},"tls":1,"server_name":"sni.example","cipher":"aes-128-gcm","server_key":"identity","base_config":{"pull_interval":45,"push_interval":30}})");
    Check(result.has_value(), "valid node response was rejected");
    Check(result->NodeID == 7, "node id mismatch");
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
    CheckInvalid(R"({})", "required");
    CheckInvalid(R"({"server_port":0})", "between 1 and 65535");
    CheckInvalid(R"({"server_port":-1})", "between 1 and 65535");
    CheckInvalid(R"({"server_port":65536})", "between 1 and 65535");
    CheckInvalid(R"({"server_port":"443"})", "integer");
    CheckInvalid(R"({"server_port":443.0})", "integer");
    CheckInvalid(R"({"server_port":null})", "integer");

    acpp::json::object source{
        {"server_port", std::numeric_limits<uint64_t>::max()},
    };
    auto result = ParseNodeInfo(source, 7, "vmess");
    Check(!result, "uint64 overflow node port was accepted");
}

}  // namespace

int main() {
    TestValidResponseIsNormalized();
    TestInvalidPortsAreRejected();
    std::cout << "v2board_node_info_json_test: ok\n";
    return 0;
}
