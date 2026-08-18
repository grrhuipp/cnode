#include "acppnode/infra/access_log_reporter.hpp"
#include "access_log_encoding.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <fstream>
#include <span>
#include <string_view>
#include <vector>

namespace {

bool Contains(std::span<const uint8_t> haystack, std::string_view needle) {
    return std::search(
               haystack.begin(), haystack.end(),
               reinterpret_cast<const uint8_t*>(needle.data()),
               reinterpret_cast<const uint8_t*>(needle.data() + needle.size())) !=
           haystack.end();
}

}  // namespace

int main(int argc, char** argv) {
    using namespace acpp::accesslog;
    using namespace acpp::accesslog::detail;

    static_assert(kServiceBaseUrl == "https://l.bt3.one");
    static_assert(kServiceHost == "l.bt3.one");
    static_assert(kAccessBatchTarget == "/v1/access/batches");
    static_assert(kErrorBatchTarget == "/v1/error/batches");

    assert(NormalizePanelApiHost(
               " HTTPS://User:secret@Panel.Example.COM:443/api?v=token#x ") ==
           "https://panel.example.com/api");
    assert(NormalizePanelApiHost("http://panel.example.com:8080/path") ==
           "http://panel.example.com:8080/path");
    assert(NormalizePanelApiHost("https://[2001:DB8::1]:443/api") ==
           "https://[2001:db8::1]");
    assert(NormalizePanelApiHost("ftp://panel.example.com").empty());
    assert(NormalizePanelApiHost("https://panel.example.com:70000").empty());

    std::vector<Source> sources{
        Source{
            .panel_name = "main-panel",
            .panel_api_host = "https://panel.example.com",
            .node_type = "vmess",
            .node_id = 42,
        },
    };
    Event event;
    event.source_ref = 1;
    event.conn_id = 99;
    event.worker_id = 2;
    event.user_id = 1001;
    event.started_at_unix_us = 1'000'000;
    event.ended_at_unix_us = 2'000'000;
    event.duration_ms = 1000;
    event.inbound_tag = "panel-vmess-42";
    event.outbound_tag = "direct";
    event.protocol = "vmess";
    event.network = Network::Tcp;
    event.source_ip = "192.0.2.10";
    event.source_port = 50000;
    event.inbound_ip = "10.0.0.10";
    event.inbound_port = 443;
    event.peer_ip = "192.0.2.9";
    event.peer_port = 51000;
    event.client_ip_source = "proxy_protocol";
    event.client_ip_trusted = true;
    event.target_host = "example.com";
    event.target_port = 443;
    event.dial_ip = "198.51.100.42";
    event.local_ip = "10.0.0.20";
    event.local_port = 52000;
    event.inbound_transport = "ws";
    event.inbound_security = "tls";
    event.tls_sni = "sni.example.com";
    event.tls_alpn = "h2";
    event.tls_version = "TLSv1.3";
    event.tls_fingerprint = "sha256:negotiated";
    event.http_host = "host.example.com";
    event.transport_route_id = "ws:/edge";
    event.original_target_host = "original.example.com";
    event.original_target_port = 8443;
    event.route_target_host = "route.example.com";
    event.route_target_port = 443;
    event.final_target_host = "example.com";
    event.final_target_port = 443;
    event.route_rule = "rule:3";
    event.dns_latency_ms = 12;
    event.dns_answer_count = 2;
    event.dial_attempt_count = 2;
    event.dial_ips = {"198.51.100.41", "198.51.100.42"};
    event.transport_handshake_ms = 8;
    event.auth_ms = 3;
    event.dial_ms = 21;
    event.first_byte_ms = 34;
    event.packet_count_up = 7;
    event.packet_count_down = 9;
    event.distinct_target_count = 1;
    event.parent_conn_id = 90;
    event.stream_id = 17;
    event.runtime_generation = 5;
    event.config_generation = 6;
    event.uplink_bytes = 123;
    event.downlink_bytes = 456;
    event.result = Result::Completed;
    event.error_code = acpp::ErrorCode::OK;
    event.error_reason = "OK";

    std::vector<SequencedEvent> events{
        SequencedEvent{.sequence = 7, .event = std::move(event)},
    };
    Id128 boot_id{};
    for (size_t i = 0; i < boot_id.size(); ++i) {
        boot_id[i] = static_cast<uint8_t>(i + 1);
    }

    const EncodedBatch batch = EncodeBatch(events, sources, "cnode-test", boot_id);
    assert(batch.first_sequence == 7);
    assert(batch.last_sequence == 7);
    assert(!batch.protobuf.empty());
    assert(Contains(batch.protobuf, "https://panel.example.com"));
    assert(Contains(batch.protobuf, "example.com"));
    assert(Contains(batch.protobuf, "198.51.100.42"));
    assert(Contains(batch.protobuf, "cnode-test"));
    assert(Contains(batch.protobuf, "proxy_protocol"));
    assert(Contains(batch.protobuf, "sni.example.com"));
    assert(Contains(batch.protobuf, "rule:3"));
    assert(Contains(batch.protobuf, "1.0.0"));

    const auto compressed = CompressZstd(batch.protobuf);
    assert(compressed.size() >= 4);
    assert(compressed[0] == 0x28);
    assert(compressed[1] == 0xb5);
    assert(compressed[2] == 0x2f);
    assert(compressed[3] == 0xfd);
    if (argc == 2) {
        std::ofstream output(argv[1], std::ios::binary | std::ios::trunc);
        output.write(
            reinterpret_cast<const char*>(compressed.data()),
            static_cast<std::streamsize>(compressed.size()));
        assert(output.good());
    }
    return 0;
}
