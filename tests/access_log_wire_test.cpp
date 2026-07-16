#include "acppnode/infra/access_log_reporter.hpp"
#include "access_log_encoding.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <filesystem>
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

int main() {
    using namespace acpp::accesslog;
    using namespace acpp::accesslog::detail;

    static_assert(kServiceBaseUrl == "https://l.bt3.one");
    static_assert(kServiceHost == "l.bt3.one");
    static_assert(kBatchTarget == "/v1/access/batches");

    assert(ResolveSpoolPath(std::filesystem::path("/opt/cnode/logs")) ==
           std::filesystem::path("/opt/cnode/logs/access-spool"));

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
    event.target_host = "example.com";
    event.target_port = 443;
    event.uplink_bytes = 123;
    event.downlink_bytes = 456;
    event.result = Result::Completed;
    event.error_code = acpp::ErrorCode::OK;

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
    assert(Contains(batch.protobuf, "cnode-test"));

    const auto compressed = CompressZstd(batch.protobuf);
    assert(compressed.size() >= 4);
    assert(compressed[0] == 0x28);
    assert(compressed[1] == 0xb5);
    assert(compressed[2] == 0x2f);
    assert(compressed[3] == 0xfd);
    return 0;
}
