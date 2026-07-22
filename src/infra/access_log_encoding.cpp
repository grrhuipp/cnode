#include "access_log_encoding.hpp"

#include <zstd.h>

#include <algorithm>
#include <charconv>
#include <limits>
#include <unordered_set>

#ifndef CNODE_VERSION
#define CNODE_VERSION "1.0.0"
#endif
#ifndef BUILD_ID
#define BUILD_ID "unknown"
#endif
#ifndef GIT_COMMIT
#define GIT_COMMIT "unknown"
#endif

namespace acpp::accesslog::detail {

namespace {

constexpr uint32_t kSchemaVersion = 1;

void WriteVarint(std::vector<uint8_t>& out, uint64_t value) {
    while (value >= 0x80) {
        out.push_back(static_cast<uint8_t>(value) | 0x80);
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

void WriteTag(std::vector<uint8_t>& out, uint32_t field, uint8_t wire_type) {
    WriteVarint(out, (static_cast<uint64_t>(field) << 3) | wire_type);
}

void WriteUInt(std::vector<uint8_t>& out, uint32_t field, uint64_t value) {
    if (value == 0) {
        return;
    }
    WriteTag(out, field, 0);
    WriteVarint(out, value);
}

void WriteInt(std::vector<uint8_t>& out, uint32_t field, int64_t value) {
    if (value == 0) {
        return;
    }
    WriteTag(out, field, 0);
    WriteVarint(out, static_cast<uint64_t>(value));
}

void WriteSInt(std::vector<uint8_t>& out, uint32_t field, int64_t value) {
    if (value == 0) {
        return;
    }
    const uint64_t zigzag =
        (static_cast<uint64_t>(value) << 1) ^
        static_cast<uint64_t>(value >> 63);
    WriteTag(out, field, 0);
    WriteVarint(out, zigzag);
}

void WriteBytes(std::vector<uint8_t>& out,
                uint32_t field,
                std::span<const uint8_t> value) {
    if (value.empty()) {
        return;
    }
    WriteTag(out, field, 2);
    WriteVarint(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

void WriteString(std::vector<uint8_t>& out,
                 uint32_t field,
                 std::string_view value,
                 size_t max_size) {
    if (value.empty()) {
        return;
    }
    value = value.substr(0, std::min(value.size(), max_size));
    WriteTag(out, field, 2);
    WriteVarint(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

void WriteMessage(std::vector<uint8_t>& out,
                  uint32_t field,
                  std::span<const uint8_t> message) {
    WriteTag(out, field, 2);
    WriteVarint(out, message.size());
    out.insert(out.end(), message.begin(), message.end());
}

Id128 IdForSequence(const Id128& boot_id, uint64_t sequence) {
    Id128 id = boot_id;
    for (size_t i = 0; i < sizeof(sequence); ++i) {
        id[8 + i] = static_cast<uint8_t>(sequence >> ((7 - i) * 8));
    }
    return id;
}

std::vector<uint8_t> EncodeSource(uint32_t source_ref, const Source& source) {
    std::vector<uint8_t> out;
    out.reserve(128);
    WriteUInt(out, 1, source_ref);
    WriteString(out, 2, source.panel_name, 256);
    WriteString(out, 3, source.panel_api_host, 2048);
    WriteString(out, 4, source.node_type, 64);
    WriteUInt(out, 5, source.node_id);
    return out;
}

std::vector<uint8_t> EncodeEvent(
    const SequencedEvent& sequenced,
    const Id128& boot_id) {
    const Event& event = sequenced.event;
    std::vector<uint8_t> out;
    out.reserve(384);

    const Id128 event_id = IdForSequence(boot_id, sequenced.sequence);
    WriteUInt(out, 1, event.source_ref);
    WriteBytes(out, 2, event_id);
    WriteUInt(out, 3, sequenced.sequence);
    WriteUInt(out, 4, event.conn_id);
    WriteUInt(out, 5, event.worker_id);
    WriteSInt(out, 6, event.user_id);
    WriteInt(out, 7, event.started_at_unix_us);
    WriteInt(out, 8, event.ended_at_unix_us);
    WriteUInt(out, 9, event.duration_ms);
    WriteString(out, 10, event.user_email, 320);
    WriteString(out, 11, event.inbound_tag, 256);
    WriteString(out, 12, event.outbound_tag, 256);
    WriteString(out, 13, event.protocol, 64);
    WriteUInt(out, 14, static_cast<uint8_t>(event.network));
    WriteString(out, 15, event.source_ip, 64);
    WriteUInt(out, 16, event.source_port);
    WriteString(out, 17, event.target_host, 1024);
    WriteUInt(out, 18, event.target_port);
    WriteString(out, 19, event.remote_ip, 64);
    WriteString(out, 20, event.local_ip, 64);
    WriteUInt(out, 21, event.uplink_bytes);
    WriteUInt(out, 22, event.downlink_bytes);
    WriteUInt(out, 23, static_cast<uint8_t>(event.result));
    WriteUInt(out, 24, static_cast<uint32_t>(event.error_code));
    WriteUInt(out, 25, static_cast<uint8_t>(event.close_side));
    WriteUInt(out, 26, event.dns_state);
    WriteString(out, 27, event.sniff_protocol, 64);
    WriteString(out, 28, event.sniff_domain, 1024);
    // Additive schema-v1 field. Older collectors skip unknown protobuf fields.
    WriteString(out, 29, event.dial_ip, 64);
    WriteString(out, 30, event.error_reason, 128);
    WriteBytes(out, 31, event.raw_packet);
    WriteUInt(out, 32, event.raw_packet_truncated ? 1 : 0);
    WriteUInt(out, 33, event.inbound_port);
    WriteString(out, 34, event.inbound_ip, 64);
    WriteString(out, 35, event.peer_ip, 64);
    WriteUInt(out, 36, event.peer_port);
    WriteString(out, 37, event.client_ip_source, 96);
    WriteUInt(out, 38, event.client_ip_trusted ? 1 : 0);
    WriteString(out, 39, event.inbound_transport, 64);
    WriteString(out, 40, event.inbound_security, 64);
    WriteString(out, 41, event.failure_stage, 64);
    WriteString(out, 42, event.failure_detail_code, 128);
    WriteInt(out, 43, event.os_error_code);
    WriteUInt(out, 44, event.local_port);
    WriteString(out, 45, event.tls_sni, 255);
    WriteString(out, 46, event.tls_alpn, 64);
    WriteString(out, 47, event.tls_version, 32);
    WriteString(out, 48, event.tls_fingerprint, 64);
    WriteString(out, 49, event.http_host, 512);
    WriteString(out, 50, event.transport_route_id, 512);
    WriteString(out, 51, event.original_target_host, 1024);
    WriteUInt(out, 52, event.original_target_port);
    WriteString(out, 53, event.route_target_host, 1024);
    WriteUInt(out, 54, event.route_target_port);
    WriteString(out, 55, event.final_target_host, 1024);
    WriteUInt(out, 56, event.final_target_port);
    WriteString(out, 57, event.route_rule, 256);
    WriteUInt(out, 58, event.dns_latency_ms);
    WriteUInt(out, 59, event.dns_answer_count);
    WriteUInt(out, 60, event.dial_attempt_count);
    for (const auto& dial_ip : event.dial_ips) {
        WriteString(out, 61, dial_ip, 64);
    }
    WriteUInt(out, 62, event.transport_handshake_ms);
    WriteUInt(out, 63, event.auth_ms);
    WriteUInt(out, 64, event.dial_ms);
    WriteUInt(out, 65, event.first_byte_ms);
    WriteUInt(out, 66, event.packet_count_up);
    WriteUInt(out, 67, event.packet_count_down);
    WriteUInt(out, 68, event.datagram_count);
    WriteUInt(out, 69, event.distinct_target_count);
    WriteUInt(out, 70, event.parent_conn_id);
    WriteUInt(out, 71, event.stream_id);
    WriteUInt(out, 72, event.runtime_generation);
    WriteUInt(out, 73, event.config_generation);
    WriteUInt(out, 74, event.raw_packet_original_len);
    WriteUInt(out, 75, event.raw_packet_captured_len);
    WriteString(out, 76, event.raw_packet_sha256, 64);
    WriteUInt(out, 77, event.raw_packet_redacted ? 1 : 0);
    WriteString(out, 78, event.raw_packet_protocol_guess, 64);
    return out;
}

}  // namespace

EncodedBatch EncodeBatch(
    std::span<const SequencedEvent> events,
    std::span<const Source> sources,
    std::string_view server_id,
    const Id128& boot_id) {
    EncodedBatch batch;
    if (events.empty()) {
        return batch;
    }

    batch.first_sequence = events.front().sequence;
    batch.last_sequence = events.back().sequence;
    batch.batch_id = IdForSequence(boot_id, batch.first_sequence);
    batch.protobuf.reserve(events.size() * 384);

    WriteUInt(batch.protobuf, 1, kSchemaVersion);
    WriteBytes(batch.protobuf, 2, batch.batch_id);
    WriteString(batch.protobuf, 3, server_id, 256);
    WriteBytes(batch.protobuf, 4, boot_id);
    WriteUInt(batch.protobuf, 5, batch.first_sequence);
    WriteUInt(batch.protobuf, 6, batch.last_sequence);
    WriteString(batch.protobuf, 11, CNODE_VERSION, 64);
    WriteString(batch.protobuf, 12, BUILD_ID, 128);
    WriteString(batch.protobuf, 13, GIT_COMMIT, 64);

    std::vector<uint32_t> source_refs;
    source_refs.reserve(events.size());
    std::unordered_set<uint32_t> seen;
    for (const auto& item : events) {
        const uint32_t ref = item.event.source_ref;
        if (ref == 0 || ref > sources.size()) {
            continue;
        }
        if (seen.emplace(ref).second) {
            source_refs.push_back(ref);
        }
    }
    std::ranges::sort(source_refs);
    for (uint32_t ref : source_refs) {
        auto encoded = EncodeSource(ref, sources[ref - 1]);
        WriteMessage(batch.protobuf, 7, encoded);
    }

    for (const auto& item : events) {
        if (item.event.source_ref == 0 ||
            item.event.source_ref > sources.size()) {
            continue;
        }
        auto encoded = EncodeEvent(item, boot_id);
        WriteMessage(batch.protobuf, 8, encoded);
    }
    return batch;
}

std::vector<uint8_t> CompressZstd(
    std::span<const uint8_t> input,
    int level) {
    if (input.empty()) {
        return {};
    }
    std::vector<uint8_t> compressed(ZSTD_compressBound(input.size()));
    const size_t size = ZSTD_compress(
        compressed.data(), compressed.size(), input.data(), input.size(), level);
    if (ZSTD_isError(size)) {
        return {};
    }
    compressed.resize(size);
    return compressed;
}

std::string HexId(const Id128& id) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(id.size() * 2);
    for (size_t i = 0; i < id.size(); ++i) {
        out[i * 2] = kHex[id[i] >> 4];
        out[i * 2 + 1] = kHex[id[i] & 0x0f];
    }
    return out;
}

}  // namespace acpp::accesslog::detail
