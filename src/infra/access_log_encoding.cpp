#include "access_log_encoding.hpp"

#include <zstd.h>

#include <algorithm>
#include <charconv>
#include <limits>
#include <unordered_set>

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
