#include "sniff/sniffer.hpp"
#include "common/ip_address.hpp"

#include "common/byte_reader.hpp"
#include "common/domain_name.hpp"
#include "core/constants.hpp"
#include "transport/internet/tls_server_name.hpp"

#include <algorithm>
#include <array>

namespace {

constexpr uint8_t kContentTypeHandshake = 0x16;
constexpr uint8_t kHandshakeClientHello = 0x01;
constexpr uint16_t kExtensionServerName = 0x0000;
constexpr uint16_t kSsl30 = 0x0300;
constexpr uint16_t kTls10 = 0x0301;
constexpr uint16_t kTls13 = 0x0304;
constexpr size_t kTlsRecordHeaderBytes = 5;
constexpr size_t kMaxTlsSniffWireBytes = 4096;
constexpr size_t kMaxTlsSniffHandshakeBytes =
    kMaxTlsSniffWireBytes - kTlsRecordHeaderBytes;

[[nodiscard]] size_t ClientHelloSize(std::span<const uint8_t> handshake) noexcept {
    return 4 + ((static_cast<size_t>(handshake[1]) << 16) |
                (static_cast<size_t>(handshake[2]) << 8) | handshake[3]);
}

[[nodiscard]] bool FitsTlsSniffWireBudget(
    size_t record_headers_bytes,
    size_t committed_payload_bytes,
    std::span<const uint8_t> handshake_prefix) noexcept {
    if (record_headers_bytes > kMaxTlsSniffWireBytes ||
        committed_payload_bytes > kMaxTlsSniffWireBytes - record_headers_bytes) {
        return false;
    }
    if (handshake_prefix.size() >= 4) {
        const size_t hello_size = ClientHelloSize(handshake_prefix);
        const size_t extra_header =
            hello_size > committed_payload_bytes ? kTlsRecordHeaderBytes : 0;
        if (hello_size > kMaxTlsSniffWireBytes - record_headers_bytes ||
            extra_header >
                kMaxTlsSniffWireBytes - record_headers_bytes - hello_size) {
            return false;
        }
        return true;
    }
    if (committed_payload_bytes == handshake_prefix.size()) {
        const size_t min_remaining_hello = 4 - handshake_prefix.size();
        if (kTlsRecordHeaderBytes + min_remaining_hello >
            kMaxTlsSniffWireBytes - record_headers_bytes -
                committed_payload_bytes) {
            return false;
        }
    }
    return true;
}
[[nodiscard]] std::optional<std::string_view> ExtractServerName(
    std::span<const uint8_t> extensions) {
    std::optional<std::string_view> server_name;
    ByteReader reader(extensions);
    while (!reader.Empty()) {
        const uint16_t extension_type = reader.ReadU16BE();
        const auto extension = reader.ReadBytes(reader.ReadU16BE());
        if (!reader.Ok()) return std::nullopt;
        if (extension_type != kExtensionServerName) continue;
        // RFC 8446 §4.2: duplicate extensions of one type are ambiguous.
        if (server_name) return std::nullopt;
        auto parsed =
            transport::internet::ParseTlsServerNameExtension(extension);
        if (!parsed ||
            !domain::IsValidDnsHostname(
                *parsed, domain::TrailingDotPolicy::Forbid) ||
            iputil::ParseLiteral(*parsed)) {
            return std::nullopt;
        }
        server_name = *parsed;
    }
    return server_name;
}


[[nodiscard]] bool TryFinishClientHelloSniff(
    std::span<const uint8_t> handshake, SniffResult& result) {
    if (handshake.size() < 4) return false;
    const size_t hello_size = ClientHelloSize(handshake);
    if (hello_size > kMaxTlsSniffHandshakeBytes) return true;
    if (handshake.size() < hello_size) return false;
    if (auto server_name =
            ParseClientHelloServerName(handshake.first(hello_size))) {
        result.success = true;
        result.protocol = constants::protocol::kTls;
        result.domain.assign(*server_name);
    }
    return true;
}
}  // namespace

std::optional<std::string_view> ParseClientHelloServerName(
    std::span<const uint8_t> handshake) {
    ByteReader reader(handshake);
    if (reader.ReadU8() != kHandshakeClientHello) return std::nullopt;
    const uint8_t size_high = reader.ReadU8();
    const size_t body_size =
        (static_cast<size_t>(size_high) << 16) | reader.ReadU16BE();
    ByteReader body(reader.ReadBytes(body_size));
    if (!reader.Ok()) return std::nullopt;

    // legacy_version + random, then legacy_session_id.
    (void)body.Skip(2 + 32);
    const uint8_t session_id_size = body.ReadU8();
    if (session_id_size > 32) return std::nullopt;
    (void)body.Skip(session_id_size);
    const uint16_t cipher_suites_size = body.ReadU16BE();
    if (cipher_suites_size < 2 || (cipher_suites_size & 1u) != 0) {
        return std::nullopt;
    }
    (void)body.Skip(cipher_suites_size);
    const uint8_t compression_methods_size = body.ReadU8();
    if (compression_methods_size == 0) return std::nullopt;
    (void)body.Skip(compression_methods_size);
    const auto extensions = body.ReadBytes(body.ReadU16BE());
    if (!body.Ok() || !body.Empty()) return std::nullopt;
    return ExtractServerName(extensions);
}

SniffResult SniffTls(std::span<const uint8_t> data) {
    SniffResult result;
    ByteReader reader(data);
    if (reader.ReadU8() != kContentTypeHandshake) return result;
    if (reader.Empty() ||
        (reader.Remaining() == 1 && reader.ReadU8() == 0x03)) {
        result.need_more = true;
        result.protocol = constants::protocol::kTls;
        return result;
    }
    const uint16_t record_version = reader.ReadU16BE();
    if (!reader.Ok()) return result;
    if ((record_version < kTls10 || record_version > kTls13) &&
        record_version != kSsl30) {
        return result;
    }
    bool version_supports_need_more =
        record_version >= kTls10 && record_version <= kTls13;
    if (reader.Remaining() < 2) {
        if (version_supports_need_more) {
            result.need_more = true;
            result.protocol = constants::protocol::kTls;
        }
        return result;
    }
    const uint16_t record_len = reader.ReadU16BE();
    if (record_len == 0 ||
        !FitsTlsSniffWireBudget(kTlsRecordHeaderBytes, record_len, {})) {
        return result;
    }
    const auto record = reader.ReadBytes(record_len);
    if (!reader.Ok()) {
        const auto partial_first = data.subspan(kTlsRecordHeaderBytes);
        if (version_supports_need_more &&
            (partial_first.empty() ||
             partial_first[0] == kHandshakeClientHello) &&
            FitsTlsSniffWireBudget(
                kTlsRecordHeaderBytes, record_len, partial_first)) {
            result.need_more = true;
            result.protocol = constants::protocol::kTls;
        }
        return result;
    }
    if (record[0] != kHandshakeClientHello) return result;
    if (!FitsTlsSniffWireBudget(kTlsRecordHeaderBytes, record.size(), record)) {
        return result;
    }

    if (TryFinishClientHelloSniff(record, result)) return result;
    if (reader.Empty()) {
        if (version_supports_need_more) {
            result.need_more = true;
            result.protocol = constants::protocol::kTls;
        }
        return result;
    }

    std::array<uint8_t, kMaxTlsSniffHandshakeBytes> reassembled{};
    std::copy_n(record.data(), record.size(), reassembled.data());
    size_t reassembled_size = record.size();
    size_t record_headers_bytes = kTlsRecordHeaderBytes;

    while (!reader.Empty()) {
        record_headers_bytes += kTlsRecordHeaderBytes;
        if (record_headers_bytes + reassembled_size >= kMaxTlsSniffWireBytes) {
            return result;
        }
        if (reassembled_size >= 4 &&
            ClientHelloSize(
                std::span<const uint8_t>(reassembled.data(), reassembled_size)) >
                kMaxTlsSniffWireBytes - record_headers_bytes) {
            return result;
        }
        if (reader.ReadU8() != kContentTypeHandshake) return result;
        if (reader.Empty()) {
            if (version_supports_need_more) {
                result.need_more = true;
                result.protocol = constants::protocol::kTls;
            }
            return result;
        }
        if (reader.Remaining() == 1) {
            if (reader.ReadU8() != 0x03) return result;
            if (version_supports_need_more) {
                result.need_more = true;
                result.protocol = constants::protocol::kTls;
            }
            return result;
        }
        const uint16_t next_version = reader.ReadU16BE();
        if ((next_version < kTls10 || next_version > kTls13) &&
            next_version != kSsl30) {
            return result;
        }
        version_supports_need_more =
            version_supports_need_more &&
            next_version >= kTls10 && next_version <= kTls13;
        if (reader.Remaining() < 2) {
            if (version_supports_need_more) {
                result.need_more = true;
                result.protocol = constants::protocol::kTls;
            }
            return result;
        }
        const uint16_t next_len = reader.ReadU16BE();
        if (next_len == 0 ||
            next_len > kMaxTlsSniffHandshakeBytes - reassembled_size) {
            return result;
        }
        const size_t committed_payload_bytes = reassembled_size + next_len;
        if (reader.Remaining() < next_len) {
            const size_t avail = reader.Remaining();
            const auto partial = reader.ReadBytes(avail);
            std::copy_n(partial.data(), avail, reassembled.data() + reassembled_size);
            reassembled_size += avail;
            if (!FitsTlsSniffWireBudget(
                    record_headers_bytes,
                    committed_payload_bytes,
                    std::span<const uint8_t>(
                        reassembled.data(), reassembled_size))) {
                return result;
            }
            if (version_supports_need_more) {
                result.need_more = true;
                result.protocol = constants::protocol::kTls;
            }
            return result;
        }
        const auto next_record = reader.ReadBytes(next_len);
        std::copy_n(next_record.data(), next_len, reassembled.data() + reassembled_size);
        reassembled_size += next_len;
        const auto reassembled_span =
            std::span<const uint8_t>(reassembled.data(), reassembled_size);
        if (!FitsTlsSniffWireBudget(
                record_headers_bytes, committed_payload_bytes, reassembled_span)) {
            return result;
        }
        if (TryFinishClientHelloSniff(reassembled_span, result)) {
            return result;
        }
    }

    if (version_supports_need_more) {
        result.need_more = true;
        result.protocol = constants::protocol::kTls;
    }
    return result;
}

