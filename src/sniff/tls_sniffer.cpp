#include "acppnode/sniff/sniffer.hpp"
#include "acppnode/common/ip_address.hpp"

#include "acppnode/common/byte_reader.hpp"
#include "acppnode/common/domain_name.hpp"
#include "acppnode/core/constants.hpp"
#include "acppnode/transport/internet/tls_server_name.hpp"

namespace acpp {
namespace {

constexpr uint8_t kContentTypeHandshake = 0x16;
constexpr uint8_t kHandshakeClientHello = 0x01;
constexpr uint16_t kExtensionServerName = 0x0000;
constexpr uint16_t kSsl30 = 0x0300;
constexpr uint16_t kTls10 = 0x0301;
constexpr uint16_t kTls13 = 0x0304;

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
    (void)body.Skip(body.ReadU8());
    const uint16_t cipher_suites_size = body.ReadU16BE();
    if (cipher_suites_size < 2 || (cipher_suites_size & 1u) != 0) {
        return std::nullopt;
    }
    (void)body.Skip(cipher_suites_size);
    const uint8_t compression_methods_size = body.ReadU8();
    if (compression_methods_size == 0) return std::nullopt;
    (void)body.Skip(compression_methods_size);
    const auto extensions = body.ReadBytes(body.ReadU16BE());
    if (!body.Ok()) return std::nullopt;
    return ExtractServerName(extensions);
}

SniffResult SniffTls(std::span<const uint8_t> data) {
    SniffResult result;
    ByteReader reader(data);
    if (reader.ReadU8() != kContentTypeHandshake) return result;
    const uint16_t record_version = reader.ReadU16BE();
    if ((record_version < kTls10 || record_version > kTls13) &&
        record_version != kSsl30) {
        return result;
    }
    const auto record = reader.ReadBytes(reader.ReadU16BE());
    if (!reader.Ok()) return result;

    if (auto server_name = ParseClientHelloServerName(record)) {
        result.success = true;
        result.protocol = constants::protocol::kTls;
        result.domain.assign(*server_name);
    }
    return result;
}

}  // namespace acpp
