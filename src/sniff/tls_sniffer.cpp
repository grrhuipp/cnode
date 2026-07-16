#include "acppnode/sniff/sniffer.hpp"

#include "acppnode/core/constants.hpp"
#include "acppnode/transport/internet/tls_server_name.hpp"

namespace acpp {
namespace {
namespace tls {

constexpr uint8_t kContentTypeHandshake = 0x16;
constexpr uint8_t kHandshakeClientHello = 0x01;
constexpr uint16_t kExtensionSni = 0x0000;
constexpr uint16_t kTls10 = 0x0301;
constexpr uint16_t kTls13 = 0x0304;

[[nodiscard]] uint16_t ReadU16(std::span<const uint8_t> data,
                               size_t offset) noexcept {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(data[offset]) << 8) |
        static_cast<uint16_t>(data[offset + 1]));
}

[[nodiscard]] uint32_t ReadU24(std::span<const uint8_t> data,
                               size_t offset) noexcept {
    return (static_cast<uint32_t>(data[offset]) << 16) |
           (static_cast<uint32_t>(data[offset + 1]) << 8) |
           static_cast<uint32_t>(data[offset + 2]);
}

}  // namespace tls
}  // namespace

SniffResult TlsSniffer::Sniff(std::span<const uint8_t> data) {
    SniffResult result;
    auto sni = ParseClientHello(data);
    if (sni) {
        result.success = true;
        result.protocol = constants::protocol::kTls;
        result.domain.assign(*sni);
        result.port = 0;
    }
    return result;
}

std::optional<std::string_view> TlsSniffer::ParseClientHello(
    std::span<const uint8_t> data) {
    if (data.size() < 5 || data[0] != tls::kContentTypeHandshake) {
        return std::nullopt;
    }

    const uint16_t record_version = tls::ReadU16(data, 1);
    if ((record_version < tls::kTls10 || record_version > tls::kTls13) &&
        record_version != 0x0300) {
        return std::nullopt;
    }

    const uint16_t record_size = tls::ReadU16(data, 3);
    if (record_size > data.size() - 5) return std::nullopt;
    const auto record = data.subspan(5, record_size);
    if (record.size() < 4 || record[0] != tls::kHandshakeClientHello) {
        return std::nullopt;
    }

    const uint32_t handshake_size = tls::ReadU24(record, 1);
    if (handshake_size > record.size() - 4) return std::nullopt;
    const auto body = record.subspan(4, handshake_size);
    if (body.size() < 2 + 32 + 1) return std::nullopt;

    size_t position = 2 + 32;
    const uint8_t session_id_size = body[position++];
    if (session_id_size > body.size() - position) return std::nullopt;
    position += session_id_size;

    if (body.size() - position < 2) return std::nullopt;
    const uint16_t cipher_suites_size = tls::ReadU16(body, position);
    position += 2;
    if (cipher_suites_size < 2 || (cipher_suites_size & 1u) != 0 ||
        cipher_suites_size > body.size() - position) {
        return std::nullopt;
    }
    position += cipher_suites_size;

    if (position == body.size()) return std::nullopt;
    const uint8_t compression_size = body[position++];
    if (compression_size == 0 || compression_size > body.size() - position) {
        return std::nullopt;
    }
    position += compression_size;

    if (body.size() - position < 2) return std::nullopt;
    const uint16_t extensions_size = tls::ReadU16(body, position);
    position += 2;
    if (extensions_size != body.size() - position) return std::nullopt;
    return ExtractSNI(body.subspan(position, extensions_size));
}

std::optional<std::string_view> TlsSniffer::ExtractSNI(
    std::span<const uint8_t> extensions) {
    std::optional<std::string_view> server_name;
    size_t position = 0;
    while (position < extensions.size()) {
        if (extensions.size() - position < 4) return std::nullopt;
        const uint16_t extension_type = tls::ReadU16(extensions, position);
        position += 2;
        const uint16_t extension_size = tls::ReadU16(extensions, position);
        position += 2;
        if (extension_size > extensions.size() - position) {
            return std::nullopt;
        }
        if (extension_type == tls::kExtensionSni) {
            if (server_name) return std::nullopt;
            auto parsed = transport::internet::ParseTlsServerNameExtension(
                extensions.subspan(position, extension_size));
            if (!parsed) return std::nullopt;
            server_name = *parsed;
        }
        position += extension_size;
    }
    return server_name;
}

}  // namespace acpp
