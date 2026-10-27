#include "trojan_codec.hpp"
#include "../socks5_address.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/byte_reader.hpp"
#include "acppnode/common/unsafe.hpp"
namespace acpp::trojan {

using acpp::AddressType;
using acpp::TargetAddress;

namespace {

[[nodiscard]] constexpr bool IsHexDigit(uint8_t ch) noexcept {
    return (ch >= '0' && ch <= '9') ||
           (ch >= 'a' && ch <= 'f') ||
           (ch >= 'A' && ch <= 'F');
}
size_t SocksAddressSize(const TargetAddress& target) {
    return proxy::Socks5AddressBodySize(target);
}

bool WriteSocksAddress(ByteWriter& writer, const TargetAddress& target) {
    std::array<uint8_t, 1 + 1 + 255> encoded{};
    const size_t n = proxy::EncodeSocks5AddressBodyTo(target, encoded.data(), encoded.size());
    if (n == 0) {
        return false;
    }
    return writer.WriteBytes(encoded.data(), n);
}

}  // namespace

// ============================================================================
// TCP 请求编解码
// ============================================================================

std::optional<TrojanRequest> TrojanCodec::ParseRequest(
    const uint8_t* data,
    size_t len,
    size_t& consumed) {

    consumed = 0;

    // 最小长度：56(hash) + 2(CRLF) + 1(cmd) + 1(atype) + 1(addr) + 2(port) + 2(CRLF) = 65
    if (len < 65) {
        return std::nullopt;
    }

    ByteReader reader(data, len);
    TrojanRequest req;

    // 解析密码哈希（56 字节十六进制）
    auto hash_span = reader.ReadBytes(56);
    if (!reader.Ok()) return std::nullopt;
    for (uint8_t ch : hash_span) {
        if (!IsHexDigit(ch)) {
            return std::nullopt;
        }
    }
    std::memcpy(req.password_hash.data(), hash_span.data(), req.password_hash.size());
    // CRLF
    uint8_t cr = reader.ReadU8();
    uint8_t lf = reader.ReadU8();
    if (!reader.Ok() || cr != 0x0D || lf != 0x0A) {
        return std::nullopt;
    }

    // 命令
    uint8_t cmd = reader.ReadU8();
    if (!reader.Ok()) return std::nullopt;
    req.command = static_cast<TrojanCommand>(cmd);
    if (req.command != TrojanCommand::CONNECT && req.command != TrojanCommand::UDP_ASSOCIATE) {
        return std::nullopt;
    }

    auto parsed_addr = proxy::ParseSocks5Address(
        data + reader.Position(), reader.Remaining(), 253, true);
    if (!parsed_addr || !reader.Skip(parsed_addr->consumed)) {
        return std::nullopt;
    }
    req.target = std::move(parsed_addr->target);
    // CRLF
    cr = reader.ReadU8();
    lf = reader.ReadU8();
    if (!reader.Ok() || cr != 0x0D || lf != 0x0A) {
        return std::nullopt;
    }

    consumed = reader.Position();
    return req;
}

size_t TrojanCodec::EncodeRequestTo(
    std::span<const char, 56> password_hash,
    TrojanCommand cmd,
    const TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    const uint8_t* payload,
    size_t payload_len) {

    size_t header_size = 56 + 2 + 1 + 2 + 2 + payload_len;
    size_t addr_size = SocksAddressSize(target);
    if (addr_size == 0) {
        return 0;
    }
    header_size += addr_size;

    if (header_size > output_size) {
        return 0;
    }

    ByteWriter writer(output, output_size);

    writer.WriteString(std::string_view(password_hash.data(), password_hash.size()));
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);
    writer.WriteU8(static_cast<uint8_t>(cmd));

    if (!WriteSocksAddress(writer, target)) {
        return 0;
    }

    writer.WriteU16BE(target.port);
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);

    if (payload && payload_len > 0) {
        writer.WriteBytes(payload, payload_len);
    }

    return writer.Position();
}

size_t TrojanCodec::EncodeUdpPacketHeaderTo(
    const TargetAddress& target,
    size_t payload_len,
    uint8_t* output,
    size_t output_size) {
    if (payload_len > 0xFFFF) {
        return 0;
    }

    size_t header_size = 0;
    header_size = SocksAddressSize(target);
    if (header_size == 0) {
        return 0;
    }
    header_size += 2 + 2 + 2;  // port + payload_len + CRLF

    if (header_size > output_size) {
        return 0;
    }

    ByteWriter writer(output, output_size);

    if (!WriteSocksAddress(writer, target)) {
        return 0;
    }

    writer.WriteU16BE(target.port);
    writer.WriteU16BE(static_cast<uint16_t>(payload_len));
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);

    return writer.Position();
}

TrojanCodec::UdpParseOutput TrojanCodec::ParseUdpPacket(
    const uint8_t* data,
    size_t len) {
    UdpParseOutput output;
    if (len < 8) {
        return output;
    }

    ByteReader reader(data, len);
    UdpPacket pkt;

    const uint8_t atype = reader.ReadU8();
    if (atype == 0x01) {
        if (reader.Remaining() < 6) {
            return output;
        }
        auto ipv4_bytes = reader.ReadBytes(4);
        const uint16_t port = reader.ReadU16BE();
        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), ipv4_bytes.data(), bytes.size());
        pkt.target = TargetAddress(net::ip::make_address_v4(bytes), port);
    } else if (atype == 0x03) {
        if (reader.Remaining() < 1) {
            return output;
        }
        const uint8_t domain_len = reader.ReadU8();
        if (domain_len == 0 || domain_len > 253) {
            output.result = UdpParseResult::INVALID;
            return output;
        }
        if (reader.Remaining() < static_cast<size_t>(domain_len) + 2) {
            return output;
        }
        const std::string_view domain = reader.ReadStringView(domain_len);
        const uint16_t port = reader.ReadU16BE();
        pkt.target = TargetAddress(domain, port);
    } else if (atype == 0x04) {
        if (reader.Remaining() < 18) {
            return output;
        }
        auto ipv6_bytes = reader.ReadBytes(16);
        const uint16_t port = reader.ReadU16BE();
        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), ipv6_bytes.data(), bytes.size());
        pkt.target = TargetAddress(net::ip::make_address_v6(bytes), port);
    } else {
        output.result = UdpParseResult::INVALID;
        return output;
    }

    const uint16_t payload_len = reader.ReadU16BE();
    if (!reader.Ok()) {
        return output;
    }

    const uint8_t cr = reader.ReadU8();
    const uint8_t lf = reader.ReadU8();
    if (!reader.Ok()) {
        return output;
    }
    if (cr != 0x0D || lf != 0x0A) {
        output.result = UdpParseResult::INVALID;
        return output;
    }

    auto payload = reader.ReadBytes(payload_len);
    if (!reader.Ok()) {
        return output;
    }

    pkt.payload = payload;
    output.result = UdpParseResult::SUCCESS;
    output.packet = std::move(pkt);
    output.consumed = reader.Position();
    return output;
}

}  // namespace acpp::trojan
