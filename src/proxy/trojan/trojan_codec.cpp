#include "trojan_codec.hpp"
#include "acppnode/common/address_codec.hpp"
#include "acppnode/common/byte_reader.hpp"
namespace acpp::trojan {

namespace {

[[nodiscard]] constexpr bool IsHexDigit(uint8_t ch) noexcept {
    return (ch >= '0' && ch <= '9') ||
           (ch >= 'a' && ch <= 'f') ||
           (ch >= 'A' && ch <= 'F');
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

    auto parsed_addr = DecodeAddress(
        std::span<const uint8_t>(data + reader.Position(), reader.Remaining()),
        AddressWireFormat::Socks5, {253, true});
    if (parsed_addr.status != AddressDecodeStatus::Complete ||
        !reader.Skip(parsed_addr.consumed)) {
        return std::nullopt;
    }
    req.target = std::move(parsed_addr.target);
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

    const size_t addr_size = AddressEncodedSize(target, AddressWireFormat::Socks5);
    if (addr_size == 0 || payload_len > output_size ||
        (payload_len != 0 && !payload)) {
        return 0;
    }
    const size_t header_size = 56 + 2 + 1 + addr_size + 2;

    if (!output || header_size > output_size - payload_len) {
        return 0;
    }

    ByteWriter writer(output, output_size);

    writer.WriteString(std::string_view(password_hash.data(), password_hash.size()));
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);
    writer.WriteU8(static_cast<uint8_t>(cmd));

    const size_t encoded = EncodeAddressTo(target, output + writer.Position(),
        output_size - writer.Position(), AddressWireFormat::Socks5);
    if (encoded == 0) return 0;
    ByteWriter tail(output + writer.Position() + encoded,
                    output_size - writer.Position() - encoded);
    tail.WriteU8(0x0D);
    tail.WriteU8(0x0A);

    if (payload && payload_len > 0) {
        tail.WriteBytes(payload, payload_len);
    }

    return writer.Position() + encoded + tail.Position();
}

size_t TrojanCodec::EncodeUdpPacketHeaderTo(
    const TargetAddress& target,
    size_t payload_len,
    uint8_t* output,
    size_t output_size) {
    if (payload_len > 0xFFFF) {
        return 0;
    }

    const size_t address_size = AddressEncodedSize(target, AddressWireFormat::Socks5);
    if (!output || address_size == 0 || address_size + 4 > output_size) return 0;
    const size_t encoded = EncodeAddressTo(
        target, output, output_size, AddressWireFormat::Socks5);
    if (encoded == 0) return 0;
    ByteWriter writer(output + encoded, output_size - encoded);
    writer.WriteU16BE(static_cast<uint16_t>(payload_len));
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);

    return encoded + writer.Position();
}


}  // namespace acpp::trojan
