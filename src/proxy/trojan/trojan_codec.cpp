#include "trojan_codec.hpp"
#include "acppnode/proxy/trojan/validator.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/byte_reader.hpp"
#include "acppnode/common/unsafe.hpp"
#include <openssl/sha.h>

namespace acpp::trojan {

using acpp::AddressType;
using acpp::TargetAddress;

const uint8_t TrojanCodec::CRLF[2] = {0x0D, 0x0A};
static const char HEX_CHARS[] = "0123456789abcdef";

std::string HashPassword(const std::string& password) {
    unsigned char hash[SHA224_DIGEST_LENGTH];
    SHA224(unsafe::ptr_cast<const unsigned char>(password.data()),
           password.size(), hash);

    std::string result;
    result.reserve(SHA224_DIGEST_LENGTH * 2);

    for (int i = 0; i < SHA224_DIGEST_LENGTH; ++i) {
        result.push_back(HEX_CHARS[hash[i] >> 4]);
        result.push_back(HEX_CHARS[hash[i] & 0x0F]);
    }

    return result;
}

namespace {

std::optional<TargetAddress> ReadSocksAddress(ByteReader& reader, uint8_t atype) {
    if (atype == 0x01) {
        auto ipv4_bytes = reader.ReadBytes(4);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) return std::nullopt;

        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), ipv4_bytes.data(), bytes.size());
        return TargetAddress(net::ip::make_address_v4(bytes), port);
    }

    if (atype == 0x03) {
        uint8_t domain_len = reader.ReadU8();
        if (!reader.Ok()) return std::nullopt;
        if (domain_len == 0 || domain_len > 253) {
            LOG_ACCESS_DEBUG("Invalid domain length: {}", domain_len);
            return std::nullopt;
        }

        std::string_view domain = reader.ReadStringView(domain_len);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) return std::nullopt;
        return TargetAddress(domain, port);
    }

    if (atype == 0x04) {
        auto ipv6_bytes = reader.ReadBytes(16);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) return std::nullopt;

        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), ipv6_bytes.data(), bytes.size());
        return TargetAddress(net::ip::make_address_v6(bytes), port);
    }

    return std::nullopt;
}

size_t SocksAddressSize(const TargetAddress& target) {
    if (target.IsDomain()) {
        return target.host.size() <= 255 ? 1 + 1 + target.host.size() : 0;
    }

    if (target.resolved_addr) {
        if (target.resolved_addr->is_v4()) return 1 + 4;
        if (target.resolved_addr->is_v6()) return 1 + 16;
    }

    return 0;
}

bool WriteSocksAddress(ByteWriter& writer, const TargetAddress& target) {
    if (target.IsDomain()) {
        if (target.host.size() > 255) return false;
        writer.WriteU8(0x03);
        writer.WriteU8(static_cast<uint8_t>(target.host.size()));
        writer.WriteString(target.host);
        return true;
    }

    if (target.resolved_addr && target.resolved_addr->is_v4()) {
        writer.WriteU8(0x01);
        auto bytes = target.resolved_addr->to_v4().to_bytes();
        writer.WriteBytes(bytes.data(), bytes.size());
        return true;
    }
    if (target.resolved_addr && target.resolved_addr->is_v6()) {
        writer.WriteU8(0x04);
        auto bytes = target.resolved_addr->to_v6().to_bytes();
        writer.WriteBytes(bytes.data(), bytes.size());
        return true;
    }

    return false;
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
    req.password_hash.assign(unsafe::ptr_cast<const char>(hash_span.data()), 56);

    // 验证哈希格式
    for (char c : req.password_hash) {
        if (!std::isxdigit(c)) {
            return std::nullopt;
        }
    }

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

    // 地址类型
    uint8_t atype = reader.ReadU8();
    if (!reader.Ok()) return std::nullopt;

    auto target = ReadSocksAddress(reader, atype);
    if (!target) {
        return std::nullopt;
    }
    req.target = std::move(*target);

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
    const std::string& password,
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

    std::string hash = HashPassword(password);
    writer.WriteString(hash);
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

size_t TrojanCodec::EncodeUdpPacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* output,
    size_t output_size) {

    size_t header_size = 0;
    header_size = SocksAddressSize(target);
    if (header_size == 0) {
        return 0;
    }
    header_size += 2 + 2 + 2;  // port + payload_len + CRLF

    if (header_size + payload_len > output_size) {
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

    if (payload && payload_len > 0) {
        writer.WriteBytes(payload, payload_len);
    }

    return writer.Position();
}

}  // namespace acpp::trojan
