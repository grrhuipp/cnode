#include "acppnode/protocol/trojan/trojan_codec.hpp"
#include "acppnode/protocol/trojan/trojan_user_manager.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/common/byte_reader.hpp"
#include "acppnode/common/unsafe.hpp"

namespace acpp::trojan {

using acpp::AddressType;
using acpp::TargetAddress;

const uint8_t TrojanCodec::CRLF[2] = {0x0D, 0x0A};

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
    req.password_hash = std::string(unsafe::ptr_cast<const char>(hash_span.data()), 56);

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

    // 解析地址
    if (atype == 0x01) {
        auto ipv4_bytes = reader.ReadBytes(4);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) return std::nullopt;

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ipv4_bytes.data(), ip_str, sizeof(ip_str));
        req.target = TargetAddress(ip_str, port);

    } else if (atype == 0x03) {
        uint8_t domain_len = reader.ReadU8();
        if (!reader.Ok()) return std::nullopt;

        // 安全加固：域名长度验证 (DNS 最大长度为 253)
        if (domain_len == 0 || domain_len > 253) {
            LOG_ACCESS_DEBUG("Invalid domain length: {}", domain_len);
            return std::nullopt;
        }

        std::string domain = reader.ReadString(domain_len);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) return std::nullopt;

        req.target = TargetAddress(domain, port);

    } else if (atype == 0x04) {
        auto ipv6_bytes = reader.ReadBytes(16);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) return std::nullopt;

        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ipv6_bytes.data(), ip_str, sizeof(ip_str));
        req.target = TargetAddress(ip_str, port);

    } else {
        return std::nullopt;
    }

    // CRLF
    cr = reader.ReadU8();
    lf = reader.ReadU8();
    if (!reader.Ok() || cr != 0x0D || lf != 0x0A) {
        return std::nullopt;
    }

    consumed = reader.Position();
    return req;
}

memory::ByteVector TrojanCodec::EncodeRequest(
    const std::string& password,
    TrojanCommand cmd,
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len) {

    memory::ByteVector buf;
    buf.resize(128 + payload_len);

    ByteWriter writer(buf.data(), buf.size());

    std::string hash = TrojanUserManager::HashPassword(password);
    writer.WriteString(hash);

    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);
    writer.WriteU8(static_cast<uint8_t>(cmd));

    if (target.IsDomain()) {
        writer.WriteU8(0x03);
        writer.WriteU8(static_cast<uint8_t>(target.host.size()));
        writer.WriteString(target.host);
    } else if (target.type == AddressType::IPv4) {
        writer.WriteU8(0x01);
        in_addr addr;
        inet_pton(AF_INET, target.host.c_str(), &addr);
        writer.WriteBytes(unsafe::ptr_cast<const uint8_t>(&addr), 4);
    } else {
        writer.WriteU8(0x04);
        in6_addr addr;
        inet_pton(AF_INET6, target.host.c_str(), &addr);
        writer.WriteBytes(unsafe::ptr_cast<const uint8_t>(&addr), 16);
    }

    writer.WriteU16BE(target.port);
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);

    if (payload && payload_len > 0) {
        writer.WriteBytes(payload, payload_len);
    }

    buf.resize(writer.Position());
    return buf;
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
    if (target.IsDomain()) {
        header_size += 1 + 1 + target.host.size();
    } else if (target.type == AddressType::IPv4) {
        header_size += 1 + 4;
    } else {
        header_size += 1 + 16;
    }

    if (header_size > output_size) {
        return 0;
    }

    ByteWriter writer(output, output_size);

    std::string hash = TrojanUserManager::HashPassword(password);
    writer.WriteString(hash);
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);
    writer.WriteU8(static_cast<uint8_t>(cmd));

    if (target.IsDomain()) {
        writer.WriteU8(0x03);
        writer.WriteU8(static_cast<uint8_t>(target.host.size()));
        writer.WriteString(target.host);
    } else if (target.type == AddressType::IPv4) {
        writer.WriteU8(0x01);
        in_addr addr;
        inet_pton(AF_INET, target.host.c_str(), &addr);
        writer.WriteBytes(unsafe::ptr_cast<const uint8_t>(&addr), 4);
    } else {
        writer.WriteU8(0x04);
        in6_addr addr;
        inet_pton(AF_INET6, target.host.c_str(), &addr);
        writer.WriteBytes(unsafe::ptr_cast<const uint8_t>(&addr), 16);
    }

    writer.WriteU16BE(target.port);
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);

    if (payload && payload_len > 0) {
        writer.WriteBytes(payload, payload_len);
    }

    return writer.Position();
}

// ============================================================================
// UDP 包编解码
// ============================================================================

std::optional<TrojanCodec::UdpPacket> TrojanCodec::ParseUdpPacket(
    const uint8_t* data,
    size_t len,
    size_t& consumed) {

    consumed = 0;

    // 最小长度：1(atype) + 1(addr) + 2(port) + 2(length) + 2(CRLF) = 8
    if (len < 8) {
        return std::nullopt;
    }

    ByteReader reader(data, len);
    UdpPacket pkt;

    uint8_t atype = reader.ReadU8();
    if (!reader.Ok()) return std::nullopt;

    if (atype == 0x01) {
        auto ipv4_bytes = reader.ReadBytes(4);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) return std::nullopt;

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ipv4_bytes.data(), ip_str, sizeof(ip_str));
        pkt.target = TargetAddress(ip_str, port);

    } else if (atype == 0x03) {
        uint8_t domain_len = reader.ReadU8();
        if (!reader.Ok()) return std::nullopt;

        if (domain_len == 0 || domain_len > 253) {
            return std::nullopt;
        }

        std::string domain = reader.ReadString(domain_len);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) return std::nullopt;

        pkt.target = TargetAddress(domain, port);

    } else if (atype == 0x04) {
        auto ipv6_bytes = reader.ReadBytes(16);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) return std::nullopt;

        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ipv6_bytes.data(), ip_str, sizeof(ip_str));
        pkt.target = TargetAddress(ip_str, port);

    } else {
        return std::nullopt;
    }

    uint16_t payload_len = reader.ReadU16BE();
    if (!reader.Ok()) return std::nullopt;

    uint8_t cr = reader.ReadU8();
    uint8_t lf = reader.ReadU8();
    if (!reader.Ok() || cr != 0x0D || lf != 0x0A) {
        return std::nullopt;
    }

    auto payload_span = reader.ReadBytes(payload_len);
    if (!reader.Ok()) return std::nullopt;

    pkt.payload.assign(payload_span.begin(), payload_span.end());
    consumed = reader.Position();
    return pkt;
}

TrojanCodec::UdpParseOutput TrojanCodec::ParseUdpPacketEx(
    const uint8_t* data,
    size_t len) {

    UdpParseOutput output;
    output.result = UdpParseResult::INCOMPLETE;
    output.consumed = 0;

    if (len < 8) {
        output.error_reason = "buffer too short (< 8 bytes)";
        return output;
    }

    ByteReader reader(data, len);
    UdpPacket pkt;

    uint8_t atype = reader.ReadU8();

    if (atype == 0x01) {
        auto ipv4_bytes = reader.ReadBytes(4);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) {
            output.error_reason = "incomplete IPv4 address";
            return output;
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, ipv4_bytes.data(), ip_str, sizeof(ip_str));
        pkt.target = TargetAddress(ip_str, port);

    } else if (atype == 0x03) {
        uint8_t domain_len = reader.ReadU8();
        if (!reader.Ok()) {
            output.error_reason = "incomplete domain length";
            return output;
        }

        if (domain_len == 0 || domain_len > 253) {
            output.result = UdpParseResult::INVALID;
            output.error_reason = "invalid domain length";
            return output;
        }

        std::string domain = reader.ReadString(domain_len);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) {
            output.error_reason = std::format("incomplete domain: need {} bytes", domain_len);
            return output;
        }

        pkt.target = TargetAddress(domain, port);

    } else if (atype == 0x04) {
        auto ipv6_bytes = reader.ReadBytes(16);
        uint16_t port = reader.ReadU16BE();
        if (!reader.Ok()) {
            output.error_reason = "incomplete IPv6 address";
            return output;
        }

        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ipv6_bytes.data(), ip_str, sizeof(ip_str));
        pkt.target = TargetAddress(ip_str, port);

    } else {
        output.result = UdpParseResult::INVALID;
        output.error_reason = std::format("invalid atype: 0x{:02x}", atype);
        return output;
    }

    uint16_t payload_len = reader.ReadU16BE();
    if (!reader.Ok()) {
        output.error_reason = "incomplete payload length";
        return output;
    }

    uint8_t cr = reader.ReadU8();
    uint8_t lf = reader.ReadU8();
    if (!reader.Ok()) {
        output.error_reason = "incomplete CRLF";
        return output;
    }

    if (cr != 0x0D || lf != 0x0A) {
        output.result = UdpParseResult::INVALID;
        output.error_reason = std::format("CRLF mismatch: expected 0x0D 0x0A, got 0x{:02x} 0x{:02x}",
                                          cr, lf);
        return output;
    }

    auto payload_span = reader.ReadBytes(payload_len);
    if (!reader.Ok()) {
        output.error_reason = std::format("incomplete payload: need {} bytes, have {}",
                                          payload_len, reader.Remaining());
        return output;
    }

    pkt.payload.assign(payload_span.begin(), payload_span.end());
    output.result = UdpParseResult::SUCCESS;
    output.packet = std::move(pkt);
    output.consumed = reader.Position();
    return output;
}

memory::ByteVector TrojanCodec::EncodeUdpPacket(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len) {

    memory::ByteVector buf;
    buf.resize(64 + payload_len);

    ByteWriter writer(buf.data(), buf.size());

    if (target.IsDomain()) {
        writer.WriteU8(0x03);
        writer.WriteU8(static_cast<uint8_t>(target.host.size()));
        writer.WriteString(target.host);
    } else if (target.type == AddressType::IPv4) {
        writer.WriteU8(0x01);
        in_addr addr;
        inet_pton(AF_INET, target.host.c_str(), &addr);
        writer.WriteBytes(unsafe::ptr_cast<const uint8_t>(&addr), 4);
    } else {
        writer.WriteU8(0x04);
        in6_addr addr;
        inet_pton(AF_INET6, target.host.c_str(), &addr);
        writer.WriteBytes(unsafe::ptr_cast<const uint8_t>(&addr), 16);
    }

    writer.WriteU16BE(target.port);
    writer.WriteU16BE(static_cast<uint16_t>(payload_len));
    writer.WriteU8(0x0D);
    writer.WriteU8(0x0A);

    if (payload && payload_len > 0) {
        writer.WriteBytes(payload, payload_len);
    }

    buf.resize(writer.Position());
    return buf;
}

size_t TrojanCodec::EncodeUdpPacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    uint8_t* output,
    size_t output_size) {

    size_t header_size = 0;
    if (target.IsDomain()) {
        header_size = 1 + 1 + target.host.size();
    } else if (target.type == AddressType::IPv4) {
        header_size = 1 + 4;
    } else {
        header_size = 1 + 16;
    }
    header_size += 2 + 2 + 2;  // port + payload_len + CRLF

    if (header_size + payload_len > output_size) {
        return 0;
    }

    ByteWriter writer(output, output_size);

    if (target.IsDomain()) {
        writer.WriteU8(0x03);
        writer.WriteU8(static_cast<uint8_t>(target.host.size()));
        writer.WriteString(target.host);
    } else if (target.type == AddressType::IPv4) {
        writer.WriteU8(0x01);
        in_addr addr;
        inet_pton(AF_INET, target.host.c_str(), &addr);
        writer.WriteBytes(unsafe::ptr_cast<const uint8_t>(&addr), 4);
    } else {
        writer.WriteU8(0x04);
        in6_addr addr;
        inet_pton(AF_INET6, target.host.c_str(), &addr);
        writer.WriteBytes(unsafe::ptr_cast<const uint8_t>(&addr), 16);
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
