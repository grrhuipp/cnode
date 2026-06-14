#include "ss_udp.hpp"
#include "shadowsocks_crypto.hpp"

#include <openssl/rand.h>
#include <algorithm>
#include <cstring>
#include <array>

namespace acpp::ss {

// ============================================================================
// 内部辅助：全零 nonce（SS UDP 每包用新 salt，nonce 固定为 0）
// ============================================================================
static std::array<uint8_t, 12> kZeroNonce{};

namespace {

struct SsAddress {
    TargetAddress target;
    size_t consumed = 0;
};

std::optional<SsAddress> ParseSocks5Address(const uint8_t* data, size_t len) {
    if (len < 1) return std::nullopt;

    SsAddress result;
    size_t idx = 0;

    const uint8_t atyp = data[idx++];

    if (atyp == 0x01) {
        if (idx + 4 + 2 > len) return std::nullopt;
        net::ip::address_v4::bytes_type bytes{};
        std::memcpy(bytes.data(), data + idx, bytes.size());
        idx += 4;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        result.target = TargetAddress(net::ip::make_address_v4(bytes), port);

    } else if (atyp == 0x03) {
        if (idx + 1 > len) return std::nullopt;
        const size_t name_len = data[idx++];
        if (idx + name_len + 2 > len) return std::nullopt;
        std::string domain(reinterpret_cast<const char*>(data + idx), name_len);
        idx += name_len;
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        result.target = TargetAddress(std::string_view(domain.data(), domain.size()), port);

    } else if (atyp == 0x04) {
        if (idx + 16 + 2 > len) return std::nullopt;
        net::ip::address_v6::bytes_type bytes{};
        std::memcpy(bytes.data(), data + idx, bytes.size());
        idx += bytes.size();
        const uint16_t port = static_cast<uint16_t>((data[idx] << 8) | data[idx + 1]);
        idx += 2;
        result.target = TargetAddress(net::ip::make_address_v6(bytes), port);
    } else {
        return std::nullopt;
    }

    result.consumed = idx;
    return result;
}

size_t Socks5AddressEncodedSize(const TargetAddress& addr) {
    if (addr.IsDomain()) {
        if (addr.host.size() > 255) {
            return 0;
        }
        return 1 + 1 + addr.host.size() + 2;
    }

    if (addr.resolved_addr) {
        if (addr.resolved_addr->is_v4()) {
            return 1 + 4 + 2;
        }
        if (addr.resolved_addr->is_v6()) {
            return 1 + 16 + 2;
        }
    }

    return 0;
}

size_t EncodeSocks5AddressTo(const TargetAddress& addr,
                            uint8_t* output,
                            size_t output_size) {
    const size_t needed = Socks5AddressEncodedSize(addr);
    if (needed == 0 || needed > output_size) {
        return 0;
    }

    size_t pos = 0;
    if (addr.IsDomain()) {
        if (addr.host.size() > 255) return 0;
        output[pos++] = 0x03;
        output[pos++] = static_cast<uint8_t>(addr.host.size());
        std::memcpy(output + pos, addr.host.data(), addr.host.size());
        pos += addr.host.size();
    } else {
        if (addr.resolved_addr && addr.resolved_addr->is_v4()) {
            output[pos++] = 0x01;
            auto bytes = addr.resolved_addr->to_v4().to_bytes();
            std::memcpy(output + pos, bytes.data(), bytes.size());
            pos += bytes.size();
        } else if (addr.resolved_addr && addr.resolved_addr->is_v6()) {
            output[pos++] = 0x04;
            auto bytes = addr.resolved_addr->to_v6().to_bytes();
            std::memcpy(output + pos, bytes.data(), bytes.size());
            pos += bytes.size();
        } else {
            return 0;
        }
    }

    output[pos++] = static_cast<uint8_t>(addr.port >> 8);
    output[pos++] = static_cast<uint8_t>(addr.port & 0xFF);
    return pos;
}

[[nodiscard]] bool AppendSpanToMultiBuffer(std::span<const uint8_t> data,
                                           buf::MultiBuffer& out) {
    size_t offset = 0;
    while (offset < data.size()) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            return false;
        }
        const size_t n = std::min(data.size() - offset,
                                  static_cast<size_t>(buffer->Available()));
        std::memcpy(buffer->Tail().data(), data.data() + offset, n);
        buffer->Produce(static_cast<uint32_t>(n));
        out.push_back(buffer.release());
        offset += n;
    }
    return true;
}

}  // namespace

// ============================================================================
// DecodeUdpPacket
// ============================================================================
std::optional<SsUdpDecodeResult> DecodeUdpPacket(
    const uint8_t*               datagram,
    size_t                       datagram_len,
    std::span<const SsUserInfo>  users,
    SsCipherType                 cipher_type,
    size_t                       key_size,
    size_t                       salt_size)
{
    if (key_size > 64 || salt_size > 64) {
        return std::nullopt;
    }

    // 最小长度: salt + 至少 1 字节 ATYP + 最小地址 + 2 字节端口 + 16 字节 tag
    // IPv4 最小: salt(N) + 1+4+2 + 16 = salt + 23
    if (datagram_len < salt_size + SsAeadCipher::kTagSize + 7) {
        return std::nullopt;
    }

    const uint8_t* salt    = datagram;
    const uint8_t* cipher  = datagram + salt_size;
    const size_t   cipherlen = datagram_len - salt_size;
    const size_t   plaintext_len = cipherlen - SsAeadCipher::kTagSize;
    memory::ByteVector plaintext(plaintext_len);

    for (size_t i = 0; i < users.size(); ++i) {
        const auto& user = users[i];

        // 派生子密钥
        std::array<uint8_t, 64> subkey{};
        if (!DeriveSubkey(user.derived_key.data(), key_size,
                          salt, salt_size,
                          subkey.data())) {
            continue;
        }

        // 整包 AEAD 解密（nonce = 全零）
        SsAeadCipher aead(cipher_type, subkey.data(), key_size);

        if (!aead.Decrypt(kZeroNonce.data(), cipher, cipherlen, plaintext.data())) {
            continue;  // 密钥不匹配，尝试下一个用户
        }

        // 解析 SOCKS5 地址
        auto addr = ParseSocks5Address(plaintext.data(), plaintext_len);
        if (!addr) {
            continue;  // 地址格式错误，尝试下一个（理论上不应发生于匹配用户）
        }

        SsUdpDecodeResult result;
        result.target     = std::move(addr->target);
        result.user_index = i;

        const size_t payload_offset = std::min(addr->consumed, plaintext_len);
        const size_t payload_size = plaintext_len - payload_offset;
        if (!AppendSpanToMultiBuffer(
                std::span<const uint8_t>(
                    plaintext.data() + payload_offset,
                    payload_size),
                result.payload)) {
            return std::nullopt;
        }

        return result;
    }

    return std::nullopt;
}

// ============================================================================
// EncodeUdpPacket
// ============================================================================
size_t EncodeUdpPacketTo(
    const TargetAddress&      target,
    const uint8_t*            payload,
    size_t                    payload_len,
    std::span<const uint8_t>  master_key,
    SsCipherType              cipher_type,
    size_t                    key_size,
    size_t                    salt_size,
    uint8_t*                  output,
    size_t                    output_size)
{
    if (key_size > 64 || salt_size > 64) {
        return 0;
    }
    if (master_key.size() < key_size) {
        return 0;
    }

    const size_t addr_size = Socks5AddressEncodedSize(target);
    if (addr_size == 0) {
        return 0;
    }
    const size_t plaintext_len = addr_size + payload_len;
    const size_t total_size = salt_size + plaintext_len + SsAeadCipher::kTagSize;
    if (output == nullptr || total_size > output_size) {
        return total_size;
    }

    uint8_t* salt = output;
    uint8_t* ciphertext = output + salt_size;

    if (RAND_bytes(salt, static_cast<int>(salt_size)) != 1) {
        return 0;
    }

    std::array<uint8_t, 64> subkey{};
    if (!DeriveSubkey(master_key.data(), key_size,
                      salt, salt_size,
                      subkey.data())) {
        return 0;
    }

    const size_t encoded = EncodeSocks5AddressTo(target, ciphertext, plaintext_len);
    if (encoded != addr_size) {
        return 0;
    }
    if (payload_len > 0) {
        std::memcpy(ciphertext + addr_size, payload, payload_len);
    }

    SsAeadCipher aead(cipher_type, subkey.data(), key_size);
    if (!aead.Encrypt(kZeroNonce.data(),
                      ciphertext, plaintext_len,
                      ciphertext)) {
        return 0;
    }

    return total_size;
}

}  // namespace acpp::ss
