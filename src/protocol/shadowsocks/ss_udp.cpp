#include "acppnode/protocol/shadowsocks/ss_udp.hpp"

#include <openssl/rand.h>
#include <cstring>
#include <array>

namespace acpp::ss {

// ============================================================================
// 内部辅助：全零 nonce（SS UDP 每包用新 salt，nonce 固定为 0）
// ============================================================================
static std::array<uint8_t, 12> kZeroNonce{};

namespace {

size_t Socks5AddressEncodedSize(const TargetAddress& addr) {
    if (addr.IsDomain()) {
        if (addr.host.size() > 255) {
            return 0;
        }
        return 1 + 1 + addr.host.size() + 2;
    }

    boost::system::error_code ec;
    auto ip = net::ip::make_address(addr.host, ec);
    if (!ec && ip.is_v4()) {
        return 1 + 4 + 2;
    }
    if (!ec && ip.is_v6()) {
        return 1 + 16 + 2;
    }

    if (addr.host.size() > 255) {
        return 0;
    }
    return 1 + 1 + addr.host.size() + 2;
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
        boost::system::error_code ec;
        auto ip = net::ip::make_address(addr.host, ec);
        if (!ec && ip.is_v4()) {
            output[pos++] = 0x01;
            auto bytes = ip.to_v4().to_bytes();
            std::memcpy(output + pos, bytes.data(), bytes.size());
            pos += bytes.size();
        } else if (!ec && ip.is_v6()) {
            output[pos++] = 0x04;
            auto bytes = ip.to_v6().to_bytes();
            std::memcpy(output + pos, bytes.data(), bytes.size());
            pos += bytes.size();
        } else {
            if (addr.host.size() > 255) return 0;
            output[pos++] = 0x03;
            output[pos++] = static_cast<uint8_t>(addr.host.size());
            std::memcpy(output + pos, addr.host.data(), addr.host.size());
            pos += addr.host.size();
        }
    }

    output[pos++] = static_cast<uint8_t>(addr.port >> 8);
    output[pos++] = static_cast<uint8_t>(addr.port & 0xFF);
    return pos;
}

}  // namespace

// ============================================================================
// DecodeUdpPacket
// ============================================================================
std::optional<SsUdpDecodeResult> DecodeUdpPacket(
    const uint8_t*               datagram,
    size_t                       datagram_len,
    const std::vector<SsUserInfo>& users,
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
        const size_t plaintext_len = cipherlen - SsAeadCipher::kTagSize;
        std::vector<uint8_t> plaintext(plaintext_len);

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

        // 载荷 = 地址头之后的数据
        if (addr->consumed < plaintext_len) {
            const size_t payload_len = plaintext_len - addr->consumed;
            std::memmove(plaintext.data(),
                         plaintext.data() + addr->consumed,
                         payload_len);
            plaintext.resize(payload_len);
        } else {
            plaintext.clear();
        }
        result.payload = std::move(plaintext);

        return result;
    }

    return std::nullopt;
}

// ============================================================================
// EncodeUdpPacket
// ============================================================================
size_t EncodeUdpPacketTo(
    const TargetAddress&         target,
    const uint8_t*               payload,
    size_t                       payload_len,
    const std::vector<uint8_t>&  master_key,
    SsCipherType                 cipher_type,
    size_t                       key_size,
    size_t                       salt_size,
    uint8_t*                     output,
    size_t                       output_size)
{
    if (key_size > 64 || salt_size > 64) {
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

std::vector<uint8_t> EncodeUdpPacket(
    const TargetAddress&         target,
    const uint8_t*               payload,
    size_t                       payload_len,
    const std::vector<uint8_t>&  master_key,
    SsCipherType                 cipher_type,
    size_t                       key_size,
    size_t                       salt_size)
{
    const size_t addr_size = Socks5AddressEncodedSize(target);
    if (addr_size == 0) {
        return {};
    }
    const size_t total_size = salt_size + addr_size + payload_len + SsAeadCipher::kTagSize;
    std::vector<uint8_t> result;
    result.resize(total_size);

    const size_t written = EncodeUdpPacketTo(
        target, payload, payload_len,
        master_key, cipher_type, key_size, salt_size,
        result.data(), result.size());
    if (written != total_size) {
        return {};
    }

    return result;
}

}  // namespace acpp::ss
