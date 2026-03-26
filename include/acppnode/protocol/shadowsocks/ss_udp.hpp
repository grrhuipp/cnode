#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/protocol/shadowsocks/shadowsocks_protocol.hpp"
#include "acppnode/common/target_address.hpp"

#include <optional>
#include <span>
#include <vector>

namespace acpp::ss {

// ============================================================================
// SS AEAD UDP 数据报格式（Xray/shadowsocks-go 兼容）
//
// 客户端 → 服务端:
//   [salt(salt_size)] + AEAD_encrypt(nonce=0, [SOCKS5_addr][payload]) + tag(16)
//
// 服务端 → 客户端:
//   [new_random_salt(salt_size)] + AEAD_encrypt(nonce=0, [SOCKS5_addr][payload]) + tag(16)
//
// 与 TCP 的区别:
//   - 每个数据报独立加密（不共享 nonce 计数器）
//   - nonce 固定为全零（salt 已提供唯一性）
//   - 无 chunk 分帧（整包一次性 AEAD）
// ============================================================================

// SS UDP 解码结果
struct SsUdpDecodeResult {
    TargetAddress        target;       // 解析出的 SOCKS5 目标地址
    memory::ByteVector   payload;      // 解密后的原始载荷
    size_t               user_index;   // 匹配用户在 users 列表中的下标
};

// ============================================================================
// DecodeUdpPacket — 解码 SS AEAD UDP 数据报
//
// 遍历 users，用每个用户的 key 派生子密钥并尝试 AEAD 解密。
// 第一个 AEAD Tag 验证通过的用户即为匹配用户。
//
// 最小包长: salt_size + 1(ATYP) + 1(域名长度或4字节IP) + 2(port) + kTagSize
// 返回 nullopt: 包过短 / 所有用户均不匹配
// ============================================================================
[[nodiscard]] std::optional<SsUdpDecodeResult> DecodeUdpPacket(
    const uint8_t*               datagram,
    size_t                       datagram_len,
    const std::vector<const SsUserInfo*>& users,
    SsCipherType                 cipher_type,
    size_t                       key_size,
    size_t                       salt_size);

// ============================================================================
// EncodeUdpPacket — 编码 SS AEAD UDP 回包
//
// 生成随机 salt，HKDF 派生子密钥，整包 AEAD 加密。
// 返回:
//   - 缓冲足够：写入 [salt] + [AEAD(SOCKS5_addr + payload)] + [tag]，返回实际长度
//   - output 为空或缓冲不足：不写入，返回所需总长度
//   - 编码失败：返回 0
// ============================================================================
[[nodiscard]] size_t EncodeUdpPacketTo(
    const TargetAddress&        target,
    const uint8_t*              payload,
    size_t                      payload_len,
    std::span<const uint8_t>    master_key,
    SsCipherType                cipher_type,
    size_t                      key_size,
    size_t                      salt_size,
    uint8_t*                    output,
    size_t                      output_size);

[[nodiscard]] memory::ByteVector EncodeUdpPacket(
    const TargetAddress&        target,
    const uint8_t*              payload,
    size_t                      payload_len,
    std::span<const uint8_t>    master_key,
    SsCipherType                cipher_type,
    size_t                      key_size,
    size_t                      salt_size);

}  // namespace acpp::ss
