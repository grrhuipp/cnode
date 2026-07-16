#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "shadowsocks_protocol.hpp"
#include "validator.hpp"
#include "acppnode/common/target_address.hpp"

#include <array>
#include <memory>
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

struct Ss2022UdpSessionState {
    SsCipherInfo cipher_info{};
    KeyBytes key;
    std::array<uint8_t, 8> client_session_id{};
    std::array<uint8_t, 8> server_session_id{};
    uint64_t next_packet_id = 0;
};

// SS UDP 解码结果
struct SsUdpDecodeResult {
    TargetAddress        target;       // 解析出的 SOCKS5 目标地址
    buf::MultiBuffer     payload;      // 解密后的 payload Buffer 所有权
    memory::ThreadLocalString session_key;
    size_t               user_index = 0;   // 匹配用户在 users 列表中的下标
    // reply_* 由 UDP 接收侧直接拿来编码回包，不再经过额外回调包装
    int64_t              user_id = 0;
    memory::ThreadLocalString user_email;
    uint64_t             speed_limit = 0;
    KeyBytes             reply_key;
    SsCipherInfo         cipher_info{};
    std::shared_ptr<Ss2022UdpSessionState> ss2022_session;
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
    const proxyman::inbound::UserStore::ShadowsocksUsersView& users,
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

[[nodiscard]] std::optional<SsUdpDecodeResult> DecodeUdpPacketWithKey(
    const uint8_t* datagram,
    size_t datagram_len,
    std::span<const uint8_t> master_key,
    SsCipherType cipher_type,
    size_t key_size,
    size_t salt_size);

[[nodiscard]] bool Init2022UdpSessionState(
    Ss2022UdpSessionState& state,
    const SsCipherInfo& cipher_info,
    const KeyBytes& key);

[[nodiscard]] size_t Encode2022UdpRequestPacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    Ss2022UdpSessionState& state,
    std::span<const KeyBytes> psk_chain,
    uint8_t* output,
    size_t output_size);

[[nodiscard]] size_t Encode2022UdpResponsePacketTo(
    const TargetAddress& target,
    const uint8_t* payload,
    size_t payload_len,
    Ss2022UdpSessionState& state,
    uint8_t* output,
    size_t output_size);

[[nodiscard]] std::optional<SsUdpDecodeResult> Decode2022UdpResponsePacket(
    const uint8_t* datagram,
    size_t datagram_len,
    Ss2022UdpSessionState& state);

}  // namespace acpp::ss
