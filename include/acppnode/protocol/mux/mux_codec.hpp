#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/target_address.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace acpp::mux {

// ============================================================================
// Mux.Cool 帧格式常量
//
// 参考 Xray-core common/mux/frame.go
//
// 帧二进制布局：
//   [MetaLen: 2 BE]          ← 后续元数据字节数（不含自身 2 字节）
//   [SessionID: 2 BE]
//   [Status: 1]              ← New=0x01, Keep=0x02, End=0x03, KeepAlive=0x04
//   [Option: 1]              ← bit0=DATA(0x01), bit1=ERROR(0x02)
//   若 Status==New 或 (Status==Keep && 地址字段存在):
//     [NetworkType: 1]       ← TCP=0x01, UDP=0x02
//     [Port: 2 BE]
//     [AddrType: 1]          ← IPv4=0x01, Domain=0x02
//     [Address: variable]
//   若 Status==New && Network==UDP && (元数据剩余 == 8):
//     [GlobalID: 8]
//   若 Option & kOptionData:
//     [DataLen: 2 BE]
//     [Payload: DataLen bytes]
// ============================================================================

enum class SessionStatus : uint8_t {
    NEW        = 0x01,
    KEEP       = 0x02,
    END        = 0x03,
    KEEPALIVE  = 0x04,
};

enum class NetworkType : uint8_t {
    TCP = 0x01,
    UDP = 0x02,
};

constexpr uint8_t kOptionData  = 0x01;
constexpr uint8_t kOptionError = 0x02;

// ============================================================================
// FrameHeader - 解析结果
// ============================================================================
struct FrameHeader {
    uint16_t      session_id    = 0;
    SessionStatus status        = SessionStatus::KEEPALIVE;
    uint8_t       option        = 0;

    // 地址信息（New 帧和 Keep UDP 帧才有）
    NetworkType   network       = NetworkType::TCP;
    bool          has_target    = false;
    TargetAddress target;

    // GlobalID（New UDP 帧，全零 = 不启用跨连接复用）
    bool                    has_global_id = false;
    std::array<uint8_t, 8>  global_id{};

    // 载荷
    bool     has_data  = false;
    uint16_t data_len  = 0;

    // 整帧字节数（= 2 + MetaLen + [2 + data_len]），用于推进 frame_buf
    // frame_size == 0 表示帧格式非法
    size_t   frame_size = 0;
};

// ============================================================================
// DecodeFrame
//
// 从 data[0..len) 中解析一个完整的 Mux 帧头。
//   - 返回 nullopt：数据不足，等待更多字节
//   - 返回 FrameHeader，frame_size == 0：帧格式非法
//   - 成功时：Payload 位于 data + (frame_size - data_len)
// ============================================================================
[[nodiscard]] std::optional<FrameHeader> DecodeFrame(
    const uint8_t* data, size_t len);

// ============================================================================
// 序列化：服务器 → 客户端
// ============================================================================

void EncodeKeepAliveTo(memory::ByteVector& out);
void EncodeEndTo(memory::ByteVector& out,
                 uint16_t session_id, bool error = false);
void EncodeKeepDataTo(memory::ByteVector& out,
                      uint16_t session_id,
                      const uint8_t* data, size_t len);
void EncodeKeepUDPTo(memory::ByteVector& out,
                     uint16_t session_id,
                     const TargetAddress& src,
                     const uint8_t* data, size_t len);

[[nodiscard]] memory::ByteVector EncodeKeepAlive();

[[nodiscard]] memory::ByteVector EncodeEnd(
    uint16_t session_id, bool error = false);

[[nodiscard]] memory::ByteVector EncodeKeepData(
    uint16_t session_id,
    const uint8_t* data, size_t len);

[[nodiscard]] memory::ByteVector EncodeKeepUDP(
    uint16_t session_id,
    const TargetAddress& src,
    const uint8_t* data, size_t len);

// ============================================================================
// 地址类型转换
//
// 项目内部 AddressType: IPv4=1, Domain=3
// Mux 线上格式:         IPv4=1, Domain=2
// ============================================================================
[[nodiscard]] uint8_t     ToMuxAddrType(AddressType t) noexcept;
[[nodiscard]] AddressType FromMuxAddrType(uint8_t t) noexcept;

// ============================================================================
// GlobalID 辅助函数
// ============================================================================

// 将 8 字节 GlobalID 转为 uint64_t key（big-endian 解释）
[[nodiscard]] inline uint64_t GlobalIdToKey(
    const std::array<uint8_t, 8>& gid) noexcept
{
    uint64_t k = 0;
    for (int i = 0; i < 8; ++i)
        k = (k << 8) | gid[i];
    return k;
}

// 判断 GlobalID 是否全零（不启用跨连接路由）
[[nodiscard]] inline bool IsNullGlobalId(
    const std::array<uint8_t, 8>& gid) noexcept
{
    for (uint8_t b : gid)
        if (b != 0) return false;
    return true;
}

}  // namespace acpp::mux
