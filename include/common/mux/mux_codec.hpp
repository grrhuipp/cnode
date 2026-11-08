#pragma once

#include "common/target_address.hpp"
#include "common/address_codec.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
namespace buf {
class MultiBuffer;
}

namespace mux {

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
//     [AddrType: 1]          ← IPv4=0x01, Domain=0x02, IPv6=0x03
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
inline constexpr size_t kMaxFrameHeaderBytes = 2 + 4 + 1 + kMaxEncodedAddressSize + 8 + 2;
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

    std::optional<ForwardedMetadata> forwarded;
    // New UDP 帧是否携带 8 字节 GlobalID（XUDP），其取值不参与本端语义
    bool          has_global_id = false;

    // 载荷
    bool     has_data  = false;
    uint16_t data_len  = 0;
    size_t   data_offset = 0;

    // 整帧字节数（= 2 + MetaLen + [2 + data_len]），用于推进 frame_buf
    // frame_size == 0 表示帧格式非法
    size_t   frame_size = 0;
};

// ============================================================================
// DecodeFrame
//
// 解析 MultiBuffer 首部的完整帧，不消费输入。
// 返回 nullopt 表示数据不足；frame_size == 0 表示非法帧，不能跳字节重同步。
// 成功时 data_offset 表示载荷相对帧首的偏移。
// ============================================================================

[[nodiscard]] std::optional<FrameHeader> DecodeFrame(const buf::MultiBuffer& data);

// ============================================================================
// 序列化：服务器 → 客户端
// ============================================================================

[[nodiscard]] size_t EncodeKeepAliveTo(std::span<uint8_t> out) noexcept;

// OptionData is independent of payload length: true + zero encodes an empty
// datagram, while false + zero opens the session without sending data.
[[nodiscard]] size_t EncodeNewHeaderTo(std::span<uint8_t> out,
                                       uint16_t session_id,
                                       NetworkType network,
                                       const TargetAddress& target,
                                       size_t payload_len,
                                       bool has_data,
                                       ForwardedMetadataView forwarded = {}) noexcept;

[[nodiscard]] size_t EncodeEndTo(std::span<uint8_t> out,
                                 uint16_t session_id,
                                 bool error = false) noexcept;

[[nodiscard]] size_t EncodeKeepDataHeaderTo(std::span<uint8_t> out,
                                            uint16_t session_id,
                                            size_t payload_len) noexcept;

[[nodiscard]] size_t EncodeKeepUDPHeaderTo(std::span<uint8_t> out,
                                           uint16_t session_id,
                                           const TargetAddress& src,
                                           size_t payload_len) noexcept;
}  // namespace mux
