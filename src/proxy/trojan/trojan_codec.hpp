#pragma once

// ============================================================================
// trojan_codec.hpp - Trojan 协议编解码
//
// 职责：协议常量、请求结构体、握手结果、编解码逻辑（TCP + UDP）
// ============================================================================

#include "acppnode/common.hpp"
#include "acppnode/common/target_address.hpp"

#include <array>
#include <optional>
#include <span>
#include <string_view>

namespace acpp::trojan {

// ============================================================================
// Trojan 命令类型
// ============================================================================
enum class TrojanCommand : uint8_t {
    CONNECT = 0x01,
    UDP_ASSOCIATE = 0x03,
};

// ============================================================================
// Trojan 请求
// ============================================================================
struct TrojanRequest {
    std::array<char, 56> password_hash{};  // SHA224 密码哈希（十六进制，56字节）
    TrojanCommand        command = TrojanCommand::CONNECT;
    TargetAddress        target;

    [[nodiscard]] std::string_view PasswordHashView() const noexcept {
        return {password_hash.data(), password_hash.size()};
    }
};
// ============================================================================
// Trojan 协议编解码
// ============================================================================
class TrojanCodec {
public:
    // 解析请求
    // 返回解析结果，如果数据不足返回 nullopt
    static std::optional<TrojanRequest> ParseRequest(
        const uint8_t* data,
        size_t len,
        size_t& consumed);

    // in-place 编码请求，避免热路径分配
    static size_t EncodeRequestTo(
        std::span<const char, 56> password_hash,
        TrojanCommand cmd,
        const TargetAddress& target,
        uint8_t* output,
        size_t output_size,
        const uint8_t* payload = nullptr,
        size_t payload_len = 0);

    // UDP 包格式
    struct UdpPacket {
        TargetAddress target;
        std::span<const uint8_t> payload;
    };

    // UDP 解析结果类型
    enum class UdpParseResult {
        SUCCESS,      // 解析成功
        INCOMPLETE,   // 数据不完整，需要更多数据
        INVALID       // 格式错误（atype 非法、CRLF 不匹配等）
    };

    // UDP 解析输出
    struct UdpParseOutput {
        UdpParseResult result = UdpParseResult::INCOMPLETE;
        std::optional<UdpPacket> packet;
        size_t consumed = 0;
    };

    // 解析单个 UDP 包。SUCCESS 时 consumed 表示完整 frame 长度；
    // INCOMPLETE 时保留输入等待更多字节；INVALID 时调用方可丢弃/同步。
    static UdpParseOutput ParseUdpPacket(
        const uint8_t* data,
        size_t len);

    // 编码 UDP 包头部（in-place 版本，避免内存分配）
    // 返回实际写入字节数，0 表示失败（缓冲区太小）
    static size_t EncodeUdpPacketHeaderTo(
        const TargetAddress& target,
        size_t payload_len,
        uint8_t* output,
        size_t output_size);
};
}  // namespace acpp::trojan
