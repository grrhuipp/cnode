#pragma once

// ============================================================================
// trojan_codec.hpp - Trojan 协议编解码
//
// 职责：协议常量、请求结构体、握手结果、编解码逻辑（TCP + UDP）
// ============================================================================

#include "acppnode/common.hpp"
#include "acppnode/common/target_address.hpp"

namespace acpp::trojan {

// ============================================================================
// 握手失败原因
// ============================================================================
enum class HandshakeFailReason {
    NONE,              // 无错误
    TIMEOUT,           // 超时
    CONNECTION_CLOSED, // 连接关闭
    INVALID_PROTOCOL,  // 协议格式错误
    AUTH_FAILED,       // 认证失败（密码错误）
    UNKNOWN_ERROR,     // 未知错误
};

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
    std::string password_hash;      // SHA224 密码哈希（十六进制，56字节）
    TrojanCommand command;          // 命令
    TargetAddress target;           // 目标地址
    std::vector<uint8_t> payload;   // 首包负载（可选）

    bool IsValid() const {
        return password_hash.size() == 56 &&
               (command == TrojanCommand::CONNECT || command == TrojanCommand::UDP_ASSOCIATE);
    }
};

// ============================================================================
// 握手结果
// ============================================================================
struct HandshakeResult {
    std::optional<TrojanRequest> request;
    HandshakeFailReason fail_reason = HandshakeFailReason::NONE;

    bool Ok() const { return request.has_value(); }
    bool IsAuthFailed() const { return fail_reason == HandshakeFailReason::AUTH_FAILED; }
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

    // 编码请求（用于客户端）
    static std::vector<uint8_t> EncodeRequest(
        const std::string& password,
        TrojanCommand cmd,
        const TargetAddress& target,
        const uint8_t* payload = nullptr,
        size_t payload_len = 0);

    // in-place 编码请求，避免热路径分配
    static size_t EncodeRequestTo(
        const std::string& password,
        TrojanCommand cmd,
        const TargetAddress& target,
        uint8_t* output,
        size_t output_size,
        const uint8_t* payload = nullptr,
        size_t payload_len = 0);

    // UDP 包格式
    struct UdpPacket {
        TargetAddress target;
        std::vector<uint8_t> payload;
    };

    // UDP 解析结果类型
    enum class UdpParseResult {
        SUCCESS,      // 解析成功
        INCOMPLETE,   // 数据不完整，需要更多数据
        INVALID       // 格式错误（atype 非法、CRLF 不匹配等）
    };

    // UDP 解析输出
    struct UdpParseOutput {
        UdpParseResult result;
        std::optional<UdpPacket> packet;
        size_t consumed = 0;
        std::string error_reason;  // 用于调试和日志
    };

    // 解析 UDP 包（旧版本，保持兼容性）
    static std::optional<UdpPacket> ParseUdpPacket(
        const uint8_t* data,
        size_t len,
        size_t& consumed);

    // 解析 UDP 包（增强版本，推荐使用）
    static UdpParseOutput ParseUdpPacketEx(
        const uint8_t* data,
        size_t len);

    // 编码 UDP 包
    static std::vector<uint8_t> EncodeUdpPacket(
        const TargetAddress& target,
        const uint8_t* payload,
        size_t payload_len);

    // 编码 UDP 包（in-place 版本，避免内存分配）
    // 返回实际写入字节数，0 表示失败（缓冲区太小）
    static size_t EncodeUdpPacketTo(
        const TargetAddress& target,
        const uint8_t* payload,
        size_t payload_len,
        uint8_t* output,
        size_t output_size);

private:
    static const uint8_t CRLF[2];
};

}  // namespace acpp::trojan
