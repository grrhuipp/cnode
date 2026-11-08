#pragma once

// ============================================================================
// trojan_codec.hpp - Trojan 协议编解码
//
// 职责：协议常量、请求结构体、握手结果、编解码逻辑（TCP + UDP）
// ============================================================================

#include "credentials.hpp"
#include "common.hpp"
#include "common/target_address.hpp"
#include "common/address_codec.hpp"

#include <array>
#include <optional>
#include <span>
#include <string_view>

namespace trojan {

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
    PasswordHash         password_hash{};  // SHA224 密码哈希（十六进制，56字节）
    TrojanCommand        command = TrojanCommand::CONNECT;
    TargetAddress        target;
    std::optional<ForwardedMetadata> forwarded;

    [[nodiscard]] std::string_view PasswordHashView() const noexcept {
        return {password_hash.data(), password_hash.size()};
    }
};

inline constexpr size_t kPasswordHashSize = std::tuple_size_v<PasswordHash>;
// hash + CRLF + command; the SOCKS5 address and a final CRLF follow.
inline constexpr size_t kRequestPrefixSize = kPasswordHashSize + 3;

enum class RequestDecodeStatus : uint8_t { Complete, Incomplete, InvalidHeader, InvalidAddress };

struct RequestDecodeResult {
    RequestDecodeStatus status = RequestDecodeStatus::Incomplete;
    TrojanRequest request;
    size_t consumed = 0;
    // Incomplete only: minimum total request bytes for the next stage; never
    // beyond the end of a valid request header.
    size_t required = 0;
};

// Single-pass incremental decode of the buffered request prefix: each call
// reports the next required length until the header is complete.
[[nodiscard]] RequestDecodeResult DecodeRequest(std::span<const uint8_t> data);

// 返回写入字节数，0 表示目标非法或缓冲区不足。
[[nodiscard]] size_t EncodeRequestTo(
    std::span<const char, 56> password_hash,
    TrojanCommand cmd,
    const TargetAddress& target,
    uint8_t* output,
    size_t output_size,
    const uint8_t* payload = nullptr,
    size_t payload_len = 0,
    ForwardedMetadataView forwarded = {});

// 返回写入字节数，0 表示目标非法、负载超过 uint16 或缓冲区不足。
[[nodiscard]] size_t EncodeUdpPacketHeaderTo(
    const TargetAddress& target,
    size_t payload_len,
    uint8_t* output,
    size_t output_size);

}  // namespace trojan
