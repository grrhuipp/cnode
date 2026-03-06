#pragma once

#include <cstdint>
#include <cstring>
#include <string>

namespace acpp {

enum class ProxyProtocolParseStatus : uint8_t {
    NotProxy = 0,
    Incomplete,
    Success,
    Invalid,
};

// ============================================================================
// PROXY Protocol 解析结果
// ============================================================================
struct ProxyProtocolResult {
    ProxyProtocolParseStatus status = ProxyProtocolParseStatus::NotProxy;
    std::string src_ip;
    uint16_t src_port = 0;
    size_t consumed = 0;  // 消耗的字节数

    [[nodiscard]] bool success() const noexcept {
        return status == ProxyProtocolParseStatus::Success;
    }

    [[nodiscard]] bool incomplete() const noexcept {
        return status == ProxyProtocolParseStatus::Incomplete;
    }
};

// ============================================================================
// PROXY Protocol 解析器（静态工具类）
//
// 支持自动检测 v1（文本）和 v2（二进制），非 PROXY 报文返回 success=false。
// ============================================================================
class ProxyProtocolParser {
public:
    // PROXY Protocol v2 签名 (12 字节)
    static constexpr uint8_t kSignatureV2[12] = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };

    // 解析 PROXY Protocol（自动检测 v1/v2）
    [[nodiscard]] static ProxyProtocolResult Parse(const uint8_t* data, size_t len);

    // 解析 v1（文本格式）
    [[nodiscard]] static ProxyProtocolResult ParseV1(const uint8_t* data, size_t len);

    // 解析 v2（二进制格式）
    [[nodiscard]] static ProxyProtocolResult ParseV2(const uint8_t* data, size_t len);
};

}  // namespace acpp
