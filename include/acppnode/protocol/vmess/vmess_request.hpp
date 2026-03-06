#pragma once

// ============================================================================
// vmess_request.hpp — VMess 协议常量、枚举与请求结构体
//
// 职责：定义 VMess 协议帧格式所需的全部协议级类型。
// 不包含加密实现、用户管理或解析逻辑。
// ============================================================================

#include "acppnode/common.hpp"
#include "acppnode/common/target_address.hpp"
#include <array>
#include <vector>
#include <cstdint>

namespace acpp {
namespace vmess {

// ============================================================================
// 协议常量
// ============================================================================

constexpr uint8_t VERSION           = 1;
constexpr size_t  GCM_TAG_SIZE      = 16;
constexpr size_t  GCM_NONCE_SIZE    = 12;
constexpr size_t  MAX_CHUNK_SIZE    = 16 * 1024;  // 16KB
constexpr int64_t TIMESTAMP_TOLERANCE = 60;        // ±60秒，防重放攻击

// ============================================================================
// 枚举：加密算法
// ============================================================================

enum class Security : uint8_t {
    AUTO             = 0,
    AES_128_GCM      = 3,
    CHACHA20_POLY1305 = 4,
    NONE             = 5,
    ZERO             = 6
};

// ============================================================================
// 枚举：命令类型
// ============================================================================

enum class Command : uint8_t {
    TCP = 1,
    UDP = 2,
    Mux = 3,  // XUDP/Mux 模式，每个包有地址头
    MUX = 3   // 别名
};

// ============================================================================
// 枚举：地址类型
// ============================================================================

enum class AddressType : uint8_t {
    IPv4   = 1,
    Domain = 2,
    IPv6   = 3
};

// ============================================================================
// 选项标志（Option 字节的位掩码）
// ============================================================================

namespace Option {
    constexpr uint8_t CHUNK_STREAM        = 0x01;
    constexpr uint8_t CONNECTION_REUSE    = 0x02;
    constexpr uint8_t CHUNK_MASKING       = 0x04;
    constexpr uint8_t GLOBAL_PADDING      = 0x08;
    constexpr uint8_t AUTHENTICATED_LENGTH = 0x10;
}

// ============================================================================
// KDF Salt 常量（用于 AEAD 密钥派生路径）
// ============================================================================

namespace KDFSalt {
    constexpr const char* AUTH_ID_ENCRYPTION_KEY        = "AES Auth ID Encryption";
    // 响应头
    constexpr const char* AEAD_RESP_HEADER_LEN_KEY      = "AEAD Resp Header Len Key";
    constexpr const char* AEAD_RESP_HEADER_LEN_IV       = "AEAD Resp Header Len IV";
    constexpr const char* AEAD_RESP_HEADER_PAYLOAD_KEY  = "AEAD Resp Header Key";
    constexpr const char* AEAD_RESP_HEADER_PAYLOAD_IV   = "AEAD Resp Header IV";
    // 请求头（客户端使用）
    constexpr const char* VMESS_AEAD_KDF                        = "VMess AEAD KDF";
    constexpr const char* VMESS_HEADER_PAYLOAD_AEAD_KEY         = "VMess Header AEAD Key";
    constexpr const char* VMESS_HEADER_PAYLOAD_AEAD_IV          = "VMess Header AEAD Nonce";
    constexpr const char* VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY  = "VMess Header AEAD Key_Length";
    constexpr const char* VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV   = "VMess Header AEAD Nonce_Length";
}

// ============================================================================
// 握手失败原因
// ============================================================================

enum class VMessHandshakeFailReason {
    NONE,              // 无错误
    TIMEOUT,           // 超时
    CONNECTION_CLOSED, // 连接关闭
    IP_BLOCKED,        // IP 被屏蔽
    AUTH_FAILED,       // 认证失败
    UNKNOWN_ERROR,     // 未知错误
};

// ============================================================================
// VMess 请求头（ParseStream 解析后填充，WrapStream 读取）
// ============================================================================

// 前向声明（VMessUser 在 vmess_user_manager.hpp 中定义）
struct VMessUser;

struct VMessRequest {
    uint8_t version = VERSION;
    std::array<uint8_t, 16> body_iv;
    std::array<uint8_t, 16> body_key;
    uint8_t response_header = 0;
    uint8_t options         = 0;
    uint8_t padding_len     = 0;
    Security security       = Security::AES_128_GCM;
    Command  command        = Command::TCP;
    TargetAddress target;

    const VMessUser* user = nullptr;

    // 握手后的预读数据（加密的数据块）
    std::vector<uint8_t> pending_data;

    bool HasChunkMasking()       const { return (options & Option::CHUNK_MASKING)       != 0; }
    bool HasAuthenticatedLength() const { return (options & Option::AUTHENTICATED_LENGTH) != 0; }
    bool HasGlobalPadding()      const { return (options & Option::GLOBAL_PADDING)       != 0; }
};

}  // namespace vmess
}  // namespace acpp
