#pragma once

// ============================================================================
// vmess_protocol.hpp — VMess 协议伞形头（umbrella header）
//
// 包含 VMess 协议所有子模块，方便一次性引入全部类型。
// 各子模块职责：
//   vmess_crypto.hpp       — 密码学原语（KDF、AES、哈希、随机数）
//   vmess_request.hpp      — 协议常量、枚举、VMessRequest 结构体
//   vmess_cipher.hpp       — AEAD 加密器（VMessCipher、ShakeMask、VMessServerStream）
//   vmess_user_manager.hpp — 用户存储与在线追踪（VMessUser、VMessUserManager）
//   vmess_parser.hpp       — 请求解析（VMessParser）
// ============================================================================

#include "acppnode/protocol/vmess/vmess_crypto.hpp"
#include "acppnode/protocol/vmess/vmess_request.hpp"
#include "acppnode/protocol/vmess/vmess_cipher.hpp"
#include "acppnode/protocol/vmess/vmess_user_manager.hpp"
#include "acppnode/protocol/vmess/vmess_parser.hpp"

#include "acppnode/common/protocol_data.hpp"

namespace acpp {

// ============================================================================
// VMessProtocolData — VMess 协议特定数据（存储在 SessionContext::protocol_data）
//
// ParseStream 写入，WrapStream 读取。
// 通过 IProtocolData 虚基类实现类型安全，避免 std::any + bad_any_cast。
//
// 使用方：
//   写入：ctx.protocol_data = std::make_unique<VMessProtocolData>(...);
//   读取：static_cast<VMessProtocolData*>(ctx.protocol_data.get())
// ============================================================================
struct VMessProtocolData : IProtocolData {
    vmess::VMessRequest request;  // WrapStream 需要此数据（move 后失效）
};

}  // namespace acpp
