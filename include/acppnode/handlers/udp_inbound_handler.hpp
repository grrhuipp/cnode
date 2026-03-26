#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/target_address.hpp"

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

namespace acpp {

using UdpReplyEncoder = std::function<size_t(const TargetAddress&,
                                             const uint8_t*,
                                             size_t,
                                             uint8_t*,
                                             size_t)>;

// ============================================================================
// UdpInboundDecodeResult — UDP 入站解码结果
//
// 协议层解码完数据报后填充此结构，返回给 Worker 的通用 UDP 接收循环。
// Worker 不需要了解任何协议细节，只需：
//   1. 根据 target 做路由 + 拨号
//   2. 用 encode_reply 对出站回包重新加密
// ============================================================================
struct UdpInboundDecodeResult {
    TargetAddress        target;        // SOCKS5 目标地址（已解析）
    memory::ByteVector   payload;       // 解密后的原始载荷
    int64_t              user_id     = 0;
    std::string          user_email;
    uint64_t             speed_limit = 0;

    // 回包编码函数（在 Decode 时值捕获用户密钥等协议上下文，生命周期安全）
    // 语义：
    //   - 成功且缓冲足够：写入 output，返回实际长度
    //   - output 为空或缓冲不足：不写入，返回所需总长度
    //   - 编码失败：返回 0
    UdpReplyEncoder encode_reply;
};

}  // namespace acpp
