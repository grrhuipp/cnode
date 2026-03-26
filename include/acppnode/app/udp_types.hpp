#pragma once

#include "acppnode/common.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/app/stats.hpp"

#include <memory>
#include <chrono>
#include <functional>
#include <optional>

namespace acpp {

// ============================================================================
// UDP 数据包
// ============================================================================
struct UDPPacket {
    TargetAddress target;           // 目标/源地址
    memory::ByteVector data;        // 原始数据（不含地址头）
};

// ============================================================================
// UDP Relay 结果
// ============================================================================
struct UDPRelayResult {
    uint64_t bytes_up = 0;
    uint64_t bytes_down = 0;
    ErrorCode error = ErrorCode::OK;
    bool client_closed_first = false;
};

// ============================================================================
// UDP 接收回调类型
// ============================================================================
using UDPReceiveCallback = std::function<void(
    const net::ip::address& from_addr,
    uint16_t from_port,
    const uint8_t* data,
    size_t len)>;

// ============================================================================
// UDP Relay 配置
// ============================================================================
struct UDPRelayConfig {
    size_t max_packet_size = 65535;          // 最大包大小
    uint64_t speed_limit = 0;               // 限速 (bytes/s), 0 = 不限速
};

}  // namespace acpp
