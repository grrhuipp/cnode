#pragma once

#include "acppnode/common.hpp"
#include "acppnode/app/session_context.hpp"
#include "acppnode/app/udp_types.hpp"
#include "acppnode/app/udp_framer.hpp"
#include "acppnode/transport/async_stream.hpp"
#include "acppnode/app/stats.hpp"

namespace acpp {

// 前向声明
struct UDPDialResult;

// ============================================================================
// Relay 配置
//
// Buffer 管理已移至 MultiBuffer（multi_buffer.hpp）：
//   - 固定 8KB pool Buffer，mimalloc 管理，无需手工配置大小
//   - 不再需要 buffer_size / tiered_pool / upload_hint / download_hint
// ============================================================================
struct RelayConfig {
    std::chrono::seconds uplink_only{defaults::kUplinkOnlyTimeout};     // 下行 EOF 后上行最多保留多久
    std::chrono::seconds downlink_only{defaults::kDownlinkOnlyTimeout}; // 上行 EOF 后下行最多保留多久
    uint64_t speed_limit = 0;              // bytes/s，0 = 不限速
};

// ============================================================================
// Relay 结果
// ============================================================================
struct RelayResult : ResultStatus {
    uint64_t bytes_up = 0;
    uint64_t bytes_down = 0;
    bool client_closed_first = false;
};

// ============================================================================
// 双协程 Relay
// ============================================================================
cobalt::task<RelayResult> DoRelay(
    AsyncStream& client,
    AsyncStream& target,
    SessionContext& ctx,
    StatsShard& stats,
    const RelayConfig& config = RelayConfig{});

// ============================================================================
// 带首包回放的 Relay
// ============================================================================
cobalt::task<RelayResult> DoRelayWithFirstPacket(
    AsyncStream& client,
    AsyncStream& target,
    SessionContext& ctx,
    StatsShard& stats,
    std::vector<uint8_t> first_packet,
    const RelayConfig& config = RelayConfig{});

// ============================================================================
// UDP Relay（Full Cone NAT）
//
// framer: UDP 帧编解码器（由上层按协议创建后传入，relay 层不感知协议细节）
//   - TrojanUdpFramer：Trojan UDP 格式（含地址头，支持粘包）
//   - PayloadOnlyUdpFramer：原始载荷直通（VMess Command::UDP / 通用协议）
// ============================================================================
cobalt::task<RelayResult> DoUDPRelay(
    AsyncStream& client_stream,
    UDPDialResult& udp_dial,
    UdpFramer& framer,
    SessionContext& ctx,
    StatsShard& stats,
    const UDPRelayConfig& config = UDPRelayConfig{});

}  // namespace acpp
