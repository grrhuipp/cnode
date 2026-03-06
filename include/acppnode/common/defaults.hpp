#pragma once

#include <cstdint>
#include <cstddef>

namespace acpp {
namespace defaults {

// 资源限制
constexpr uint32_t kMaxConnections = 0;            // 最大并发连接数（0=不限制）
constexpr uint32_t kMaxConnectionsPerIP = 0;       // 单 IP 最大连接数（0=不限制）
constexpr size_t kBufferSize = 24 * 1024;      // 24KB
constexpr size_t kMaxHeaderSize = 4 * 1024;    // 4KB

// 超时配置（秒）—— 对齐 Xray policy.SessionDefault()
constexpr uint32_t kHandshakeTimeout = 60;    // 握手阶段超时（对齐 Nginx client_header_timeout，防时序指纹）
constexpr uint32_t kDialTimeout = 10;         // 拨号超时
constexpr uint32_t kReadTimeout = 15;         // 连接读方向 deadline
constexpr uint32_t kWriteTimeout = 30;        // 连接写方向 deadline
constexpr uint32_t kIdleTimeout = 300;        // 连接空闲超时（connIdle）
constexpr uint32_t kUplinkOnlyTimeout = 1;    // 下行 EOF 后等待上行的空闲超时
constexpr uint32_t kDownlinkOnlyTimeout = 1;  // 上行 EOF 后等待下行的空闲超时

// 连接压力控制
constexpr uint32_t kMaxConnectionsPerWorker = 10000;  // 每 Worker 连接安全上限
constexpr uint32_t kPressurePercent = 75;              // 负载压力阈值百分比
constexpr uint32_t kPressureIdleTimeout = 60;          // 高压时空闲超时（秒）

// DNS 配置
constexpr uint32_t kDnsTimeout = 5;
constexpr uint32_t kDnsCacheSize = 10000;
constexpr uint32_t kDnsMinTTL = 60;
constexpr uint32_t kDnsMaxTTL = 3600;

// 面板配置
constexpr uint32_t kPanelPullInterval = 60;
constexpr uint32_t kPanelPushInterval = 60;
constexpr uint32_t kPanelConfigRefreshInterval = 300;

// 统计输出间隔
constexpr uint32_t kStatsOutputInterval = 10;

}  // namespace defaults
}  // namespace acpp
