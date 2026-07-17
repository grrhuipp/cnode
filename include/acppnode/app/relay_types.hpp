#pragma once

#include "acppnode/common/defaults.hpp"
#include "acppnode/common/error.hpp"

#include <chrono>
#include <cstdint>

namespace acpp {

// ============================================================================
// Relay 配置
//
// Buffer 管理已移至 buf::MultiBuffer（multi_buffer.hpp）：
//   - relay 数据面固定 8KB Buffer，交给 system allocator 管理
//   - 小对象和短生命周期 scratch 走 allocator 的合适尺寸桶，用完归还/收缩
//   - 不再需要协议私有 pool / buffer_size / upload_hint / download_hint
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
    bool close_side_known = false;
};

}  // namespace acpp
