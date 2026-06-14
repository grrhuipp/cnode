#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/defaults.hpp"
#include "acppnode/transport/internet/stream_settings.hpp"

#include <chrono>
#include <optional>
#include <string_view>
#include <vector>

namespace acpp {

// ============================================================================
// OutboundDialCandidate - 单个候选拨号地址
// ============================================================================
struct OutboundDialCandidate {
    tcp::endpoint endpoint;
    std::optional<net::ip::address> bind_local;  // 可按候选 IP 单独决定绑定地址
};

// ============================================================================
// OutboundTransportTarget - 出站传输目标（仅携带已解析拨号候选）
//
// 这是 transport/internet 的拨号输入，不属于 proxy 出站协议壳。
// ============================================================================
struct OutboundTransportTarget {
    enum class BindMode : uint8_t {
        None = 0,
        Auto,
        Explicit,
    };

    std::optional<OutboundDialCandidate> single_candidate; // 单个已解析候选，避免每连接 vector 分配
    std::vector<OutboundDialCandidate> candidates; // 已解析候选地址（按优先级排序）
    BindMode bind_mode = BindMode::None;
    std::string_view server_name;                   // TLS SNI / WS Host（冷路径配置视图，可空）
    const StreamSettings* stream_settings = nullptr; // 必填：冷路径准备好的传输层组合配置
    std::chrono::seconds timeout{defaults::kDialTimeout};
};

}  // namespace acpp
