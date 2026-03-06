#pragma once

#include <string>
#include <cstdint>

namespace acpp {

// ============================================================================
// PortBinding - 端口绑定描述（Worker 独立监听时传递）
// ============================================================================
struct PortBinding {
    uint16_t    port     = 0;
    std::string protocol;           // "vmess" / "trojan"
    std::string tag;                // inbound tag
    std::string listen = "0.0.0.0"; // 监听地址
};

}  // namespace acpp
