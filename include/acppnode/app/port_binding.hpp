#pragma once

#include <cstdint>
#include <string>

#include "acppnode/transport/internet/inbound_listen.hpp"

namespace acpp {

// ============================================================================
// PortBinding - 端口绑定描述（Worker 独立监听时传递）
// ============================================================================
struct PortBinding {
    uint16_t    port     = 0;
    std::string protocol;           // "vmess" / "trojan"
    std::string tag;                // inbound tag
    InboundListen listen;
};

}  // namespace acpp
