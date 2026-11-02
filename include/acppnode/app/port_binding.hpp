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

    // Protocol/credentials are handler state and do not change the bound
    // socket. Listener reuse is safe when the tag and endpoint shape match.
    [[nodiscard]] bool UsesSameSocket(const PortBinding& other) const noexcept {
        return port == other.port && tag == other.tag && listen == other.listen;
    }
};


}  // namespace acpp
