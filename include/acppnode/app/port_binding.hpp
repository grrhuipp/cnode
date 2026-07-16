#pragma once

#include <cstdint>
#include <string>
#include <utility>

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

[[nodiscard]] inline PortBinding MakePortBinding(
    uint16_t port,
    std::string protocol,
    std::string tag,
    InboundListen listen = {}) {
    PortBinding binding;
    binding.port     = port;
    binding.protocol = std::move(protocol);
    binding.tag      = std::move(tag);
    binding.listen   = std::move(listen);
    return binding;
}

}  // namespace acpp
