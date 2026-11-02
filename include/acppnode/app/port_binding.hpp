#pragma once

#include <cstddef>
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

    // Protocol/credentials are handler state and do not change the bound
    // socket. Listener reuse is safe when the tag and endpoint shape match.
    [[nodiscard]] bool UsesSameSocket(const PortBinding& other) const noexcept {
        if (port != other.port || tag != other.tag) {
            return false;
        }
        const auto candidates = listen.Candidates();
        const auto other_candidates = other.listen.Candidates();
        if (candidates.size() != other_candidates.size()) {
            return false;
        }
        for (size_t i = 0; i < candidates.size(); ++i) {
            if (candidates[i] != other_candidates[i]) {
                return false;
            }
        }
        return true;
    }
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
