#pragma once

#include <cstdint>

namespace acpp {

// ============================================================================
// 连接状态
// ============================================================================
enum class ConnState : uint8_t {
    ACCEPTED = 0,      // 已接受连接
    HANDSHAKING,       // 协议握手中
    SNIFFING,          // 流量嗅探中
    ROUTING,           // 路由决策中
    DIALING,           // 出站拨号中
    RELAYING,          // 数据转发中
    CLOSING,           // 关闭中
    CLOSED             // 已关闭
};

constexpr const char* ConnStateToString(ConnState s) {
    switch (s) {
        case ConnState::ACCEPTED:    return "ACCEPTED";
        case ConnState::HANDSHAKING: return "HANDSHAKING";
        case ConnState::SNIFFING:    return "SNIFFING";
        case ConnState::ROUTING:     return "ROUTING";
        case ConnState::DIALING:     return "DIALING";
        case ConnState::RELAYING:    return "RELAYING";
        case ConnState::CLOSING:     return "CLOSING";
        case ConnState::CLOSED:      return "CLOSED";
        default: return "UNKNOWN";
    }
}

}  // namespace acpp
