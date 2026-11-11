#pragma once

#include "core/constants.hpp"

#include <cstdint>
#include <string_view>

namespace routing {

// 可嗅探协议名到位的唯一映射：嗅探 destOverride 与路由规则的 protocol 条件共用
// 同一张表，配置边界一次换算成位集，热路径只做位运算。
inline constexpr uint8_t kSniffedTls = 1u << 0;
inline constexpr uint8_t kSniffedHttp = 1u << 1;
inline constexpr uint8_t kSniffedQuic = 1u << 2;
inline constexpr uint8_t kSniffedBitTorrent = 1u << 3;

// 不在可嗅探集合内的协议名返回 0。
[[nodiscard]] constexpr uint8_t SniffedProtocolBit(std::string_view protocol) noexcept {
    if (protocol == constants::protocol::kTls) return kSniffedTls;
    if (protocol == constants::protocol::kHttp) return kSniffedHttp;
    if (protocol == constants::protocol::kQuic) return kSniffedQuic;
    if (protocol == constants::protocol::kBitTorrent) return kSniffedBitTorrent;
    return 0;
}

}  // namespace routing
