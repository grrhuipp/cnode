#pragma once

#include "common/domain_name.hpp"
#include "core/constants.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>


// ============================================================================
// SniffConfig - 流量嗅探配置（所有协议共用）
//
// destOverride 是封闭的协议集合，配置边界一次解析为位集；字段之间没有派生
// 状态，任意构造结果即可直接进入热路径。
// ============================================================================
struct SniffConfig {
    static constexpr uint8_t kTls = 1u << 0;
    static constexpr uint8_t kHttp = 1u << 1;
    static constexpr uint8_t kQuic = 1u << 2;
    static constexpr uint8_t kBitTorrent = 1u << 3;

    bool enabled = true;
    bool metadata_only = false;
    bool route_only = true;
    uint8_t dest_override = kTls | kHttp | kQuic;
    std::vector<std::string> domains_excluded;

    // 0 for a protocol name outside the supported destOverride set.
    [[nodiscard]] static constexpr uint8_t DestOverrideBit(std::string_view protocol) noexcept {
        if (protocol == constants::protocol::kTls) return kTls;
        if (protocol == constants::protocol::kHttp) return kHttp;
        if (protocol == constants::protocol::kQuic) return kQuic;
        if (protocol == constants::protocol::kBitTorrent) return kBitTorrent;
        return 0;
    }

    [[nodiscard]] bool MatchesDestOverride(std::string_view protocol) const noexcept {
        return (dest_override & DestOverrideBit(protocol)) != 0;
    }

    [[nodiscard]] bool IsDomainExcluded(std::string_view hostname) const noexcept {
        for (const auto& excluded : domains_excluded) {
            if (domain::DnsHostnamesEqual(excluded, hostname)) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool operator==(const SniffConfig&) const = default;
};

