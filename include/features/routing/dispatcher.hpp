#pragma once

#include "common/asio_types.hpp"
#include "app/relay.hpp"
#include "common/domain_name.hpp"
#include "common/error.hpp"
#include "common/initial_payload.hpp"
#include "core/constants.hpp"
#include "transport/link.hpp"

#include <cstdint>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
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

class AsyncStream;

namespace session {
struct Context;
}

struct StatsShard;
struct TimeoutsConfig;

namespace routing {

// Dispatcher-owned outbound selection policy. Both alternatives require an
// explicit target, so a receiver cannot accidentally inherit mutable process
// state or enter the hot path without a complete selection policy.
struct ForceOutbound {
    explicit ForceOutbound(std::string tag)
        : outbound_tag(std::move(tag)) {
        if (outbound_tag.empty()) {
            throw std::invalid_argument("forced outbound tag must not be empty");
        }
    }

    std::string outbound_tag;
};

struct RouteWithFallback {
    explicit RouteWithFallback(std::string tag)
        : outbound_tag(std::move(tag)) {
        if (outbound_tag.empty()) {
            throw std::invalid_argument("routing fallback tag must not be empty");
        }
    }

    std::string outbound_tag;
};

using OutboundSelectionPolicy = std::variant<ForceOutbound, RouteWithFallback>;

// Immutable after receiver preparation. Inbound handlers, Mux children and
// native UDP sessions pass only this narrow hot-path contract to Dispatcher.
struct DispatchPolicy {
    SniffConfig sniffing;
    OutboundSelectionPolicy outbound;
};

// ============================================================================
// Dispatcher - routing feature interface
//
// Dispatch 接收协议层准备好的不可变策略、transport::Link、初始 payload
// 和 relay 参数；路由编排是实现细节，唯一公开热路径直接进入
// outbound.Process 和 relay。
// ============================================================================
class Dispatcher {
public:
    virtual ~Dispatcher() noexcept = default;

    virtual net::awaitable<RelayResult> Dispatch(
        net::io_context& io_context,
        const DispatchPolicy& policy,
        std::unique_ptr<AsyncStream> inbound,
        transport::Link inbound_link,
        InitialPayload first_packet,
        session::Context& ctx,
        StatsShard& stats,
        const TimeoutsConfig& timeouts) = 0;
};

}  // namespace routing
