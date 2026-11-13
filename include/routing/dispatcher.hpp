#pragma once

#include "common/asio_types.hpp"
#include "app/relay.hpp"
#include "common/domain_name.hpp"
#include "common/multi_buffer.hpp"
#include "common/constants.hpp"
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
// destOverride 是封闭的协议集合（routing::SniffedProtocolBit），配置边界一次
// 解析为位集；字段之间没有派生状态，任意构造结果即可直接进入热路径。
// ============================================================================
namespace routing {

// 可嗅探协议名到位的唯一映射：嗅探 destOverride 与路由规则的 protocol 条件共用
// 同一张表，配置边界一次换算成位集，热路径只做位运算。
inline constexpr uint8_t kSniffedTls = 1u << 0;
inline constexpr uint8_t kSniffedHttp = 1u << 1;
inline constexpr uint8_t kSniffedQuic = 1u << 2;
inline constexpr uint8_t kSniffedBitTorrent = 1u << 3;

[[nodiscard]] constexpr uint8_t SniffedProtocolBit(std::string_view protocol) noexcept {
    if (protocol == common::kTls) return kSniffedTls;
    if (protocol == common::kHttp) return kSniffedHttp;
    if (protocol == common::kQuic) return kSniffedQuic;
    if (protocol == common::kBitTorrent) return kSniffedBitTorrent;
    return 0;
}

struct SniffConfig {
    bool enabled = true;
    bool metadata_only = false;
    bool route_only = true;
    uint8_t dest_override =
        routing::kSniffedTls | routing::kSniffedHttp | routing::kSniffedQuic;
    std::vector<std::string> domains_excluded;

    [[nodiscard]] bool MatchesDestOverride(std::string_view protocol) const noexcept {
        return (dest_override & routing::SniffedProtocolBit(protocol)) != 0;
    }

    [[nodiscard]] bool IsDomainExcluded(std::string_view hostname) const noexcept {
        for (const auto& excluded : domains_excluded) {
            if (common::DnsHostnamesEqual(excluded, hostname)) {
                return true;
            }
        }
        return false;
    }

    [[nodiscard]] bool operator==(const SniffConfig&) const = default;
};

}  // namespace routing

namespace transport {

class AsyncStream;

}  // namespace transport

namespace common {
struct Context;
}

namespace app {

struct StatsShard;

}  // namespace app
namespace infra {

struct TimeoutsConfig;

}  // namespace infra

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

    virtual net::awaitable<app::RelayResult> Dispatch(
        net::io_context& io_context,
        const DispatchPolicy& policy,
        std::unique_ptr<transport::AsyncStream> inbound,
        transport::Link inbound_link,
        common::InitialPayload first_packet,
        common::Context& ctx,
        app::StatsShard& stats,
        const infra::TimeoutsConfig& timeouts) = 0;
};

}  // namespace routing
