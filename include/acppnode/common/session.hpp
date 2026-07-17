#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/clock.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/common/network.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

namespace session {

struct Context;

using ID = uint64_t;

}  // namespace session

namespace session {

enum class DnsResultState : uint8_t {
    None,
    Cache,
    Resolve,
    Failed,
};

// xray-core common/session.Inbound 对应的连接入站元数据。
// 字符串视图指向冷路径监听配置；用户邮箱使用 Worker 本地短生命周期存储。
struct Inbound {
    net::ip::address source_addr;
    std::string source_ip;
    uint16_t source_port = 0;
    std::optional<tcp::endpoint> local_endpoint;
    std::string_view tag;
    std::string_view protocol;
    const std::vector<std::string>* tags = nullptr;
    int64_t user_id = 0;
    std::string user_email;
    // Opaque reference into the process-level immutable access-log source
    // registry. Panel fields stay in the control plane and never enter the
    // Worker hot-path Context.
    uint32_t access_source_ref = 0;
};

// xray-core common/session.Outbound 对应的出站目标/路由元数据。
struct Outbound {
    TargetAddress original_target;
    TargetAddress target;
    TargetAddress route_target;
    // The final destination address confirmed by a direct outbound after a
    // successful dial. Proxy next-hop addresses must never be stored here.
    std::optional<net::ip::address> connected_target_addr;
    // The final destination address most recently attempted by a direct
    // outbound. Unlike connected_target_addr, this remains available when
    // the transport dial or handshake fails. Proxy next hops must not be
    // stored here.
    std::optional<net::ip::address> dial_target_addr;
    // Local egress address of the established outbound socket. Unlike the
    // remote field this is meaningful for direct and proxy next-hop sockets.
    std::optional<net::ip::address> connected_local_addr;
    std::string_view tag;
};

// xray-core common/session.Content 对应的内容元数据。
struct Content {
    Network network = Network::TCP;
    std::string protocol;
    std::string sniff_domain;
    uint64_t speed_limit = 0;
    session::DnsResultState dns_result = session::DnsResultState::None;
    bool multiple_targets = false;
};

struct Traffic {
    uint64_t bytes_up = 0;
    uint64_t bytes_down = 0;
};

struct Sockopt {
    int32_t mark = 0;
};

// Per-connection xray-style session metadata. The object itself stays
// Worker-local; protocol, routing, outbound and relay code read/write the
// records directly instead of going through the old app-layer context shell.
struct Context {
    // 连接标识
    ID conn_id = 0;

    Inbound inbound;
    Outbound outbound;
    std::vector<Outbound> outbounds;
    Content content;
    Traffic traffic;
    std::optional<Sockopt> sockopt;

    // 接入时间戳（微秒，使用 steady_clock），用于访问日志。
    int64_t accept_time_us = 0;

    uint32_t worker_id = 0;

    // Worker-local idempotency bit shared by the inbound fallback guard and
    // Dispatcher terminal-event guard.
    bool access_event_submitted = false;

    Context() {
        accept_time_us = NowMicros();
    }

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) = delete;
    Context& operator=(Context&&) = delete;
};

[[nodiscard]] ID NewID(uint32_t worker_id) noexcept;

}  // namespace session

std::string FormatAccessLog(
    const session::Context& ctx,
    const net::ip::address* resolved_ip = nullptr,
    const net::ip::address* local_ip = nullptr);

}  // namespace acpp
