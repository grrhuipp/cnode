#pragma once

#include "acppnode/common/allocator.hpp"
#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/clock.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/common/network.hpp"
#include "acppnode/runtime/channel.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <memory>
#include <limits>
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
// 配置标签、协议与安全方式由会话按值持有。
struct Inbound {
    net::ip::address source_addr;
    memory::DataString source_ip;
    uint16_t source_port = 0;
    // Physical socket peer is retained separately from an effective client
    // address supplied by a trusted PROXY protocol or HTTP transport header.
    memory::DataString peer_ip;
    uint16_t peer_port = 0;
    memory::DataString client_ip_source = "socket";
    bool client_ip_trusted = true;

    [[nodiscard]] bool HasProxyProtocolClientIP() const noexcept {
        return client_ip_source == "proxy_protocol" && !source_ip.empty();
    }
    std::optional<tcp::endpoint> local_endpoint;
    memory::DataString tag;
    memory::DataString protocol;
    memory::DataVector<memory::DataString> tags;
    int64_t user_id = 0;
    memory::DataString user_email;
    std::string_view transport;
    memory::DataString security;
    memory::DataString tls_sni;
    memory::DataString tls_alpn;
    memory::DataString tls_version;
    memory::DataString tls_fingerprint;
    memory::DataString http_host;
    memory::DataString transport_route_id;
    uint64_t transport_handshake_ms = 0;
    int64_t transport_ready_at_unix_us = 0;
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
    uint16_t connected_local_port = 0;
    memory::DataString route_rule;
    uint64_t dns_latency_ms = 0;
    uint32_t dns_answer_count = 0;
    uint64_t dial_ms = 0;
    uint32_t dial_attempt_count = 0;
    std::vector<net::ip::address> dial_addresses;
    int32_t os_error_code = 0;
    memory::DataString failure_detail_code;
    std::string_view tag;
};

// xray-core common/session.Content 对应的内容元数据。
struct Content {
    Network network = Network::TCP;
    memory::DataString protocol;
    memory::DataString sniff_domain;
    uint64_t speed_limit = 0;
    session::DnsResultState dns_result = session::DnsResultState::None;
    bool multiple_targets = false;
};

struct Traffic {
    uint64_t bytes_up = 0;
    uint64_t bytes_down = 0;
    uint64_t packet_count_up = 0;
    uint64_t packet_count_down = 0;
    uint64_t datagram_count = 0;
    uint32_t distinct_target_count = 0;
    std::array<uint64_t, 32> distinct_target_hashes{};
    uint64_t first_byte_ms = 0;
};

// The connection uses Local() only on its owner strand. Other services receive
// a bounded value snapshot; they never retain a pointer into Context.
class TrafficSource {
public:
    explicit TrafficSource(net::any_io_executor executor)
        : channel_(std::move(executor), 2) {}
    TrafficSource(const TrafficSource&) = delete;
    TrafficSource& operator=(const TrafficSource&) = delete;
    [[nodiscard]] Traffic& Local() noexcept { return traffic_; }
    net::awaitable<Traffic> Snapshot() {
        return channel_.Call([this] { return traffic_; });
    }
private:
    ServiceChannel channel_;
    Traffic traffic_;
};

struct Sockopt {
    int32_t mark = 0;
};

// Per-connection xray-style session metadata. The object itself stays
// Session-owned; protocol, routing, outbound and relay code read/write the
// records directly instead of going through the old app-layer context shell.
struct Context {
    // 连接标识
    ID conn_id = 0;

    Inbound inbound;
    Outbound outbound;
    memory::DataVector<Outbound> outbounds;
    Content content;
    std::shared_ptr<TrafficSource> traffic_owner;
    Traffic& traffic;
    std::optional<Sockopt> sockopt;

    // 接入时间戳（微秒，使用 steady_clock），用于访问日志。
    int64_t accept_time_us = 0;

    uint64_t parent_conn_id = 0;
    uint64_t stream_id = 0;
    uint64_t runtime_generation = 1;
    uint64_t config_generation = 1;
    uint64_t auth_ms = 0;

    explicit Context(net::any_io_executor executor)
        : traffic_owner(memory::AllocateShared<TrafficSource>(std::move(executor))),
          traffic(traffic_owner->Local()) {
        accept_time_us = NowMicros();
    }

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) = delete;
    Context& operator=(Context&&) = delete;
};

inline constexpr uint64_t kConnectionIdStride =
    static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 2;
inline constexpr uint64_t kMaxPhysicalSequence =
    std::numeric_limits<uint64_t>::max() / kConnectionIdStride;

// Physical IDs are allocated serially by the runtime owner. The gap reserves
// one unique ID for every possible 16-bit logical stream of that connection.
[[nodiscard]] constexpr ID PhysicalID(uint64_t sequence) noexcept {
    return sequence * kConnectionIdStride;
}

[[nodiscard]] constexpr ID ChildID(ID physical_id, uint32_t stream_id) noexcept {
    return physical_id + static_cast<uint64_t>(stream_id) + 1;
}

}  // namespace session

std::string FormatAccessLog(const session::Context& ctx);

}  // namespace acpp
