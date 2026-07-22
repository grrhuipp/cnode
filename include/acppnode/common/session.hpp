#pragma once

#include "acppnode/common/asio_types.hpp"
#include "acppnode/common/clock.hpp"
#include "acppnode/common/target_address.hpp"
#include "acppnode/common/network.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace acpp {

class ReadPrefixCapture;

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
    // Physical socket peer is retained separately from an effective client
    // address supplied by a trusted PROXY protocol or HTTP transport header.
    std::string peer_ip;
    uint16_t peer_port = 0;
    std::string client_ip_source = "socket";
    bool client_ip_trusted = true;
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
    std::string_view transport;
    std::string_view security;
    std::string tls_sni;
    std::string tls_alpn;
    std::string tls_version;
    std::string tls_fingerprint;
    std::string http_host;
    std::string transport_route_id;
    uint64_t transport_handshake_ms = 0;
    int64_t transport_ready_at_unix_us = 0;
    // Worker-local raw wire prefix retained only until protocol admission
    // succeeds. Error reporting copies it into an owning event value.
    std::shared_ptr<ReadPrefixCapture> read_prefix_capture;
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
    std::string route_rule;
    uint64_t dns_latency_ms = 0;
    uint32_t dns_answer_count = 0;
    uint64_t dial_ms = 0;
    uint32_t dial_attempt_count = 0;
    std::vector<net::ip::address> dial_addresses;
    int32_t os_error_code = 0;
    std::string failure_detail_code;
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
    uint64_t packet_count_up = 0;
    uint64_t packet_count_down = 0;
    uint64_t datagram_count = 0;
    uint32_t distinct_target_count = 0;
    std::array<uint64_t, 32> distinct_target_hashes{};
    uint64_t first_byte_ms = 0;
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
    uint64_t parent_conn_id = 0;
    uint64_t stream_id = 0;
    uint64_t runtime_generation = 1;
    uint64_t config_generation = 1;
    uint64_t auth_ms = 0;

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

std::string FormatXrayAccessLog(const session::Context& ctx);

}  // namespace acpp
