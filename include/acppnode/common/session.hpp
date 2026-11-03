#pragma once

#include "acppnode/common/allocator.hpp"
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

namespace session {

struct Context;

using ID = uint64_t;

}  // namespace session

namespace session {

// xray-core common/session.Inbound 对应的连接入站元数据。
// 配置标签、协议与安全方式在会话中按值保存在 Worker 本地 PMR 存储。
struct Inbound {
    Inbound() = default;
    explicit Inbound(std::pmr::memory_resource* resource)
        : source_ip(resource)
        , peer_ip(resource)
        , client_ip_source("socket", resource)
        , tag(resource)
        , accounting_key(resource)
        , protocol(resource)
        , tags(resource)
        , user_email(resource)
        , security(resource) {}

    net::ip::address source_addr;
    memory::ThreadLocalString source_ip;
    uint16_t source_port = 0;
    // Physical socket peer is retained separately from an effective client
    // address supplied by a trusted PROXY protocol or HTTP transport header.
    memory::ThreadLocalString peer_ip;
    uint16_t peer_port = 0;
    memory::ThreadLocalString client_ip_source = "socket";
    bool client_ip_trusted = true;

    [[nodiscard]] bool HasProxyProtocolClientIP() const noexcept {
        return client_ip_source == "proxy_protocol" && !source_ip.empty();
    }
    std::optional<tcp::endpoint> local_endpoint;
    memory::ThreadLocalString tag;
    memory::ThreadLocalString accounting_key;
    memory::ThreadLocalString protocol;
    memory::ThreadLocalVector<memory::ThreadLocalString> tags;
    int64_t user_id = 0;
    memory::ThreadLocalString user_email;
    memory::ThreadLocalString security;
};

// xray-core common/session.Outbound 对应的出站目标/路由元数据。
struct Outbound {
    TargetAddress original_target;
    TargetAddress target;
    TargetAddress route_target;
    // Local egress address of the established outbound socket. Unlike the
    // remote field this is meaningful for direct and proxy next-hop sockets.
    std::optional<net::ip::address> connected_local_addr;
    std::string_view tag;
};

// xray-core common/session.Content 对应的内容元数据。
struct Content {
    Content() = default;
    explicit Content(std::pmr::memory_resource* resource)
        : protocol(resource) {}

    Network network = Network::TCP;
    memory::ThreadLocalString protocol;
    uint64_t speed_limit = 0;
};

struct Traffic {
    uint64_t bytes_up = 0;
    uint64_t bytes_down = 0;
};


// Per-connection xray-style session metadata. The object itself stays
// Worker-local; protocol, routing, outbound and relay code read/write the
// records directly instead of going through the old app-layer context shell.
struct Context {
private:
    static constexpr std::size_t kInitialArenaBytes = 224;
    memory::request_memory memory_{kInitialArenaBytes, std::pmr::get_default_resource()};

public:
    // 连接标识
    ID conn_id = 0;

    Inbound inbound{memory_.resource()};
    Outbound outbound;
    Content content{memory_.resource()};
    Traffic traffic;

    // 接入时间戳（微秒，使用 steady_clock），用于访问日志。
    int64_t accept_time_us = 0;

    uint32_t worker_id = 0;

    Context() {
        accept_time_us = NowMicros();
    }

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) = delete;
    Context& operator=(Context&&) = delete;

    // Request/session lifetime monotonic arena.
    [[nodiscard]] std::pmr::memory_resource* arena() const noexcept {
        return memory_.resource();
    }

    // Worker-local reclaimable pool resource.
    [[nodiscard]] std::pmr::memory_resource* pool() const noexcept {
        return memory_.upstream_resource();
    }

    template <typename T = std::byte>
    [[nodiscard]] std::pmr::polymorphic_allocator<T> allocator() const noexcept {
        return std::pmr::polymorphic_allocator<T>(arena());
    }
};

[[nodiscard]] ID NewID(uint32_t worker_id) noexcept;

}  // namespace session

std::string FormatAccessLog(const session::Context& ctx);

}  // namespace acpp
