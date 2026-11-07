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

struct ConnectionFamily;

namespace session {

struct Context;

using ID = uint64_t;

[[nodiscard]] inline std::pmr::memory_resource* SessionPoolResource() noexcept {
    auto* resource = std::pmr::get_default_resource();
    return resource != std::pmr::new_delete_resource()
        ? resource
        : memory::ThreadMemoryPool().resource();
}

// 高 32 位为 worker_id，低 32 位为 Worker 线程本地序号，避免全局原子计数器的跨线程争用。
[[nodiscard]] ID NewID(uint32_t worker_id) noexcept;

// xray-core common/session.Inbound 对应的连接入站元数据。
// 配置标签、协议与安全方式在会话中按值保存在 Worker 本地 PMR 存储。
struct Inbound {
    Inbound() : Inbound(SessionPoolResource()) {}
    explicit Inbound(std::pmr::memory_resource* resource)
        : source_ip(resource)
        , client_ip_source("socket", resource)
        , tag(resource)
        , accounting_key(resource)
        , tags(resource)
        , user_email(resource)
        , origin_tag(resource)
        , origin_user_email(resource)
        , origin_source_ip(resource) {}
    net::ip::address source_addr;
    memory::ThreadLocalString source_ip;
    uint16_t source_port = 0;
    memory::ThreadLocalString client_ip_source = "socket";

    [[nodiscard]] bool HasProxyProtocolClientIP() const noexcept {
        return client_ip_source == "proxy_protocol" && !source_ip.empty();
    }
    std::optional<tcp::endpoint> local_endpoint;
    memory::ThreadLocalString tag;
    memory::ThreadLocalString accounting_key;
    memory::ThreadLocalVector<memory::ThreadLocalString> tags;
    int64_t user_id = 0;
    memory::ThreadLocalString user_email;

    // 链式代理透传自最初入站的标签、身份与真实客户端 IP。
    memory::ThreadLocalString origin_tag;
    int64_t origin_user_id = 0;
    memory::ThreadLocalString origin_user_email;
    net::ip::address origin_source_addr;
    memory::ThreadLocalString origin_source_ip;

    // Connection-limit family lease of the physical connection this request
    // arrived on. Set by the inbound handler; substreams inherit it and take
    // their logical admission against it.
    std::shared_ptr<ConnectionFamily> connection_family;

    void ApplyForwardedMetadata(const ForwardedMetadata& metadata) {
        if (!metadata.inbound_tag.empty()) {
            origin_tag.assign(metadata.inbound_tag.data(), metadata.inbound_tag.size());
        }
        if (metadata.user_id > 0) {
            origin_user_id = metadata.user_id;
        }
        if (!metadata.user_email.empty()) {
            origin_user_email.assign(metadata.user_email.data(), metadata.user_email.size());
        }
        if (metadata.client_ip && !metadata.client_ip->is_unspecified()) {
            origin_source_addr = iputil::NormalizeAddress(*metadata.client_ip);
            const auto text = iputil::AddressText(origin_source_addr);
            origin_source_ip.assign(text.View());
        }
    }

    [[nodiscard]] bool HasOriginIdentity() const noexcept {
        return origin_user_id > 0 || !origin_user_email.empty() || !origin_tag.empty();
    }

    [[nodiscard]] std::string_view EffectiveInboundTag() const noexcept {
        return !origin_tag.empty() ? std::string_view(origin_tag)
                                   : std::string_view(tag);
    }
    [[nodiscard]] int64_t EffectiveUserId() const noexcept {
        return HasOriginIdentity() ? origin_user_id : user_id;
    }

    [[nodiscard]] std::string_view EffectiveUserEmail() const noexcept {
        return HasOriginIdentity() ? std::string_view(origin_user_email)
                                   : std::string_view(user_email);
    }

    [[nodiscard]] const net::ip::address& EffectiveClientAddress() const noexcept {
        return !origin_source_addr.is_unspecified() ? origin_source_addr : source_addr;
    }

    [[nodiscard]] std::string_view EffectiveClientIp() const noexcept {
        return !origin_source_ip.empty() ? std::string_view(origin_source_ip)
                                         : std::string_view(source_ip);
    }

    [[nodiscard]] ForwardedMetadataView MakeForwardedMetadata() const noexcept {
        std::optional<net::ip::address> client_ip;
        const auto& addr = EffectiveClientAddress();
        if (!addr.is_unspecified()) {
            client_ip = addr;
        } else if (const auto literal = iputil::ParseLiteral(EffectiveClientIp())) {
            const auto normalized = iputil::NormalizeAddress(*literal);
            if (!normalized.is_unspecified()) {
                client_ip = normalized;
            }
        }
        return ForwardedMetadataView{
            .user_id = EffectiveUserId(),
            .user_email = EffectiveUserEmail(),
            .client_ip = client_ip,
            .inbound_tag = EffectiveInboundTag(),
        };
    }
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
    Content() : Content(SessionPoolResource()) {}
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
// records directly.
struct Context {
    // 连接标识
    ID conn_id = 0;

    Inbound inbound;
    Outbound outbound;
    Content content;
    Traffic traffic;

    // 接入时间戳（微秒，Unix 纪元），用于访问日志。
    int64_t accept_time_us = 0;

    uint32_t worker_id = 0;

    Context() {
        accept_time_us = NowMicros();
    }

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) = delete;
    Context& operator=(Context&&) = delete;

    void InitSubstreamFrom(const Context& parent, uint16_t sub_source_port = 0);
};

}  // namespace session

enum class AccessStatus { Accepted, Rejected };

std::string FormatAccessLog(
    const session::Context& ctx,
    AccessStatus status = AccessStatus::Accepted,
    std::string_view reason = {});

}  // namespace acpp
