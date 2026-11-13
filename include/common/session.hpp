#pragma once

#include "common/allocator.hpp"
#include "common/asio_types.hpp"
#include "common/target_address.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>


namespace app {

struct ConnectionFamily;

}  // namespace app

namespace common {

struct Context;

using ID = uint64_t;

// 高 32 位为 worker_id，低 32 位为 Worker 线程本地序号，避免全局原子计数器的跨线程争用。
[[nodiscard]] ID NewID(uint32_t worker_id) noexcept;

// xray-core common/session.Inbound 对应的连接入站元数据。
// 配置标签、协议与安全方式按值保存在 Worker 本地。
struct Inbound {
    enum class ClientIpSource : uint8_t { Socket, ProxyProtocol, HttpHeader };

    net::ip::address source_addr;
    std::string source_ip;
    uint16_t source_port = 0;
    ClientIpSource client_ip_source = ClientIpSource::Socket;

    [[nodiscard]] bool HasProxyProtocolClientIP() const noexcept {
        return client_ip_source == ClientIpSource::ProxyProtocol && !source_ip.empty();
    }
    std::optional<tcp::endpoint> local_endpoint;
    std::string tag;
    std::string accounting_key;
    std::vector<std::string> tags;
    int64_t user_id = 0;
    std::string user_email;

    // 链式代理透传自最初入站的标签、身份与真实客户端 IP。
    std::string origin_tag;
    int64_t origin_user_id = 0;
    std::string origin_user_email;
    net::ip::address origin_source_addr;
    std::string origin_source_ip;

    // Connection-limit family lease of the physical connection this request
    // arrived on. Set by the inbound handler; substreams inherit it and take
    // their logical admission against it.
    std::shared_ptr<app::ConnectionFamily> connection_family;

    void ApplyForwardedMetadata(const ForwardedMetadata& metadata) {
        if (!metadata.inbound_tag.empty()) {
            origin_tag.assign(metadata.inbound_tag.data(), metadata.inbound_tag.size());
        } else {
            origin_tag.clear();
        }
        origin_user_id = metadata.user_id > 0 ? metadata.user_id : 0;
        if (!metadata.user_email.empty()) {
            origin_user_email.assign(metadata.user_email.data(), metadata.user_email.size());
        } else {
            origin_user_email.clear();
        }
        if (metadata.client_ip) {
            const auto normalized = NormalizeAddress(*metadata.client_ip);
            if (!normalized.is_unspecified()) {
                origin_source_addr = normalized;
                const auto text = AddressText(origin_source_addr);
                origin_source_ip.assign(text.View());
                return;
            }
        }
        origin_source_addr = net::ip::address{};
        origin_source_ip.clear();
    }

    [[nodiscard]] bool HasOriginIdentity() const noexcept {
        return origin_user_id > 0 || !origin_user_email.empty() || !origin_tag.empty();
    }

    [[nodiscard]] std::string_view EffectiveInboundTag() const& noexcept {
        return !origin_tag.empty() ? std::string_view(origin_tag)
                                   : std::string_view(tag);
    }
    std::string_view EffectiveInboundTag() const&& = delete;

    [[nodiscard]] int64_t EffectiveUserId() const noexcept {
        return HasOriginIdentity() ? origin_user_id : user_id;
    }

    [[nodiscard]] std::string_view EffectiveUserEmail() const& noexcept {
        return HasOriginIdentity() ? std::string_view(origin_user_email)
                                   : std::string_view(user_email);
    }
    std::string_view EffectiveUserEmail() const&& = delete;

    [[nodiscard]] const net::ip::address& EffectiveClientAddress() const& noexcept {
        return !origin_source_addr.is_unspecified() ? origin_source_addr : source_addr;
    }
    const net::ip::address& EffectiveClientAddress() const&& = delete;

    [[nodiscard]] std::string_view EffectiveClientIp() const& noexcept {
        return !origin_source_ip.empty() ? std::string_view(origin_source_ip)
                                         : std::string_view(source_ip);
    }
    std::string_view EffectiveClientIp() const&& = delete;

    [[nodiscard]] ForwardedMetadataView MakeForwardedMetadata() const& noexcept {
        std::optional<net::ip::address> client_ip;
        const auto& addr = EffectiveClientAddress();
        if (!addr.is_unspecified()) {
            client_ip = addr;
        } else if (const auto literal = ParseLiteral(EffectiveClientIp())) {
            const auto normalized = NormalizeAddress(*literal);
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
    ForwardedMetadataView MakeForwardedMetadata() const&& = delete;
};
using ClientIpSource = Inbound::ClientIpSource;


// xray-core common/session.Outbound 对应的出站目标/路由元数据。
struct Outbound {
    // 仅当嗅探改写了 target 时保存改写前的请求目标；否则为空（与 target 相同）。
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
    Network network = Network::TCP;
    std::string protocol;
    uint64_t speed_limit = 0;
};

struct Traffic {
    uint64_t bytes_up = 0;
    uint64_t bytes_down = 0;
};

// Per-connection metadata stays Worker-local.
struct Context {
    Context() = default;

    // 连接标识
    ID conn_id = 0;

    Inbound inbound;
    Outbound outbound;
    Content content;
    Traffic traffic;

    uint32_t worker_id = 0;

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) = delete;
    Context& operator=(Context&&) = delete;
    void InitSubstreamFrom(const Context& parent, uint16_t sub_source_port = 0);
};

enum class AccessStatus { Accepted, Rejected };

std::string FormatAccessLog(
    const Context& ctx,
    AccessStatus status = AccessStatus::Accepted,
    std::string_view reason = {});

}  // namespace common

