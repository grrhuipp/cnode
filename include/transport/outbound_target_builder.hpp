#pragma once

#include "common/asio_types.hpp"
#include "common/defaults.hpp"
#include "common/domain_name.hpp"
#include "common/error.hpp"
#include "common/ip_address.hpp"
#include "common/session.hpp"
#include "common/target_address.hpp"
#include "transport/async_stream.hpp"
#include "transport/outbound_bind.hpp"
#include "transport/outbound_server.hpp"
#include "transport/stream_settings.hpp"
#include "transport/transport_security.hpp"

#include <tl/expected.hpp>

#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace app {
class DNS;
}  // namespace app

namespace transport {

class SslContext;

// Xray proxyman SenderSettings: how one outbound tag leaves this node. Owned by
// the proxyman outbound Handler and borrowed by its OutboundDialer; protocol
// defaults (TLS requirement, fallback SNI, ALPN) are applied when prepared.
struct OutboundSenderSettings {
    StreamSettings stream_settings;
    OutboundBind send_through;
    bool passthrough = false;
};



// 单个候选拨号地址
struct OutboundDialCandidate {
    tcp::endpoint endpoint;
    std::optional<net::ip::address> bind_local;  // 可按候选 IP 单独决定绑定地址
};

// 出站传输目标（仅携带已解析拨号候选）：transport/internet 的拨号输入，
// 不属于 proxy 出站协议壳。
struct OutboundTransportTarget {
    std::optional<OutboundDialCandidate> single_candidate; // 单个已解析候选，避免每连接 vector 分配
    std::vector<OutboundDialCandidate> candidates; // 已解析候选地址（按优先级排序）
    std::string_view tls_server_name;               // TLS SNI（冷路径配置视图，可空）
    std::string ws_host;              // 未配置显式 HTTP Host 时动态格式化的 fallback authority
    const StreamSettings* stream_settings = nullptr; // 必填：冷路径准备好的传输层组合配置
    SslContext* security_context = nullptr;          // TLS/REALITY 时必填：出站 handler 的 Worker 私有上下文
    std::chrono::seconds timeout{common::kDialTimeout};

    // XHTTP packet-up / stream-up 可用独立下行入口；仅保存已解析候选和不可变配置视图。
    std::unique_ptr<const OutboundTransportTarget> xhttp_download_target;

    [[nodiscard]] std::string_view HttpHost() const noexcept {
        if (stream_settings && !stream_settings->configured_http_host.empty()) {
            return stream_settings->configured_http_host;
        }
        return ws_host;
    }

    [[nodiscard]] std::span<const OutboundDialCandidate> Candidates() const noexcept {
        return single_candidate
            ? std::span<const OutboundDialCandidate>(&*single_candidate, 1)
            : std::span<const OutboundDialCandidate>(candidates);
    }
};

struct OutboundTargetOptions {
    app::DNS* dns_service = nullptr;
    std::string_view address{};
    std::optional<net::ip::address> literal_address = std::nullopt;
    uint16_t port = 0;
    const StreamSettings* stream_settings = nullptr;
    // The outbound handler's contexts for |stream_settings|; the XHTTP
    // download leg uses its XHttpDownload() contexts.
    const TransportSecurity* security = nullptr;
    std::chrono::seconds timeout{common::kDialTimeout};
    const OutboundBind* send_through = nullptr; // Borrowed from the outbound handler.
    const tcp::endpoint* inbound_local_addr = nullptr;
    std::string_view inbound_source_ip{};
    int64_t inbound_user_id = 0;
    std::string_view inbound_user_email{};
    std::string_view inbound_tag{};
    std::optional<OutboundBind::Selection> ordered_bind_v4 = std::nullopt;
    std::optional<OutboundBind::Selection> ordered_bind_v6 = std::nullopt;
};

[[nodiscard]] std::string_view ResolveOutboundTlsServerName(
    const StreamSettings& settings,
    std::string_view fallback_server_name);
std::string_view ResolveOutboundTlsServerName(
    const StreamSettings&& settings,
    std::string_view fallback_server_name) = delete;

[[nodiscard]]
net::awaitable<tl::expected<OutboundTransportTarget, common::ErrorCode>>
BuildOutboundTransportTarget(OutboundTargetOptions options);

// 统一出站传输连接：
// 消费冷路径预构建候选，建立 TCP 连接，并按 StreamSettings 完成 TLS/WS。
[[nodiscard]]
net::awaitable<DialResult> DialOutboundTransport(
    net::io_context& io_context,
    common::Context& ctx,
    const OutboundTransportTarget& target);

// ============================================================================
// OutboundDialer - Xray internet.Dialer of one proxyman outbound Handler
//
// The Handler owns it next to its sender settings and passes it by reference
// into proxy::Outbound::Process. Every outbound connection of that tag leaves
// through here: the stream settings, transport security and sendThrough are the
// Handler's, never a protocol's private copy. Bound to the Worker's reactor
// and DNS client; the sender settings must outlive the dialer.
// ============================================================================
class OutboundDialer final {
public:
    // Per-request sendThrough choice for Ordered binds, computed once so that a
    // caller can match pooled transports against the same selection it dials.
    struct OrderedBind {
        OutboundBind::Selection v4;
        OutboundBind::Selection v6;
    };

    struct AddressFamilyPolicy {
        bool accepts_v4 = true;
        bool accepts_v6 = true;
        bool prefers_v6 = false;
        bool preserves_dns_order = true;
        bool restricts_literals = false;
    };

    // Remote side of a native (transport-less) UDP association.
    struct DatagramRemote {
        // Known remote address; fixes the socket family.
        std::optional<net::ip::address> address;
        // Family hint when the remote is a hostname (e.g. a routing lookup).
        std::optional<net::ip::address> family_hint;
        AddressFamilyPolicy family_policy;
    };

    OutboundDialer(net::io_context& io_context,
                   app::DNS& dns,
                   const OutboundSenderSettings& sender,
                   std::chrono::seconds timeout);
    OutboundDialer(const OutboundDialer&) = delete;
    OutboundDialer& operator=(const OutboundDialer&) = delete;

    [[nodiscard]] net::io_context& IoContext() const noexcept { return io_context_; }

    [[nodiscard]] common::ForwardedMetadataView ForwardedMetadata(
        const common::Context& ctx) const noexcept;
    common::ForwardedMetadataView ForwardedMetadata(
        const common::Context&& ctx) const = delete;
    // Empty unless sendThrough is Ordered.
    [[nodiscard]] std::optional<OrderedBind> SelectOrderedBind(
        const common::Context& ctx) const;
    std::optional<OrderedBind> SelectOrderedBind(
        const common::Context&& ctx) const = delete;

    // Proxy next hop through the Handler's stream settings.
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, common::ErrorCode>>
    Dial(common::Context& ctx, const OutboundServer& server,
         const OrderedBind* ordered = nullptr);

    // 直连目标的解析、地址族筛选与尝试顺序由拨号器统一执行。
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, common::ErrorCode>>
    Dial(common::Context& ctx, const common::TargetAddress& target, AddressFamilyPolicy policy);

    // Native UDP association: selects the sendThrough bind address, constructs
    // Endpoint(io_context, dns, bind_address, args...) and records the egress.
    template <typename Endpoint, typename... Args>
    [[nodiscard]] tl::expected<void, common::ErrorCode> OpenDatagram(
        common::Context& ctx, const DatagramRemote& remote,
        std::optional<Endpoint>& endpoint, Args&&... args) {
        auto bind = SelectDatagramBind(ctx, remote);
        if (!bind) return tl::unexpected(bind.error());
        try {
            endpoint.emplace(IoContext(), dns_, *bind, std::forward<Args>(args)...);
        } catch (const transport::LinkError& error) {
            ReportDatagramFailure(ctx, *bind, error.what());
            return tl::unexpected(error.code());
        } catch (const IoSystemError& error) {
            ReportDatagramFailure(ctx, *bind, error.what());
            return tl::unexpected(common::MapAsioError(error.code()));
        }
        RecordEgress(ctx, *bind);
        return {};
    }

    // Records the egress of a pooled transport reused for this request, exactly
    // as a fresh dial does (connected local address and access log).
    void RecordConnected(common::Context& ctx, const AsyncStream& stream) const;

private:
    [[nodiscard]] tl::expected<OutboundTransportTarget, common::ErrorCode>
    BuildResolvedTarget(const common::Context& ctx, std::span<const net::ip::address> addresses,
                        uint16_t port, AddressFamilyPolicy policy) const;
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, common::ErrorCode>>
    DialServerSlow(common::Context& ctx, const OutboundServer& server,
                   const OrderedBind* ordered);
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, common::ErrorCode>>
    DialDomainTarget(common::Context& ctx, const common::TargetAddress& target,
                     AddressFamilyPolicy policy);
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, common::ErrorCode>>
    DialTarget(common::Context& ctx, OutboundTransportTarget target);
    [[nodiscard]] tl::expected<net::ip::address, common::ErrorCode> SelectDatagramBind(
        const common::Context& ctx, const DatagramRemote& remote) const;
    void ReportDatagramFailure(const common::Context& ctx,
                               const net::ip::address& bind,
                               std::string_view reason) const;
    void RecordEgress(common::Context& ctx,
                      const std::optional<net::ip::address>& local) const;

    net::io_context& io_context_;
    app::DNS& dns_;
    const OutboundSenderSettings& sender_;
    TransportSecurity security_;  // Contexts for sender_.stream_settings.
    std::chrono::seconds timeout_;
};

}  // namespace transport

