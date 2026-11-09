#pragma once

#include "common/asio_types.hpp"
#include "common/defaults.hpp"
#include "common/domain_name.hpp"
#include "common/error.hpp"
#include "common/ip_address.hpp"
#include "common/target_address.hpp"
#include "transport/async_stream.hpp"
#include "common/allocator.hpp"
#include "transport/internet/outbound_bind.hpp"
#include "transport/internet/stream_settings.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <string>
#include <tl/expected.hpp>
#include <utility>
#include <vector>

namespace app::dns {
class DNS;
}  // namespace app::dns


namespace session {
struct Context;
}  // namespace session

class SslContext;

// Xray proxyman SenderSettings: how one outbound tag leaves this node. Owned by
// the proxyman outbound Handler and borrowed by its OutboundDialer; protocol
// defaults (TLS requirement, fallback SNI, ALPN) are applied when prepared.
struct OutboundSenderSettings {
    StreamSettings stream_settings;
    OutboundBind send_through;
    bool passthrough = false;
};

// A proxy protocol's next hop. The literal form is parsed once on the cold
// path; a hostname is resolved by the dialer per connection.
struct OutboundServer {
    std::string address;
    std::optional<net::ip::address> literal_address;
    uint16_t port = 0;
};

// The one validator for a configured next hop: a non-empty IP literal or DNS
// hostname and a non-zero port.
[[nodiscard]] inline tl::expected<OutboundServer, std::string_view> MakeOutboundServer(
    std::string address, uint16_t port) {
    if (address.empty()) return tl::unexpected(std::string_view("server address is required"));
    if (port == 0) return tl::unexpected(std::string_view("server port is required"));
    auto literal = iputil::ParseLiteral(address);
    if (!literal && !domain::IsValidDnsHostname(address, domain::TrailingDotPolicy::Allow)) {
        return tl::unexpected(std::string_view(
            "server address must be an IP literal or DNS hostname"));
    }
    return OutboundServer{
        .address = std::move(address),
        .literal_address = literal,
        .port = port,
    };
}

// 单个候选拨号地址
struct OutboundDialCandidate {
    tcp::endpoint endpoint;
    std::optional<net::ip::address> bind_local;  // 可按候选 IP 单独决定绑定地址
};

// 出站传输目标（仅携带已解析拨号候选）：transport/internet 的拨号输入，
// 不属于 proxy 出站协议壳。
struct OutboundTransportTarget {
    std::optional<OutboundDialCandidate> single_candidate; // 单个已解析候选，避免每连接 vector 分配
    memory::ThreadLocalVector<OutboundDialCandidate> candidates; // 已解析候选地址（按优先级排序）
    std::string_view tls_server_name;               // TLS SNI（冷路径配置视图，可空）
    memory::ThreadLocalString ws_host;              // HTTP Host/authority（WS、HTTPUpgrade、gRPC、XHTTP，已按端口格式化）
    const StreamSettings* stream_settings = nullptr; // 必填：冷路径准备好的传输层组合配置
    SslContext* security_context = nullptr;          // TLS/REALITY 时必填：出站 handler 的 Worker 私有上下文
    std::chrono::seconds timeout{defaults::kDialTimeout};

    // XHTTP packet-up / stream-up 可用独立下行入口；仅保存已解析候选和不可变配置视图。
    std::shared_ptr<const OutboundTransportTarget> xhttp_download_target;

    [[nodiscard]] std::span<const OutboundDialCandidate> Candidates() const noexcept {
        return single_candidate
            ? std::span<const OutboundDialCandidate>(&*single_candidate, 1)
            : std::span<const OutboundDialCandidate>(candidates);
    }
};

struct OutboundTargetOptions {
    app::dns::DNS* dns_service = nullptr;
    std::string_view address{};
    std::optional<net::ip::address> literal_address = std::nullopt;
    uint16_t port = 0;
    const StreamSettings* stream_settings = nullptr;
    // The outbound handler's contexts for |stream_settings|; the XHTTP
    // download leg uses its XHttpDownload() contexts.
    const TransportSecurity* security = nullptr;
    std::chrono::seconds timeout{defaults::kDialTimeout};
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
net::awaitable<tl::expected<OutboundTransportTarget, ErrorCode>>
BuildOutboundTransportTarget(OutboundTargetOptions options);

// 统一出站传输连接：
// 消费冷路径预构建候选，建立 TCP 连接，并按 StreamSettings 完成 TLS/WS。
[[nodiscard]]
net::awaitable<DialResult> DialOutboundTransport(
    net::io_context& io_context,
    session::Context& ctx,
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

    // Remote side of a native (transport-less) UDP association.
    struct DatagramRemote {
        // Known remote address; fixes the socket family.
        std::optional<net::ip::address> address;
        // Family hint when the remote is a hostname (e.g. a routing lookup).
        std::optional<net::ip::address> family_hint;
        bool accepts_v4 = true;
        bool accepts_v6 = true;
        bool prefers_v6 = false;
    };

    OutboundDialer(net::io_context& io_context,
                   app::dns::DNS& dns,
                   const OutboundSenderSettings& sender,
                   std::chrono::seconds timeout);
    OutboundDialer(const OutboundDialer&) = delete;
    OutboundDialer& operator=(const OutboundDialer&) = delete;

    [[nodiscard]] net::io_context& IoContext() const noexcept { return io_context_; }
    [[nodiscard]] app::dns::DNS& Dns() const noexcept { return dns_; }

    [[nodiscard]] bool Passthrough() const noexcept { return sender_.passthrough; }
    [[nodiscard]] ForwardedMetadataView ForwardedMetadata(
        const session::Context& ctx) const noexcept;
    ForwardedMetadataView ForwardedMetadata(
        const session::Context&& ctx) const = delete;
    // Empty unless sendThrough is Ordered.
    [[nodiscard]] std::optional<OrderedBind> SelectOrderedBind(
        const session::Context& ctx) const;
    std::optional<OrderedBind> SelectOrderedBind(
        const session::Context&& ctx) const = delete;

    // Proxy next hop through the Handler's stream settings.
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
    Dial(session::Context& ctx, const OutboundServer& server,
         const OrderedBind* ordered = nullptr);

    // Destination already resolved by protocol policy (Freedom domainStrategy);
    // candidates are tried in the given order.
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
    Dial(session::Context& ctx, std::span<const net::ip::address> addresses, uint16_t port);

    // Native UDP association: selects the sendThrough bind address, constructs
    // Endpoint(io_context, dns, bind_address, args...) and records the egress.
    template <typename Endpoint, typename... Args>
    [[nodiscard]] tl::expected<void, ErrorCode> OpenDatagram(
        session::Context& ctx, const DatagramRemote& remote,
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
            return tl::unexpected(MapAsioError(error.code()));
        }
        RecordEgress(ctx, *bind);
        return {};
    }

    // Records the egress of a pooled transport reused for this request, exactly
    // as a fresh dial does (connected local address and access log).
    void RecordConnected(session::Context& ctx, const AsyncStream& stream) const;

private:
    [[nodiscard]] net::awaitable<tl::expected<std::unique_ptr<AsyncStream>, ErrorCode>>
    DialTarget(session::Context& ctx, const OutboundTransportTarget& target);
    [[nodiscard]] tl::expected<net::ip::address, ErrorCode> SelectDatagramBind(
        const session::Context& ctx, const DatagramRemote& remote) const;
    void ReportDatagramFailure(const session::Context& ctx,
                               const net::ip::address& bind,
                               std::string_view reason) const;
    void RecordEgress(session::Context& ctx,
                      const std::optional<net::ip::address>& local) const;

    net::io_context& io_context_;
    app::dns::DNS& dns_;
    const OutboundSenderSettings& sender_;
    TransportSecurity security_;  // Contexts for sender_.stream_settings.
    std::chrono::seconds timeout_;
};

