#pragma once

#include "common/user_online_tracker.hpp"
#include "common/string_hash.hpp"
#include "app/rate_limiter.hpp"
#include "app/proxyman/user_store.hpp"
#include "app/request_load.hpp"
#include "app/stats.hpp"
#include "routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"
#include "transport/proxy_protocol.hpp"
#include "transport/quic_listener.hpp"
#include "transport/stream_settings.hpp"
#include "transport/transport_security.hpp"
#include "app/datagram_session_environment.hpp"
#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include <unordered_map>

namespace infra {

struct InboundProtocolSettings;
struct InboundUserSpec;

}  // namespace infra
namespace common {

struct OnlineDevice;

}  // namespace common
namespace transport {

class InboundTransportStreamHandler;

}  // namespace transport

namespace app {

class DNS;

// ============================================================================
// ReceiverSettings - xray-style proxyman receiver settings
//
// 对齐 xray-core app/proxyman ReceiverConfig 的职责：监听、传输、嗅探、
// 出站选择策略这些 receiver 语义。冷路径构建；inbound Handler
// 热路径只读，Dispatcher 只接收其中的窄 DispatchPolicy。
// ============================================================================
struct ReceiverSettings {
    std::string      inbound_tag;             // 主标签（map key）
    std::vector<std::string> inbound_tags;   // 所有标签（路由匹配任一）
    std::string      protocol;          // "vmess" / "trojan" 等协议名
    std::string      accounting_key{};  // Opaque stable reporting identity; empty disables per-user reporting.
    transport::StreamSettings   stream_settings;  // 传输层配置（network/security）
    routing::DispatchPolicy dispatch_policy;
    transport::ProxyProtocolMode proxy_protocol = transport::ProxyProtocolMode::Auto;

    [[nodiscard]] const std::vector<std::string>* RouteInboundTags() const noexcept {
        return inbound_tags.empty() ? nullptr : &inbound_tags;
    }
};

[[nodiscard]] inline ReceiverSettings MakeReceiverSettings(
    std::string inbound_tag,
    std::vector<std::string> inbound_tags,
    std::string protocol,
    transport::StreamSettings stream_settings,
    routing::SniffConfig sniff_config,
    transport::ProxyProtocolMode proxy_protocol,
    routing::OutboundSelectionPolicy outbound_policy,
    std::string accounting_key) {
    std::erase(inbound_tags, inbound_tag);
    return ReceiverSettings{
        .inbound_tag = std::move(inbound_tag),
        .inbound_tags = std::move(inbound_tags),
        .protocol = std::move(protocol),
        .accounting_key = std::move(accounting_key),
        .stream_settings = std::move(stream_settings),
        .dispatch_policy = {
            .sniffing = std::move(sniff_config),
            .outbound = std::move(outbound_policy),
        },
        .proxy_protocol = proxy_protocol,
    };
}

enum class DatagramHandlerBuildStatus : uint8_t {
    Unsupported,
    Failed,
    Ready,
};

enum class DatagramTransport : uint8_t {
    None,
    Packet,
    Quic,
};

struct DatagramHandlerBuildResult {
    DatagramHandlerBuildStatus status =
        DatagramHandlerBuildStatus::Unsupported;
    std::unique_ptr<::proxy::Inbound> handler;
};

// Worker-owned capabilities, borrowed by every inbound entry point.
struct AdmissionEnvironment final {
    app::GroupCoordinator& coordinator;
    app::ConnectionLimiter& limiter;
    common::UserOnlineTracker& online_users;
    app::StatsShard& stats;
};

struct InboundProtocolTraits final {
    bool mailbox_email_defaults_to_tag = false;
    bool requires_tls = false;
};


// ============================================================================
// ProxyRegistration - 入站协议注册项
// ============================================================================
struct ProxyRegistration {
    // Required when either user builder is present. This maps arbitrary
    // registration names to one concrete UserStore partition.
    std::optional<UserProtocol> user_protocol;
    DatagramTransport datagram_transport = DatagramTransport::None;

    InboundProtocolTraits traits{};

    // 创建 TCP 入站处理器（必须）
    std::unique_ptr<::proxy::Inbound> (*create_tcp_handler)(
        const AdmissionEnvironment& environment,
        const BuildRequest& req) = nullptr;

    // 创建 UDP 入站处理器（可选）
    std::unique_ptr<::proxy::Inbound> (*create_datagram_handler)(
        const AdmissionEnvironment& environment,
        const BuildRequest& req) = nullptr;
    std::unique_ptr<transport::QuicListener> (*create_quic_listener)(
        uint32_t worker_id, uint32_t worker_count, net::io_context& io,
        app::DatagramSessionEnvironment environment) = nullptr;

    // Parse protocol-specific source fields on the cold path. The returned
    // immutable type remains private to the protocol implementation.
    std::optional<std::shared_ptr<const ProtocolSettings>>
    (*prepare_settings)(
        std::string_view tag,
        const ::infra::InboundProtocolSettings& settings) = nullptr;

    // 用户构建属于冷路径，结果发布到进程级只读 UserStore 快照。所有来源共用；
    // 来源间的凭据差异只存在于 InboundProtocolSettings / InboundUserSpec 数据中。
    std::optional<UserSet> (*build_users)(
        const BuildRequest& req,
        std::span<const ::infra::InboundUserSpec> users) = nullptr;
};

// Registration errors are programming errors during static initialization and
// therefore fail fast instead of returning an ignorable status.
void RegisterProxy(std::string_view protocol, ProxyRegistration registration);

[[nodiscard]] bool HasProxy(std::string_view protocol);

[[nodiscard]] std::optional<UserProtocol> RegisteredUserProtocol(
    std::string_view protocol);

[[nodiscard]] DatagramTransport RegisteredDatagramTransport(
    std::string_view protocol);

[[nodiscard]] InboundProtocolTraits RegisteredProtocolTraits(std::string_view protocol);
[[nodiscard]] std::unique_ptr<transport::QuicListener> NewQuicListener(
    std::string_view protocol, uint32_t worker_id, uint32_t worker_count,
    net::io_context& io, app::DatagramSessionEnvironment environment);

[[nodiscard]] std::optional<BuildRequest> PrepareBuildRequest(
    std::string_view protocol,
    std::string_view tag,
    const ::infra::InboundProtocolSettings& settings);

[[nodiscard]] std::optional<UserSet> BuildUsers(
    const BuildRequest& req,
    std::span<const ::infra::InboundUserSpec> users);

// ============================================================================
// Handler - address-stable Worker inbound transport host.
// Listener descriptors may use an eagerly prepared protocol; Workers create
// protocol state only when a real logical request reaches the proxy.
// Either way each request crosses exactly one virtual Inbound::Process.
// ============================================================================
class InboundHandler final : public std::enable_shared_from_this<InboundHandler> {
public:
    // Prepared TransportSecurity is shared; SSL contexts are never rebuilt for
    // each short HTTP packet upload.
    InboundHandler(app::ReceiverSettings receiver, std::unique_ptr<proxy::Inbound> proxy,
                   const AdmissionEnvironment& environment);

    InboundHandler(const InboundHandler&) = delete;
    InboundHandler& operator=(const InboundHandler&) = delete;
    InboundHandler(InboundHandler&&) = delete;
    InboundHandler& operator=(InboundHandler&&) = delete;

    [[nodiscard]] std::string_view Tag() const noexcept {
        return receiver_.inbound_tag;
    }

    [[nodiscard]] const app::ReceiverSettings& ReceiverSettings() const noexcept {
        return receiver_;
    }
    net::awaitable<void> ProcessAcceptedTCP(
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        app::StatsShard& stats,
        app::RequestLoadState& request_load,
        const infra::TimeoutsConfig& timeouts,
        std::unique_ptr<transport::AsyncStream> raw_conn,
        common::Context& ctx,
        app::DNS* dns_service = nullptr);

    // Logical-stream sink for a transport session that authenticated its
    // client itself (Hysteria QUIC, as Xray's hysteria hub). Each delivered
    // stream runs the inbound protocol with a child of |session_ctx|
    // that keeps the session's identity and client endpoint, and takes a
    // logical admission under the session's physical |family|.
    [[nodiscard]] std::shared_ptr<transport::InboundTransportStreamHandler>
    NewAuthenticatedStreamSink(
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        app::StatsShard& stats,
        app::RequestLoadState& request_load,
        const infra::TimeoutsConfig& timeouts,
        const common::Context& session_ctx,
        std::shared_ptr<app::ConnectionLimiter::Family> family);


private:
    class LogicalTransportStreamSink;


    const app::ReceiverSettings receiver_;
    transport::TransportSecurity security_;
    std::unique_ptr<proxy::Inbound> proxy_;
    const AdmissionEnvironment& environment_;
};
using InboundHandlerPtr = std::shared_ptr<InboundHandler>;
// ============================================================================
// HandlerRegistry - per-Worker inbound handler registry
//
// 对齐 xray-core features/inbound.Manager 的职责边界。它只在 Worker 线程访问，
// 不加锁；跨线程控制面操作只能经所属 Worker 的有界 mailbox 投递。
// ============================================================================
class InboundHandlerRegistry final {
public:
    explicit InboundHandlerRegistry(const AdmissionEnvironment& environment);
    ~InboundHandlerRegistry() noexcept;

    InboundHandlerRegistry(const InboundHandlerRegistry&) = delete;
    InboundHandlerRegistry& operator=(const InboundHandlerRegistry&) = delete;

    using HandlerPtr = std::shared_ptr<InboundHandler>;

    [[nodiscard]] HandlerPtr GetHandler(std::string_view tag) noexcept;

    [[nodiscard]] std::unique_ptr<::proxy::Inbound> NewHandler(
        const BuildRequest& req);

    [[nodiscard]] DatagramHandlerBuildResult NewDatagramHandler(
        const BuildRequest& req);

    // ReplaceHandler 在所属 Worker 上替换同 tag handler。调用方持有的
    // shared_ptr 让在途物理连接及其任务组持有的逻辑子任务继续使用原 handler。
    [[nodiscard]] HandlerPtr ReplaceHandler(std::unique_ptr<InboundHandler> handler);

    // RemoveHandler 只撤销 registry 所有权；在途请求按 shared_ptr 自然收尾。
    void RemoveHandler(std::string_view tag);


private:
    using HandlerMap = std::unordered_map<
        std::string,
        std::shared_ptr<InboundHandler>,
        common::TransparentStringHash,
        common::TransparentStringEq>;

    const AdmissionEnvironment& environment_;
    HandlerMap handlers_;
};

}  // namespace app

