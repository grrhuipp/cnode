#pragma once

#include "common/allocator.hpp"
#include "common/sharded_user_stats.hpp"
#include "common/string_hash.hpp"
#include "app/rate_limiter.hpp"
#include "app/proxyman/inbound/user_store.hpp"
#include "app/stats.hpp"
#include "features/routing/dispatcher.hpp"
#include "infra/config_types.hpp"
#include "proxy/inbound.hpp"
#include "transport/async_stream.hpp"
#include "transport/internet/proxy_protocol.hpp"
#include "transport/internet/stream_settings.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

struct InboundProtocolSettings;
struct InboundUserSpec;
struct OnlineDevice;
namespace app {
// Worker-local request pressure; physical and dispatch counts are not added together.
class RequestLoadState final {
public:
    RequestLoadState(uint32_t pressure_threshold,
                     uint32_t pressure_idle_timeout) noexcept
        : pressure_threshold_(std::max<uint32_t>(pressure_threshold, 1)),
          pressure_idle_timeout_(pressure_idle_timeout) {}

    [[nodiscard]] uint32_t ActiveConnections() const noexcept {
        return std::max(physical_connections_, active_dispatches_);
    }

    [[nodiscard]] uint32_t PressureIdleTimeout() const noexcept {
        return ActiveConnections() >= pressure_threshold_
            ? pressure_idle_timeout_
            : 0;
    }

    class PhysicalConnectionScope final {
    public:
        explicit PhysicalConnectionScope(RequestLoadState& state) noexcept
            : state_(&state) {
            ++state_->physical_connections_;
        }

        ~PhysicalConnectionScope() noexcept {
            --state_->physical_connections_;
        }

        PhysicalConnectionScope(const PhysicalConnectionScope&) = delete;
        PhysicalConnectionScope& operator=(const PhysicalConnectionScope&) = delete;
        PhysicalConnectionScope(PhysicalConnectionScope&&) = delete;
        PhysicalConnectionScope& operator=(PhysicalConnectionScope&&) = delete;

    private:
        RequestLoadState* state_;
    };

    class DispatchScope final {
    public:
        explicit DispatchScope(RequestLoadState& state) noexcept
            : state_(state) {
            ++state_.active_dispatches_;
        }

        ~DispatchScope() noexcept {
            --state_.active_dispatches_;
        }

        DispatchScope(const DispatchScope&) = delete;
        DispatchScope& operator=(const DispatchScope&) = delete;
        DispatchScope(DispatchScope&&) = delete;
        DispatchScope& operator=(DispatchScope&&) = delete;

    private:
        RequestLoadState& state_;
    };

private:
    uint32_t physical_connections_ = 0;
    uint32_t active_dispatches_ = 0;
    const uint32_t pressure_threshold_;
    const uint32_t pressure_idle_timeout_;
};

namespace dns {
class DNS;
}  // namespace dns
}  // namespace app

class InboundTransportStreamHandler;

namespace proxyman::inbound {

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
    StreamSettings   stream_settings;  // 传输层配置（network/security）
    routing::DispatchPolicy dispatch_policy;
    ProxyProtocolMode proxy_protocol = ProxyProtocolMode::Auto;

    [[nodiscard]] const std::vector<std::string>* RouteInboundTags() const noexcept {
        return inbound_tags.empty() ? nullptr : &inbound_tags;
    }
};

[[nodiscard]] inline ReceiverSettings MakeReceiverSettings(
    std::string inbound_tag,
    std::vector<std::string> inbound_tags,
    std::string protocol,
    StreamSettings stream_settings,
    SniffConfig sniff_config,
    ProxyProtocolMode proxy_protocol,
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
    std::unique_ptr<::Inbound> handler;
};

// ============================================================================
// ProtocolRuntime - 每个 Worker 的协议私有可变状态
// ============================================================================
class ProtocolRuntime : public memory::WorkerAllocated {
public:
    virtual ~ProtocolRuntime() noexcept = default;

    [[nodiscard]] virtual ::UserOnlineTracker* OnlineTracker() noexcept {
        return nullptr;
    }
};

// ============================================================================
// ProxyRegistration - 入站协议注册项
// ============================================================================
struct ProxyRegistration {
    // Required when either user builder is present. This maps arbitrary
    // registration names to one concrete UserStore partition.
    std::optional<UserProtocol> user_protocol;
    DatagramTransport datagram_transport = DatagramTransport::None;

    // 创建当前 Worker 独占的协议运行态（必须），对象与运行态取自该 Worker 池。
    std::unique_ptr<ProtocolRuntime> (*create_runtime)(memory::worker_memory& pool) = nullptr;

    // 创建 TCP 入站处理器（必须）
    std::unique_ptr<::Inbound> (*create_tcp_handler)(
        ProtocolRuntime& runtime,
        ::StatsShard& stats,
        ::ConnectionLimiter* limiter,
        const BuildRequest& req,
        memory::worker_memory& pool) = nullptr;

    // 创建 UDP 入站处理器（可选）
    std::unique_ptr<::Inbound> (*create_datagram_handler)(
        ProtocolRuntime& runtime,
        ::StatsShard& stats,
        ::ConnectionLimiter* limiter,
        const BuildRequest& req,
        memory::worker_memory& pool) = nullptr;

    // Parse protocol-specific source fields on the cold path. The returned
    // immutable type remains private to the protocol implementation.
    std::optional<std::shared_ptr<const ProtocolSettings>>
    (*prepare_settings)(
        std::string_view tag,
        const ::InboundProtocolSettings& settings) = nullptr;

    // 用户构建属于冷路径，结果发布到进程级只读 UserStore 快照。所有来源共用；
    // 来源间的凭据差异只存在于 InboundProtocolSettings / InboundUserSpec 数据中。
    std::optional<UserSet> (*build_users)(
        const BuildRequest& req,
        std::span<const ::InboundUserSpec> users) = nullptr;
};

// Registration errors are programming errors during static initialization and
// therefore fail fast instead of returning an ignorable status.
void RegisterProxy(std::string_view protocol, ProxyRegistration registration);

[[nodiscard]] bool HasProxy(std::string_view protocol);

[[nodiscard]] std::optional<UserProtocol> RegisteredUserProtocol(
    std::string_view protocol);

[[nodiscard]] DatagramTransport RegisteredDatagramTransport(
    std::string_view protocol);
[[nodiscard]] std::unique_ptr<ProtocolRuntime> NewProtocolRuntime(
    std::string_view protocol,
    memory::worker_memory& pool);

[[nodiscard]] std::unique_ptr<::Inbound> NewHandler(
    std::string_view protocol,
    ProtocolRuntime& runtime,
    ::StatsShard& stats,
    ::ConnectionLimiter* limiter,
    const BuildRequest& req,
    memory::worker_memory& pool);

[[nodiscard]] DatagramHandlerBuildResult NewDatagramHandler(
    std::string_view protocol,
    ProtocolRuntime& runtime,
    ::StatsShard& stats,
    ::ConnectionLimiter* limiter,
    const BuildRequest& req,
    memory::worker_memory& pool);

[[nodiscard]] std::optional<BuildRequest> PrepareBuildRequest(
    std::string_view protocol,
    std::string_view tag,
    const ::InboundProtocolSettings& settings);

[[nodiscard]] std::optional<UserSet> BuildUsers(
    const BuildRequest& req,
    std::span<const ::InboundUserSpec> users);

// ============================================================================
// Handler - address-stable Worker inbound transport host.
// Listener descriptors may use an eagerly prepared protocol; Workers create
// protocol state only when a real logical request reaches the proxy.
// Either way each request crosses exactly one virtual Inbound::Process.
// ============================================================================
class Handler final
    : public memory::WorkerAllocated
    , public std::enable_shared_from_this<Handler> {
public:
    // Prepared TransportSecurity is shared; SSL contexts are never rebuilt for
    // each short HTTP packet upload.
    Handler(inbound::ReceiverSettings receiver, std::unique_ptr<Inbound> proxy,
            ConnectionLimiter& limiter);

    Handler(const Handler&) = delete;
    Handler& operator=(const Handler&) = delete;
    Handler(Handler&&) = delete;
    Handler& operator=(Handler&&) = delete;

    [[nodiscard]] std::string_view Tag() const noexcept {
        return receiver_.inbound_tag;
    }

    [[nodiscard]] const inbound::ReceiverSettings& ReceiverSettings() const noexcept {
        return receiver_;
    }
    net::awaitable<void> ProcessAcceptedTCP(
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        StatsShard& stats,
        app::RequestLoadState& request_load,
        const TimeoutsConfig& timeouts,
        std::unique_ptr<AsyncStream> raw_conn,
        session::Context& ctx,
        app::dns::DNS* dns_service = nullptr);

    // Logical-stream sink for a transport session that authenticated its
    // client itself (Hysteria QUIC, as Xray's hysteria hub). Each delivered
    // stream runs the inbound protocol with a child of |session_ctx|
    // that keeps the session's identity and client endpoint, and takes a
    // logical admission under the session's physical |family|.
    [[nodiscard]] std::shared_ptr<InboundTransportStreamHandler>
    NewAuthenticatedStreamSink(
        net::io_context& io_context,
        routing::Dispatcher& dispatcher,
        StatsShard& stats,
        app::RequestLoadState& request_load,
        const TimeoutsConfig& timeouts,
        const session::Context& session_ctx,
        std::shared_ptr<ConnectionLimiter::Family> family);


private:
    class LogicalTransportStreamSink;

    Inbound& Proxy();

    const inbound::ReceiverSettings receiver_;
    TransportSecurity security_;
    std::unique_ptr<Inbound> proxy_;
    ConnectionLimiter& limiter_;
};

// ============================================================================
// HandlerRegistry - per-Worker inbound handler registry
//
// 对齐 xray-core features/inbound.Manager 的职责边界。它只在 Worker 线程访问，
// 不加锁；跨线程控制面操作只能经所属 Worker 的有界 mailbox 投递。
// ============================================================================
class HandlerRegistry final : public memory::WorkerAllocated {
public:
    HandlerRegistry(memory::worker_memory& pool, StatsShard& stats);
    ~HandlerRegistry() noexcept;

    HandlerRegistry(const HandlerRegistry&) = delete;
    HandlerRegistry& operator=(const HandlerRegistry&) = delete;

    using HandlerPtr = std::shared_ptr<Handler>;

    [[nodiscard]] HandlerPtr GetHandler(std::string_view tag) noexcept;

    [[nodiscard]] std::unique_ptr<::Inbound> NewHandler(
        ::ConnectionLimiter* limiter,
        const BuildRequest& req);

    [[nodiscard]] DatagramHandlerBuildResult NewDatagramHandler(
        ::ConnectionLimiter* limiter,
        const BuildRequest& req);
    [[nodiscard]] ProtocolRuntime* GetOrCreateRuntime(
        std::string_view protocol);

    // ReplaceHandler 在所属 Worker 上替换同 tag handler。调用方持有的
    // shared_ptr 让在途物理连接及其任务组持有的逻辑子任务继续使用原 handler。
    [[nodiscard]] HandlerPtr ReplaceHandler(std::unique_ptr<Handler> handler);

    // RemoveHandler 只撤销 registry 所有权；在途请求按 shared_ptr 自然收尾。
    void RemoveHandler(std::string_view tag);

    [[nodiscard]] std::vector<::OnlineDevice>
    GetOnlineDevices(std::string_view protocol, std::string_view tag) const;

private:
    using HandlerMap = memory::UnorderedMap<
        memory::String,
        std::shared_ptr<Handler>,
        TransparentStringHash,
        TransparentStringEq>;
    using RuntimeMap = memory::UnorderedMap<
        memory::String,
        std::unique_ptr<ProtocolRuntime>,
        TransparentStringHash,
        TransparentStringEq>;

    memory::worker_memory& pool_;
    StatsShard& stats_;
    RuntimeMap runtimes_;
    HandlerMap handlers_;
};

}  // namespace proxyman::inbound

class UserOnlineTracker;
namespace app {

struct DatagramSessionEnvironment final {
    TimeoutsConfig timeouts;
    routing::Dispatcher* dispatcher = nullptr;
    StatsShard* stats = nullptr;
    ConnectionLimiter* limiter = nullptr;
    RequestLoadState* request_load = nullptr;
    UserOnlineTracker* tracker = nullptr;
    uint32_t* active_sessions = nullptr;
    std::shared_ptr<proxyman::inbound::Handler> handler{};
    std::shared_ptr<const proxyman::inbound::BuildRequest> prepared{};
};

} // namespace app
