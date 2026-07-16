#include "acppnode/app/worker.hpp"
#include "acppnode/app/port_binding.hpp"
#include "acppnode/app/proxyman/inbound/receiver_settings.hpp"
#include "acppnode/app/traffic_types.hpp"
#include "acppnode/app/worker_runtime_config.hpp"
#include "acppnode/app/worker_stats.hpp"
#include "acppnode/common/session.hpp"
#include "acppnode/common/rule.hpp"
#include "acppnode/common/allocator.hpp"
#include "acppnode/common/buf/multi_buffer.hpp"
#include "acppnode/common/ip_utils.hpp"
#include "acppnode/common/container_util.hpp"
#include "acppnode/common/online_device.hpp"
#include "acppnode/common/string_hash.hpp"
#include "acppnode/infra/log.hpp"
#include "acppnode/app/dispatcher/default_dispatcher.hpp"
#include "acppnode/app/mux_session_handler.hpp"
#include "acppnode/app/proxyman/inbound/manager.hpp"
#include "acppnode/app/proxyman/inbound/factory.hpp"
#include "acppnode/app/proxyman/inbound/tcp_worker.hpp"
#include "acppnode/app/proxyman/inbound/udp_worker.hpp"
#include "acppnode/app/proxyman/outbound/manager.hpp"
#include "acppnode/app/session_tracking.hpp"
#include "acppnode/app/dns/dns.hpp"
#include "acppnode/app/proxyman/outbound/factory.hpp"
#include "acppnode/app/udp_session.hpp"
#include "acppnode/transport/internet/tcp_stream.hpp"
#include "acppnode/transport/internet/timeout_scheduler.hpp"
#include "acppnode/app/router/router.hpp"
#include "acppnode/common/error.hpp"
#include "acppnode/app/proxyman/inbound/handler.hpp"
#include "acppnode/proxy/inbound.hpp"

#ifndef _WIN32
#include <sys/socket.h>
#endif
#include <algorithm>
#include <chrono>
#include <cstring>
#include <format>
#include <atomic>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>

namespace acpp {

struct Worker::ListenerSlot {
    // Worker 线程内稳定的 per-tag slot。AcceptLoop 持有 slot 指针；
    // 配置热更新只替换当前 inbound handler；每个已接受连接复制 shared_ptr，
    // 让 HTTP/2/gRPC/XHTTP detached 逻辑子流覆盖 handler 的完整生命周期。
    std::shared_ptr<proxyman::inbound::Handler> handler;
    std::unique_ptr<proxyman::inbound::TcpWorker> tcp_worker;
    std::optional<PortBinding> tcp_binding;
    std::optional<PortBinding> udp_binding;
};

struct Worker::ListenerState : proxyman::inbound::UdpReplySink {
    using ListenerSlotMap =
        memory::ThreadLocalUnorderedMap<std::string, ListenerSlot>;
    using ListenerKeys = memory::ThreadLocalVector<std::string>;

    memory::ThreadLocalUnorderedMap<std::string, std::string> tcp_listener_tags;
    ListenerSlotMap listener_slots;
    memory::ThreadLocalUnorderedMap<std::string, std::string> udp_socket_tags;
    memory::ThreadLocalUnorderedMap<std::string, std::unique_ptr<proxyman::inbound::UdpWorker>>
        udp_workers;

    [[nodiscard]] bool StartListening(Worker& worker, const PortBinding& binding);
    [[nodiscard]] ListenerKeys CollectTcpListenerKeys(const std::string& tag) const;
    void StopListening(const std::string& tag,
                       ListenerKeys listener_keys) noexcept;
    [[nodiscard]] bool StartUdpListening(
        Worker& worker,
        const PortBinding& binding,
        std::unique_ptr<proxyman::inbound::UdpHandler> handler);
    [[nodiscard]] ListenerKeys CollectUdpSocketKeys(const std::string& tag) const;
    void ResetUdpListening(const std::string& tag,
                           ListenerKeys socket_keys) noexcept;
    void StopUdpListening(const std::string& tag,
                          ListenerKeys socket_keys) noexcept;
    void Shutdown();
    void DrainRetiredOutboundsIfIdle(Worker& worker);

    net::awaitable<void> AcceptLoop(
        Worker& worker,
        std::string listener_key,
        std::string tag,
        tcp::acceptor* acceptor,
        ListenerSlot* slot);

    net::awaitable<void> ProcessReceivedConnection(
        Worker& worker,
        tcp::socket socket,
        tcp::endpoint remote_ep,
        std::shared_ptr<proxyman::inbound::Handler> inbound_handler);

    net::awaitable<void> UdpReceiveLoop(
        Worker& worker,
        std::string socket_key,
        std::string tag,
        ListenerSlot* listener_slot);

    [[nodiscard]] proxyman::inbound::UdpWorker*
    FindUdpWorkerBySocketKey(const std::string& socket_key) noexcept;
    [[nodiscard]] const proxyman::inbound::UdpWorker*
    FindUdpWorkerBySocketKey(const std::string& socket_key) const noexcept;

    void EnqueueUdpReply(const std::string& tag,
                         udp::socket* sock,
                         udp::endpoint endpoint,
                         std::span<const uint8_t> payload,
                         uint32_t worker_id);
    void EnqueueUdpReply(const std::string& tag,
                         udp::socket* sock,
                         udp::endpoint endpoint,
                         buf::MultiBuffer payload,
                         uint32_t worker_id) override;
    void EnqueueUdpReply(const std::string& tag,
                         udp::socket* sock,
                         udp::endpoint endpoint,
                         buf::BufferGuard payload,
                         uint32_t worker_id);
    void StartUdpReplySend(const std::string& tag,
                           udp::socket* sock,
                           uint32_t worker_id);
};

struct Worker::RuntimeState {
    RuntimeState(net::io_context& io_context,
                 const WorkerRuntimeConfig& runtime_config,
                 StatsShard& stats_ref,
                 geo::GeoManager* geo_manager_ref)
        : io_context(io_context)
        , runtime_snapshot(std::make_shared<WorkerRuntimeConfig>(runtime_config))
        , stats(stats_ref)
        , geo_manager(geo_manager_ref)
        , listener_state(std::make_unique<ListenerState>())
        , inbound_manager(std::make_unique<proxyman::inbound::Manager>(stats))
        , session_tracking(std::make_unique<app::SessionTrackingState>())
        , dns_service(std::make_unique<app::dns::DNS>(io_context, runtime_config.dns))
        , udp_session_manager(std::make_unique<UDPSessionManager>(
              io_context,
              *dns_service,
              runtime_config.timeouts.SessionIdleTimeout()))
        , outbound_manager(std::make_unique<proxyman::outbound::Manager>())
        , router(std::make_unique<app::router::Router>())
        , rule_manager(std::make_unique<rule::Manager>())
        , mux_session_handler(std::make_unique<app::MuxSessionHandler>())
        , dispatcher(std::make_unique<app::dispatcher::DefaultDispatcher>()) {}

    [[nodiscard]] std::shared_ptr<const WorkerRuntimeConfig> Snapshot() const {
        return runtime_snapshot.load(std::memory_order_acquire);
    }

    void StoreSnapshot(std::shared_ptr<const WorkerRuntimeConfig> snapshot) noexcept {
        runtime_snapshot.store(std::move(snapshot), std::memory_order_release);
    }

    void InitOutbounds(Worker& worker,
                       const std::vector<proxyman::outbound::PreparedOutboundConfig>& outbounds);
    void InitRouter(Worker& worker,
                    const RoutingConfig& routing,
                    std::string_view default_outbound_tag,
                    geo::GeoManager* geo_manager_ref);

    net::io_context& io_context;
    std::atomic<std::shared_ptr<const WorkerRuntimeConfig>> runtime_snapshot;
    StatsShard& stats;
    geo::GeoManager* geo_manager = nullptr;
    uint32_t active_connections = 0;

    std::unique_ptr<ListenerState> listener_state;
    std::unique_ptr<proxyman::inbound::Manager> inbound_manager;
    std::unique_ptr<app::SessionTrackingState> session_tracking;
    std::unique_ptr<app::dns::DNS> dns_service;
    std::unique_ptr<UDPSessionManager> udp_session_manager;
    std::unique_ptr<proxyman::outbound::Manager> outbound_manager;
    std::unique_ptr<app::router::Router> router;
    std::unique_ptr<rule::Manager> rule_manager;
    std::unique_ptr<app::MuxSessionHandler> mux_session_handler;
    std::unique_ptr<app::dispatcher::DefaultDispatcher> dispatcher;
};

namespace {

constexpr auto kAcceptErrorBackoff = std::chrono::milliseconds(5);
constexpr auto kAcceptResourceBackoff = std::chrono::milliseconds(100);

std::string BuildListenerKey(std::string_view tag, std::string_view listen, uint16_t port) {
    std::string key;
    key.reserve(tag.size() + listen.size() + 12);
    key.append(tag);
    key.push_back('|');
    key.append(listen);
    key.push_back('|');
    key.append(std::to_string(port));
    return key;
}

void RemoveInboundRuntimeFromSnapshot(WorkerRuntimeConfig& snapshot, std::string_view tag) {
    std::erase_if(snapshot.static_inbounds, [&](const StaticInboundRuntimeEntry& entry) {
        return entry.tag == tag;
    });
}

void ApplyProxyProtocolResult(
    uint32_t worker_id,
    session::Context& ctx,
    const tcp::endpoint& remote_ep,
    const ProxyProtocolResult& result) {
    if (!result.success()) {
        return;
    }

    if (result.src_addr) {
        const auto src_addr = iputil::NormalizeAddress(*result.src_addr);
        ctx.inbound.source_addr = src_addr;
        ctx.inbound.source_ip = src_addr.to_string();
        ctx.inbound.source_port = result.src_port;
        LOG_CONN_DEBUG(ctx, "[{}] PROXY protocol: proxy={} real_ip={}:{}",
                       ctx.inbound.tag, iputil::NormalizeAddressString(remote_ep.address()),
                       ctx.inbound.source_ip, result.src_port);
    } else if (!result.src_ip.empty()) {
        ctx.inbound.source_addr = net::ip::address{};
        ctx.inbound.source_ip = result.src_ip;
        ctx.inbound.source_port = result.src_port;
        LOG_CONN_DEBUG(ctx, "[{}] PROXY protocol: proxy={} real_ip={}:{}",
                       ctx.inbound.tag, iputil::NormalizeAddressString(remote_ep.address()),
                       ctx.inbound.source_ip, result.src_port);
    }
}

}  // namespace

// ============================================================================
// Worker 构造 / 析构
// ============================================================================

Worker::Worker(uint32_t id, net::io_context& io_context,
               const WorkerRuntimeConfig& runtime_config, StatsShard& stats,
               geo::GeoManager* geo_manager)
    : id_(id)
    , runtime_(std::make_unique<RuntimeState>(io_context, runtime_config, stats, geo_manager)) {
    runtime_->dispatcher->BindRuleManager(*runtime_->rule_manager);
    runtime_->dispatcher->BindSessionTracking(*runtime_->session_tracking);
    runtime_->dispatcher->BindDnsService(*runtime_->dns_service);
    runtime_->dispatcher->BindMuxSessionHandler(*runtime_->mux_session_handler);
    runtime_->udp_session_manager->StartCleanup();
    const auto runtime_snapshot = runtime_->Snapshot();
    LOG_DEBUG("Worker[{}]: UDP session manager initialized (timeout={}s)",
              id_, runtime_snapshot->timeouts.SessionIdleTimeout().count());
    runtime_->InitOutbounds(*this, runtime_snapshot->outbounds);
    runtime_->dispatcher->BindOutboundManager(*runtime_->outbound_manager);
    const std::string_view default_outbound_tag = runtime_snapshot->default_outbound_tag.empty()
        ? std::string_view(constants::protocol::kDirect)
        : std::string_view(runtime_snapshot->default_outbound_tag);
    runtime_->InitRouter(*this, runtime_snapshot->routing, default_outbound_tag, geo_manager);
}

Worker::~Worker() = default;

net::io_context::executor_type Worker::GetExecutor() {
    return runtime_->io_context.get_executor();
}

// ============================================================================
// 初始化
// ============================================================================

void Worker::RuntimeState::InitOutbounds(
    Worker& worker,
    const std::vector<proxyman::outbound::PreparedOutboundConfig>& outbounds) {
    outbound_manager->Clear();
    const auto snapshot = Snapshot();
    const auto dial_timeout = snapshot->timeouts.DialTimeout();

    for (const auto& prepared_outbound : outbounds) {
        auto handler = proxyman::outbound::NewHandler(
            prepared_outbound, worker.runtime_->io_context,
            *dns_service, udp_session_manager.get(),
            dial_timeout);

        if (!outbound_manager->AddHandler(std::move(handler))) {
            throw std::logic_error(
                "failed to install prepared outbound '" +
                prepared_outbound.tag + "'");
        }
        LOG_DEBUG("Worker[{}]: registered {} outbound '{}'",
                  worker.id_, prepared_outbound.protocol, prepared_outbound.tag);
    }
}

void Worker::RuntimeState::InitRouter(
    Worker& worker,
    const RoutingConfig& routing,
    std::string_view default_outbound_tag,
    geo::GeoManager* geo_manager_ref) {
    router->Configure(routing, default_outbound_tag, geo_manager_ref);
    dispatcher->BindRouter(*router);

    LOG_DEBUG("Worker[{}]: router initialized, {} rules, default='{}'",
              worker.id_, routing.rules.size(), router->DefaultOutbound());
}

// ============================================================================
// SO_REUSEPORT 监听管理（仅在 Worker io_context 上调用）
// ============================================================================

bool Worker::ListenerState::StartListening(Worker& worker, const PortBinding& binding) {
#ifdef _WIN32
    // Windows has no SO_REUSEPORT-equivalent listener distribution.  Keep the
    // accepted socket on its owning Worker instead of exporting Worker pointers
    // and native handles across io_context boundaries.
    if (worker.Id() != 0) {
        return true;
    }
#endif

    auto inbound_handler = worker.runtime_->inbound_manager->GetHandler(binding.tag);
    if (!inbound_handler) {
        LOG_ERROR("Worker[{}]: TCP listener tag={} has no inbound handler",
                  worker.id_, binding.tag);
        return false;
    }

    const bool replacing = std::ranges::any_of(
        tcp_listener_tags,
        [&](const auto& item) { return item.second == binding.tag; });
    auto existing_slot = listener_slots.find(binding.tag);
    if (replacing && existing_slot != listener_slots.end() &&
        existing_slot->second.tcp_worker &&
        existing_slot->second.tcp_binding &&
        existing_slot->second.tcp_binding->UsesSameSocket(binding)) {
        return true;
    }

    PortBinding committed_binding = binding;
    if (replacing) {
        LOG_WARN("Worker[{}]: replacing existing TCP listeners tag={}", worker.id_, binding.tag);
        StopListening(binding.tag, CollectTcpListenerKeys(binding.tag));
    }

    auto& listener_slot = listener_slots[binding.tag];
    if (!listener_slot.tcp_worker) {
        listener_slot.tcp_worker = std::make_unique<proxyman::inbound::TcpWorker>(binding.tag);
    }
    auto& tcp_worker = *listener_slot.tcp_worker;
    const auto fail_listener = [&]() -> bool {
        tcp_worker.Close();
        listener_slot.tcp_worker.reset();
        listener_slot.tcp_binding.reset();
        return false;
    };

    const auto listen_candidates = binding.listen.Candidates();
    size_t bound_count = 0;

    for (const auto& addr : listen_candidates) {
        const std::string listen_addr = addr.to_string();
        IoErrorCode ec;

        tcp::endpoint ep(addr, binding.port);
        const std::string listener_key = BuildListenerKey(binding.tag, listen_addr, binding.port);
        tcp::acceptor* candidate_acceptor =
            tcp_worker.CreateAcceptor(listener_key, worker.runtime_->io_context);
        if (!candidate_acceptor) {
            LOG_ERROR("Worker[{}]: failed to create TCP acceptor tag={} key={}",
                      worker.id_, binding.tag, listener_key);
            continue;
        }

        auto fail_candidate = [&](std::string_view op, std::string_view msg) -> bool {
            tcp_worker.CloseAcceptor(listener_key);
            if (listen_candidates.size() > 1) {
                LOG_WARN("Worker[{}]: TCP {} {} failed: {}, continuing dual-stack bind",
                         worker.id_,
                         op,
                         iputil::FormatEndpointForLog(listen_addr, binding.port),
                         msg);
                return true;
            }
            LOG_ERROR("Worker[{}]: TCP {} {} failed: {}",
                      worker.id_, op,
                      iputil::FormatEndpointForLog(listen_addr, binding.port),
                      msg);
            return false;
        };

        candidate_acceptor->open(ep.protocol(), ec);
        if (ec) {
            if (fail_candidate("open", ec.message())) continue;
            return fail_listener();
        }

        if (addr.is_v6()) {
            candidate_acceptor->set_option(net::ip::v6_only(true), ec);
            if (ec) {
                if (fail_candidate("set IPV6_V6ONLY", ec.message())) continue;
                return fail_listener();
            }
        }

        candidate_acceptor->set_option(net::socket_base::reuse_address(true), ec);

#ifndef _WIN32
        // SO_REUSEPORT：每 Worker 独立 accept，内核负责负载均衡。
        int optval = 1;
        if (::setsockopt(candidate_acceptor->native_handle(), SOL_SOCKET, SO_REUSEPORT,
                         &optval, sizeof(optval)) < 0) {
            if (fail_candidate("SO_REUSEPORT", strerror(errno))) continue;
            return fail_listener();
        }
#endif

        candidate_acceptor->bind(ep, ec);
        if (ec) {
            if (fail_candidate("bind", ec.message())) continue;
            return fail_listener();
        }

        candidate_acceptor->listen(net::socket_base::max_listen_connections, ec);
        if (ec) {
            if (fail_candidate("listen", ec.message())) continue;
            return fail_listener();
        }

        tcp::acceptor* acceptor = candidate_acceptor;
        if (!acceptor) {
            LOG_ERROR("Worker[{}]: failed to attach TCP acceptor tag={} key={}",
                      worker.id_, binding.tag, listener_key);
            continue;
        }
        tcp_listener_tags.emplace(listener_key, binding.tag);

        net::co_spawn(worker.runtime_->io_context.get_executor(),
                      AcceptLoop(worker, listener_key, binding.tag, acceptor, &listener_slot),
                      [](std::exception_ptr) {});

        ++bound_count;
        LOG_DEBUG("worker.listener ready worker={} endpoint={} tag={} protocol={} accept=SO_REUSEPORT",
                  worker.id_,
                  iputil::FormatEndpointForLog(listen_addr, binding.port),
                  binding.tag,
                  binding.protocol);
    }

    if (bound_count == 0) {
        LOG_ERROR("Worker[{}]: no TCP listener bound tag={} protocol={}",
                  worker.id_, binding.tag, binding.protocol);
        return fail_listener();
    }
    listener_slot.tcp_binding = std::move(committed_binding);
    return true;
}

Worker::ListenerState::ListenerKeys
Worker::ListenerState::CollectTcpListenerKeys(const std::string& tag) const {
    ListenerKeys listener_keys;
    for (const auto& [listener_key, listener_tag] : tcp_listener_tags) {
        if (listener_tag == tag) {
            listener_keys.push_back(listener_key);
        }
    }
    return listener_keys;
}

void Worker::ListenerState::StopListening(
    const std::string& tag,
    ListenerKeys listener_keys) noexcept {
    if (listener_keys.empty()) return;

    auto slot_it = listener_slots.find(tag);
    for (const auto& listener_key : listener_keys) {
        if (slot_it != listener_slots.end() && slot_it->second.tcp_worker) {
            slot_it->second.tcp_worker->CloseAcceptor(listener_key);  // 使 AcceptLoop 收到 operation_aborted 退出
        }
        tcp_listener_tags.erase(listener_key);
    }
    MaybeShrinkHashContainer(tcp_listener_tags, 8);
    if (slot_it != listener_slots.end()) {
        slot_it->second.tcp_binding.reset();
    }
}

proxyman::inbound::UdpWorker*
Worker::ListenerState::FindUdpWorkerBySocketKey(const std::string& socket_key) noexcept {
    auto tag_it = udp_socket_tags.find(socket_key);
    if (tag_it == udp_socket_tags.end()) {
        return nullptr;
    }
    auto worker_it = udp_workers.find(tag_it->second);
    if (worker_it == udp_workers.end() || !worker_it->second) {
        return nullptr;
    }
    return worker_it->second.get();
}

const proxyman::inbound::UdpWorker*
Worker::ListenerState::FindUdpWorkerBySocketKey(const std::string& socket_key) const noexcept {
    auto tag_it = udp_socket_tags.find(socket_key);
    if (tag_it == udp_socket_tags.end()) {
        return nullptr;
    }
    auto worker_it = udp_workers.find(tag_it->second);
    if (worker_it == udp_workers.end() || !worker_it->second) {
        return nullptr;
    }
    return worker_it->second.get();
}

Worker::ListenerState::ListenerKeys
Worker::ListenerState::CollectUdpSocketKeys(const std::string& tag) const {
    ListenerKeys socket_keys;
    for (const auto& [socket_key, socket_tag] : udp_socket_tags) {
        if (socket_tag == tag) {
            socket_keys.push_back(socket_key);
        }
    }
    return socket_keys;
}

void Worker::ListenerState::ResetUdpListening(
    const std::string& tag,
    ListenerKeys socket_keys) noexcept {
    for (const auto& socket_key : socket_keys) {
        if (auto* udp_worker = FindUdpWorkerBySocketKey(socket_key)) {
            udp_worker->CloseSocket(socket_key);
        }

        udp_socket_tags.erase(socket_key);
    }

    MaybeShrinkHashContainer(udp_socket_tags, 8);
    if (auto it = udp_workers.find(tag); it != udp_workers.end()) {
        if (it->second) {
            it->second->Close();
        }
        it->second.reset();
    }
    if (auto slot_it = listener_slots.find(tag);
            slot_it != listener_slots.end()) {
        slot_it->second.udp_binding.reset();
    }
}

void Worker::ListenerState::StopUdpListening(
    const std::string& tag,
    ListenerKeys socket_keys) noexcept {
    ResetUdpListening(tag, std::move(socket_keys));
    udp_workers.erase(tag);
}

void Worker::ListenerState::Shutdown() {
    while (!tcp_listener_tags.empty()) {
        const std::string tag = tcp_listener_tags.begin()->second;
        StopListening(tag, CollectTcpListenerKeys(tag));
    }
    while (!udp_workers.empty()) {
        const std::string tag = udp_workers.begin()->first;
        StopUdpListening(tag, CollectUdpSocketKeys(tag));
    }
    while (!udp_socket_tags.empty()) {
        const std::string tag = udp_socket_tags.begin()->second;
        StopUdpListening(tag, CollectUdpSocketKeys(tag));
    }
}

void Worker::ListenerState::EnqueueUdpReply(const std::string& tag,
                                            udp::socket* sock,
                                            udp::endpoint endpoint,
                                            std::span<const uint8_t> payload,
                                            uint32_t worker_id) {
    if (payload.empty()) {
        return;
    }

    buf::MultiBuffer mb;
    mb.reserve((payload.size() + buf::Buffer::kSize - 1) / buf::Buffer::kSize);
    size_t offset = 0;
    while (offset < payload.size()) {
        buf::BufferGuard buffer{buf::Buffer::New()};
        if (!buffer) {
            return;
        }
        const size_t n = std::min(payload.size() - offset,
                                  static_cast<size_t>(buffer->Available()));
        std::memcpy(buffer->Tail().data(), payload.data() + offset, n);
        buffer->Produce(static_cast<uint32_t>(n));
        mb.push_back(buffer.release());
        offset += n;
    }
    EnqueueUdpReply(tag, sock, std::move(endpoint), std::move(mb), worker_id);
}

void Worker::ListenerState::EnqueueUdpReply(const std::string& tag,
                                            udp::socket* sock,
                                            udp::endpoint endpoint,
                                            buf::MultiBuffer payload,
                                            uint32_t worker_id) {
    auto* udp_worker = FindUdpWorkerBySocketKey(tag);
    auto* current_sock = udp_worker ? udp_worker->FindSocket(tag) : nullptr;
    if (current_sock != sock || !sock || !sock->is_open() || payload.empty()) {
        return;
    }

    if (udp_worker->EnqueueReply(tag, std::move(endpoint), std::move(payload))) {
        StartUdpReplySend(tag, sock, worker_id);
    }
}

void Worker::ListenerState::EnqueueUdpReply(const std::string& tag,
                                            udp::socket* sock,
                                            udp::endpoint endpoint,
                                            buf::BufferGuard payload,
                                            uint32_t worker_id) {
    auto* udp_worker = FindUdpWorkerBySocketKey(tag);
    auto* current_sock = udp_worker ? udp_worker->FindSocket(tag) : nullptr;
    if (current_sock != sock || !sock || !sock->is_open() || !payload || payload->IsEmpty()) {
        return;
    }

    if (udp_worker->EnqueueReply(tag, std::move(endpoint), std::move(payload))) {
        StartUdpReplySend(tag, sock, worker_id);
    }
}

void Worker::ListenerState::StartUdpReplySend(const std::string& tag,
                                              udp::socket* sock,
                                              uint32_t worker_id) {
    auto* udp_worker = FindUdpWorkerBySocketKey(tag);
    auto* current_sock = udp_worker ? udp_worker->FindSocket(tag) : nullptr;
    if (current_sock != sock ||
        !sock || !sock->is_open()) {
        return;
    }

    auto packet = udp_worker->BeginReplySend(tag);
    if (!packet) {
        return;
    }

    const auto send_buffers =
        proxyman::inbound::UdpWorker::ReplySendBuffers(*packet);
    const auto endpoint =
        proxyman::inbound::UdpWorker::ReplyEndpoint(*packet);

    sock->async_send_to(
        send_buffers,
        endpoint,
        [this, tag, sock, packet = std::move(packet), worker_id](IoErrorCode ec, size_t /*bytes_sent*/) {
            auto* udp_worker = FindUdpWorkerBySocketKey(tag);
            if (!udp_worker) {
                return;
            }

            if (ec && ec != io_error::operation_aborted) {
                LOG_ACCESS_DEBUG("Worker[{}]: UDP reply send failed tag={}: {}",
                                 worker_id, tag, ec.message());
            }

            const bool current_sock =
                udp_worker->FindSocket(tag) == sock;

            const bool has_pending = udp_worker->CompleteReplySend(tag);
            if (has_pending && current_sock && sock && sock->is_open()) {
                StartUdpReplySend(tag, sock, worker_id);
            }
        });
}

// ============================================================================
// AcceptLoop — 每个 TCP socket 一个协程，运行在 Worker io_context 上
// ============================================================================

net::awaitable<void> Worker::ListenerState::AcceptLoop(
    Worker& worker,
    std::string listener_key,
    std::string tag,
    tcp::acceptor* acceptor,
    ListenerSlot* slot) {
    while (true) {
        if (!acceptor) co_return;

        auto [ec, socket] = co_await acceptor->async_accept(
            net::as_tuple(net::use_awaitable));

        if (ec == io_error::operation_aborted) co_return;
        if (ec) {
            if (!slot || !slot->tcp_worker ||
                slot->tcp_worker->FindAcceptor(listener_key) != acceptor) {
                co_return;
            }
            LOG_WARN("Worker[{}]: accept error tag={}: {}", worker.id_, tag, ec.message());
            const auto backoff = MapAsioError(ec) == ErrorCode::RESOURCE_EXHAUSTED
                ? kAcceptResourceBackoff
                : kAcceptErrorBackoff;
            ScheduledSleep sleep(worker.runtime_->io_context);
            co_await sleep.WaitFor(
                std::chrono::duration_cast<std::chrono::milliseconds>(backoff));
            continue;
        }

        // 获取远端地址（可能失败，不影响接受）
        tcp::endpoint remote_ep;
        IoErrorCode ep_ec;
        remote_ep = socket.remote_endpoint(ep_ec);

        auto inbound_handler = slot ? slot->handler : nullptr;
        if (!inbound_handler) {
            LOG_ERROR("Worker[{}]: no inbound handler for tag={}", worker.id_, tag);
            socket.close();
            continue;
        }

        ++worker.runtime_->active_connections;

        net::co_spawn(worker.runtime_->io_context.get_executor(),
                      ProcessReceivedConnection(
                          worker, std::move(socket), remote_ep,
                          std::move(inbound_handler)),
                      [&worker](std::exception_ptr ep) {
                          if (ep) {
                              try {
                                  std::rethrow_exception(ep);
                              } catch (const std::exception& e) {
                                  LOG_ERROR("Worker[{}]: TCP connection coroutine failed: {}",
                                            worker.id_, e.what());
                              } catch (...) {
                                  LOG_ERROR("Worker[{}]: TCP connection coroutine failed: unknown",
                                            worker.id_);
                              }
                          }
                          --worker.runtime_->active_connections;
                          worker.runtime_->listener_state->DrainRetiredOutboundsIfIdle(worker);
                      });
    }
}

// ============================================================================
// ProcessReceivedConnection — per-connection 协程
// ============================================================================

net::awaitable<void> Worker::ListenerState::ProcessReceivedConnection(
    Worker& worker,
    tcp::socket socket,
    tcp::endpoint remote_ep,
    std::shared_ptr<proxyman::inbound::Handler> inbound_handler) {
    if (!inbound_handler) {
        LOG_ERROR("Worker[{}]: no inbound handler for accepted connection", worker.id_);
        socket.close();
        co_return;
    }
    proxyman::inbound::ReceiverSettings& listener = inbound_handler->ReceiverSettings();

    auto tcp_stream = std::make_unique<TcpStream>(std::move(socket));

    session::Context ctx;
    ctx.conn_id = session::NewID(worker.id_);
    ctx.worker_id = worker.id_;
    ctx.inbound.tag      = listener.inbound_tag;
    ctx.inbound.tags     = listener.RouteInboundTags();
    const auto local_ep = tcp_stream->LocalEndpoint();
    if (!local_ep.address().is_unspecified()) {
        const auto local_addr = iputil::NormalizeAddress(local_ep.address());
        ctx.inbound.local_endpoint = tcp::endpoint(local_addr, local_ep.port());
    }
    try {
        const auto normalized_remote = iputil::NormalizeAddress(remote_ep.address());
        ctx.inbound.source_addr = normalized_remote;
        ctx.inbound.source_ip = normalized_remote.to_string();
        ctx.inbound.source_port = remote_ep.port();
    } catch (...) {
        ctx.inbound.source_ip = "unknown";
    }
    const auto runtime_snapshot = worker.runtime_->Snapshot();
    uint32_t pressure_idle_timeout = 0;
    if (worker.runtime_->active_connections >= runtime_snapshot->pressure_threshold) {
        pressure_idle_timeout = runtime_snapshot->pressure_idle_timeout;
    }
    LOG_CONN_DEBUG(ctx, "Worker[{}]: accepted TCP tag={} from {}:{}",
                   worker.id_,
                   ctx.inbound.tag,
                   ctx.inbound.source_ip,
                   ctx.inbound.source_port);

    // ----------------------------------------------------------------
    // PROXY Protocol 检测（负载均衡器透传真实客户端 IP）
    //
    // 读取、消耗和 pending-data 管理由 transport/internet 完成；
    // Worker 只把解析出的真实客户端地址写入当前 session。
    // ----------------------------------------------------------------
    if (listener.proxy_protocol != ProxyProtocolMode::Off) {
        auto proxy_read = co_await tcp_stream->ReadProxyProtocolHeader(
            runtime_snapshot->timeouts.HandshakeTimeout());
        if (!proxy_read.ok()) {
            switch (proxy_read.status) {
                case ProxyProtocolReadStatus::TimedOut:
                    LOG_CONN_FAIL_CTX(ctx,
                                      "PROXY_PROTOCOL_TIMEOUT client={}",
                                      ctx.inbound.source_ip);
                    break;
                case ProxyProtocolReadStatus::Truncated:
                    LOG_CONN_FAIL_CTX(ctx, "PROXY_PROTOCOL_TRUNCATED");
                    break;
                case ProxyProtocolReadStatus::TooLarge:
                    LOG_CONN_FAIL_CTX(ctx, "PROXY_PROTOCOL_TOO_LARGE limit={}B", 2048);
                    break;
                case ProxyProtocolReadStatus::Invalid:
                    LOG_CONN_FAIL_CTX(ctx, "PROXY_PROTOCOL_INVALID");
                    break;
                case ProxyProtocolReadStatus::Ok:
                    break;
            }
            tcp_stream->Close();
            co_return;
        }

        if (listener.proxy_protocol == ProxyProtocolMode::On &&
            proxy_read.result.status != ProxyProtocolParseStatus::Success) {
            LOG_CONN_FAIL_CTX(ctx,
                              "PROXY_PROTOCOL_REQUIRED_MISSING client={}",
                              ctx.inbound.source_ip);
            tcp_stream->Close();
            co_return;
        }

        ApplyProxyProtocolResult(worker.id_, ctx, remote_ep, proxy_read.result);
    }

    co_await inbound_handler->ProcessAcceptedTCP(
        worker.runtime_->io_context, *worker.runtime_->dispatcher, worker.runtime_->stats, runtime_snapshot->timeouts,
        std::move(tcp_stream), ctx,
        pressure_idle_timeout);
}

// ============================================================================
// 线程安全 Async 接口（主线程调用，post 到 Worker 线程）
// ============================================================================

net::awaitable<bool> Worker::AddListenerTask(PortBinding binding) {
    co_return runtime_->listener_state->StartListening(*this, binding);
}

net::awaitable<void> Worker::ShutdownTask() {
    runtime_->listener_state->Shutdown();
    runtime_->udp_session_manager->StopAll();

    // Yield once so listener/session cancellation handlers queued above can
    // run before the main thread stops this Worker io_context.
    co_await net::post(runtime_->io_context, net::use_awaitable);
}

bool Worker::RegisterInboundOnWorkerThread(
    std::string_view protocol,
    ConnectionLimiterPtr limiter,
    const proxyman::inbound::BuildRequest& req,
    proxyman::inbound::ReceiverSettings receiver) {
    auto handler = runtime_->inbound_manager->NewHandler(protocol, limiter, req);
    if (!handler) {
        LOG_WARN("Worker[{}]: failed to create inbound handler tag={} protocol={}",
                 id_, receiver.inbound_tag, protocol);
        return false;
    }
    runtime_->listener_state->DrainRetiredOutboundsIfIdle(*this);
    auto inbound_handler =
        std::make_unique<proxyman::inbound::Handler>(std::move(receiver), std::move(handler));
    auto& settings = inbound_handler->ReceiverSettings();
    if (settings.route_policy.kind == proxyman::inbound::RoutePolicyKind::FixedOutbound &&
        !runtime_->outbound_manager->GetHandler(settings.route_policy.outbound_tag)) {
        LOG_WARN("Worker[{}]: listener tag={} fixed outbound '{}' not found",
                 id_, settings.inbound_tag, settings.route_policy.outbound_tag);
    }
    const std::string key(settings.inbound_tag);
    auto [slot_it, slot_inserted] =
        runtime_->listener_state->listener_slots.try_emplace(key);
    std::shared_ptr<proxyman::inbound::Handler> registered;
    try {
        registered = runtime_->inbound_manager->ReplaceHandler(
            std::move(inbound_handler));
    } catch (...) {
        if (slot_inserted) {
            runtime_->listener_state->listener_slots.erase(slot_it);
        }
        throw;
    }
    if (!registered) {
        if (slot_inserted) {
            runtime_->listener_state->listener_slots.erase(slot_it);
        }
        LOG_WARN("Worker[{}]: failed to install inbound handler tag={}", id_, key);
        return false;
    }
    slot_it->second.handler = registered;
    runtime_->listener_state->DrainRetiredOutboundsIfIdle(*this);
    return true;
}

net::awaitable<bool> Worker::RegisterInboundTask(
    std::string protocol,
    ConnectionLimiterPtr limiter,
    proxyman::inbound::BuildRequest req,
    proxyman::inbound::ReceiverSettings receiver) {
    co_return RegisterInboundOnWorkerThread(
        protocol, limiter, req, std::move(receiver));
}

void Worker::AddOutboundOnWorkerThread(
    proxyman::outbound::PreparedOutboundConfig config) {
    runtime_->listener_state->DrainRetiredOutboundsIfIdle(*this);

    auto current_snapshot = runtime_->Snapshot();
    auto handler = proxyman::outbound::NewHandler(
        config, runtime_->io_context,
        *runtime_->dns_service, runtime_->udp_session_manager.get(),
        current_snapshot->timeouts.DialTimeout());

    auto next_snapshot = std::make_shared<WorkerRuntimeConfig>(*current_snapshot);
    std::erase_if(next_snapshot->outbounds,
                  [&](const auto& outbound) { return outbound.tag == config.tag; });
    next_snapshot->outbounds.push_back(std::move(config));
    if (next_snapshot->default_outbound_tag.empty()) {
        next_snapshot->default_outbound_tag = next_snapshot->outbounds.front().tag;
    }

    const bool update_router_default =
        runtime_->router->DefaultOutbound() != next_snapshot->default_outbound_tag;
    std::string next_router_default;
    if (update_router_default) {
        next_router_default = next_snapshot->default_outbound_tag;
    }
    const std::string_view installed_protocol = next_snapshot->outbounds.back().protocol;
    const std::string_view installed_tag = next_snapshot->outbounds.back().tag;

    if (!runtime_->outbound_manager->ReplaceHandler(std::move(handler))) {
        throw std::logic_error(
            "failed to install dynamic outbound '" + std::string(installed_tag) + "'");
    }
    if (update_router_default) {
        runtime_->router->SetDefaultOutbound(std::move(next_router_default));
    }
    runtime_->StoreSnapshot(std::move(next_snapshot));

    LOG_DEBUG("Worker[{}]: registered dynamic {} outbound '{}'",
              id_, installed_protocol, installed_tag);
    runtime_->listener_state->DrainRetiredOutboundsIfIdle(*this);
}

net::awaitable<void> Worker::AddOutboundTask(
    proxyman::outbound::PreparedOutboundConfig config) {
    AddOutboundOnWorkerThread(std::move(config));
    co_return;
}

void Worker::RemoveOutboundOnWorkerThread(std::string_view tag) {
    auto current_snapshot = runtime_->Snapshot();
    auto next_snapshot = std::make_shared<WorkerRuntimeConfig>(*current_snapshot);
    std::erase_if(next_snapshot->outbounds,
                  [&](const auto& outbound) { return outbound.tag == tag; });
    if (next_snapshot->default_outbound_tag == tag) {
        next_snapshot->default_outbound_tag = next_snapshot->outbounds.empty()
            ? std::string(constants::protocol::kDirect)
            : next_snapshot->outbounds.front().tag;
    }

    const bool update_router_default =
        runtime_->router->DefaultOutbound() != next_snapshot->default_outbound_tag;
    std::string next_router_default;
    if (update_router_default) {
        next_router_default = next_snapshot->default_outbound_tag;
    }

    runtime_->outbound_manager->RemoveHandler(tag);
    if (update_router_default) {
        runtime_->router->SetDefaultOutbound(std::move(next_router_default));
    }
    runtime_->StoreSnapshot(std::move(next_snapshot));
    runtime_->listener_state->DrainRetiredOutboundsIfIdle(*this);
}

net::awaitable<void> Worker::RemoveOutboundTask(std::string tag) {
    RemoveOutboundOnWorkerThread(tag);
    co_return;
}

void Worker::ListenerState::DrainRetiredOutboundsIfIdle(Worker& worker) {
    if (worker.runtime_->active_connections != 0) {
        return;
    }
    worker.runtime_->outbound_manager->DrainRetiredHandlers();
}

void Worker::UnregisterListenerOnWorkerThread(std::string_view tag) {
    auto current_snapshot = runtime_->Snapshot();
    const std::string owned_tag(tag);
    auto next_snapshot = std::make_shared<WorkerRuntimeConfig>(*current_snapshot);
    RemoveInboundRuntimeFromSnapshot(*next_snapshot, tag);

    auto tcp_listener_keys =
        runtime_->listener_state->CollectTcpListenerKeys(owned_tag);
    auto udp_socket_keys =
        runtime_->listener_state->CollectUdpSocketKeys(owned_tag);

    auto retiring = runtime_->inbound_manager->GetHandler(owned_tag);
    runtime_->inbound_manager->RemoveHandler(owned_tag);
    if (auto slot_it = runtime_->listener_state->listener_slots.find(owned_tag);
            slot_it != runtime_->listener_state->listener_slots.end() &&
            slot_it->second.handler == retiring) {
        slot_it->second.handler.reset();
    }
    runtime_->listener_state->StopListening(
        owned_tag, std::move(tcp_listener_keys));
    runtime_->listener_state->StopUdpListening(
        owned_tag, std::move(udp_socket_keys));
    runtime_->StoreSnapshot(std::move(next_snapshot));
    runtime_->listener_state->DrainRetiredOutboundsIfIdle(*this);
}

net::awaitable<void> Worker::UnregisterListenerTask(std::string tag) {
    UnregisterListenerOnWorkerThread(tag);
    co_return;
}

net::awaitable<void> Worker::UpdateRuleTask(
    std::string tag,
    std::vector<rule::DetectRule> rules) {
    runtime_->rule_manager->UpdateRule(tag, rules);
    co_return;
}

// ============================================================================
// 数据收集协程（在 Worker 线程执行，供 Spawn 从主线程调用）
// ============================================================================

net::awaitable<Worker::UserTrafficSnapshot>
Worker::GetTrafficTask(std::string tag) {
    co_return runtime_->session_tracking->CollectAndResetTraffic(tag);
}

void Worker::AddUserTraffic(std::string_view tag,
                            int64_t user_id,
                            uint64_t upload,
                            uint64_t download) {
    runtime_->session_tracking->AddUserTraffic(
        tag,
        user_id,
        upload,
        download);
}

net::awaitable<std::vector<OnlineDevice>>
Worker::GetOnlineDeviceTask(std::string tag) {
    auto handler = runtime_->inbound_manager->GetHandler(tag);
    if (!handler) {
        co_return std::vector<OnlineDevice>{};
    }
    co_return runtime_->inbound_manager->GetOnlineDevices(handler->ReceiverSettings().protocol, tag);
}

net::awaitable<std::vector<rule::DetectResult>>
Worker::GetDetectResultTask(std::string tag) {
    co_return runtime_->rule_manager->GetDetectResult(tag);
}

// ============================================================================
// 运行时资源计数，仅通过 Worker executor 上的收集任务读取。
// ============================================================================

Worker::MemoryStats Worker::GetMemoryStats() const {
    MemoryStats stats;

    auto dns_stats       = runtime_->dns_service->GetCacheStats();
    stats.dns_entries    = dns_stats.entries;

    stats.udp_sessions        = runtime_->udp_session_manager->ActiveSessionCount();
    stats.buffer_recycle      = buf::SnapshotThreadBufferRecycleStats();
    stats.small_alloc_cache   = memory::SnapshotThreadSmallAllocCacheStats();
    return stats;
}

net::awaitable<Worker::RuntimeStatsSnapshot>
Worker::CollectRuntimeStatsTask() const {
    RuntimeStatsSnapshot snapshot;
    snapshot.memory = GetMemoryStats();
    snapshot.dns_cache = runtime_->dns_service->GetCacheStats();
    snapshot.stats = runtime_->stats.Snapshot();
    snapshot.active_connections = runtime_->active_connections;
    co_return snapshot;
}

// ============================================================================
// UDP 监听（SO_REUSEPORT，与 TCP acceptor 同端口）
//
// 具体的解码、认证和 ban 逻辑委托给 inbound UdpHandler；Worker 只维护监听
// socket 与当前 Worker-local UdpWorker 生命周期。
// ============================================================================

net::awaitable<bool> Worker::AddUdpListenerTask(
    PortBinding binding,
    std::string protocol,
    ConnectionLimiterPtr limiter,
    proxyman::inbound::BuildRequest req) {
    auto result = runtime_->inbound_manager->NewUdpHandler(protocol, limiter, req);
    switch (result.status) {
        case proxyman::inbound::UdpHandlerBuildStatus::Unsupported:
            co_return true;
        case proxyman::inbound::UdpHandlerBuildStatus::Failed:
            co_return false;
        case proxyman::inbound::UdpHandlerBuildStatus::Ready:
            if (!result.handler) {
                co_return false;
            }
            break;
    }
    co_return runtime_->listener_state->StartUdpListening(
        *this, binding, std::move(result.handler));
}

bool Worker::ListenerState::StartUdpListening(
    Worker& worker,
    const PortBinding& binding,
    std::unique_ptr<proxyman::inbound::UdpHandler> handler) {
#ifdef _WIN32
    // TCP follows the same ownership rule above.  A UDP socket and its client
    // session table stay on the Worker that bound the socket.
    if (worker.Id() != 0) {
        return true;
    }
#endif

    const bool replacing = std::ranges::any_of(
        udp_socket_tags,
        [&](const auto& item) { return item.second == binding.tag; });
    auto existing_slot = listener_slots.find(binding.tag);
    auto existing_worker = udp_workers.find(binding.tag);
    if (replacing && existing_slot != listener_slots.end() &&
        existing_slot->second.udp_binding &&
        existing_slot->second.udp_binding->UsesSameSocket(binding) &&
        existing_worker != udp_workers.end() && existing_worker->second) {
        return existing_worker->second->ReplaceHandler(std::move(handler));
    }

    PortBinding committed_binding = binding;
    auto replacement_worker =
        std::make_unique<proxyman::inbound::UdpWorker>(
            binding.tag, std::move(handler));
    auto slot_it = listener_slots.try_emplace(binding.tag).first;
    auto worker_it = udp_workers.try_emplace(binding.tag).first;

    if (replacing) {
        LOG_WARN("Worker[{}]: replacing existing UDP listeners tag={}", worker.id_, binding.tag);
        ResetUdpListening(binding.tag, CollectUdpSocketKeys(binding.tag));
    } else if (worker_it->second) {
        worker_it->second->Close();
    }

    worker_it->second = std::move(replacement_worker);
    auto& listener_slot = slot_it->second;

    const auto listen_candidates = binding.listen.Candidates();
    size_t bound_count = 0;

    for (const auto& addr : listen_candidates) {
        const std::string listen_addr = addr.to_string();
        IoErrorCode ec;
        udp::endpoint ep(addr, binding.port);
        auto* current_udp_worker = worker_it->second.get();
        auto candidate_sock =
            current_udp_worker->MakeSocket(worker.runtime_->io_context);

        auto fail_candidate = [&](std::string_view op, std::string_view msg) -> bool {
            if (listen_candidates.size() > 1) {
                LOG_WARN("Worker[{}]: UDP {} {} failed: {}, continuing dual-stack bind",
                         worker.id_,
                         op,
                         iputil::FormatEndpointForLog(listen_addr, binding.port),
                         msg);
                return true;
            }
            LOG_ERROR("Worker[{}]: UDP {} {} failed: {}",
                      worker.id_, op, iputil::FormatEndpointForLog(listen_addr, binding.port), msg);
            return false;
        };

        candidate_sock->open(ep.protocol(), ec);
        if (ec) {
            if (fail_candidate("open", ec.message())) continue;
            break;
        }

        if (addr.is_v6()) {
            candidate_sock->set_option(net::ip::v6_only(true), ec);
            if (ec) {
                if (fail_candidate("set IPV6_V6ONLY", ec.message())) continue;
                break;
            }
        }

        candidate_sock->set_option(net::socket_base::reuse_address(true), ec);

#ifndef _WIN32
        // SO_REUSEPORT：每 Worker 独立绑定，内核负载均衡。
        int optval = 1;
        if (::setsockopt(candidate_sock->native_handle(), SOL_SOCKET, SO_REUSEPORT,
                         &optval, sizeof(optval)) < 0) {
            if (fail_candidate("SO_REUSEPORT", strerror(errno))) continue;
            break;
        }
#endif

        candidate_sock->bind(ep, ec);
        if (ec) {
            if (fail_candidate("bind", ec.message())) continue;
            break;
        }

        const std::string socket_key = BuildListenerKey(binding.tag, listen_addr, binding.port);
        udp::socket* bound_sock =
            current_udp_worker->AttachSocket(socket_key, std::move(candidate_sock));
        if (!bound_sock) {
            LOG_ERROR("Worker[{}]: failed to attach UDP socket tag={} key={}",
                      worker.id_, binding.tag, socket_key);
            continue;
        }
        udp_socket_tags[socket_key] = binding.tag;

        net::co_spawn(worker.runtime_->io_context.get_executor(),
                      UdpReceiveLoop(worker, socket_key, binding.tag, &listener_slot),
                      [](std::exception_ptr) {});

        ++bound_count;
        LOG_DEBUG("worker.udp_listener ready worker={} endpoint={} tag={} protocol={} accept=SO_REUSEPORT",
                  worker.id_,
                  iputil::FormatEndpointForLog(listen_addr, binding.port),
                  binding.tag,
                  binding.protocol);
    }

    if (bound_count == 0) {
        worker_it->second->Close();
        udp_workers.erase(worker_it);
        listener_slot.udp_binding.reset();
        LOG_ERROR("Worker[{}]: no UDP listener bound tag={} protocol={}",
                  worker.id_, binding.tag, binding.protocol);
        return false;
    }
    listener_slot.udp_binding = std::move(committed_binding);
    return true;
}

// ============================================================================
// UdpReceiveLoop — 通用 UDP 数据报收发主循环（协议无关）
//
// 设计参考 xray-core transport/internet/udp.Dispatcher：
//   - Worker 只做 UDP socket 收发；inbound UDP datagram 处理下沉到 UdpWorker。
//   - 每个客户端 (IP:port) 由 UdpWorker 维护一个 transport::Link，首包创建后
//     交给 dispatcher.Dispatch；路由、出站选择和 UDP relay 均在主链路内完成。
//   - 会话空闲超过配置的 session idle 后关闭 link，relay 自然退出。
// ============================================================================

net::awaitable<void> Worker::ListenerState::UdpReceiveLoop(
    Worker& worker,
    std::string socket_key,
    std::string tag,
    ListenerSlot* listener_slot) {
    constexpr size_t kRecvBufSize = buf::Buffer::kSize;
    const auto runtime_snapshot = worker.runtime_->Snapshot();
    const auto session_idle_timeout = runtime_snapshot->timeouts.SessionIdleTimeout();

    auto* udp_worker = FindUdpWorkerBySocketKey(socket_key);
    if (!udp_worker) {
        co_return;
    }
    udp::socket* sock = udp_worker->FindSocket(socket_key);
    if (!sock) {
        co_return;
    }

    while (true) {
        udp::endpoint client_ep;
        buf::BufferGuard recv_buf{buf::Buffer::New()};
        if (!recv_buf) {
            LOG_ERROR("Worker[{}]: UDP receive buffer allocation failed tag={}", worker.id_, tag);
            co_return;
        }
        auto [ec, n] = co_await sock->async_receive_from(
            net::buffer(recv_buf->Tail().data(), kRecvBufSize), client_ep,
            net::as_tuple(net::use_awaitable));

        if (ec == io_error::operation_aborted) co_return;
        if (ec || n == 0) {
            continue;
        }

        // ── 懒清理空闲会话 ────────────────────────────────────────────────
        const auto now = std::chrono::steady_clock::now();
        udp_worker->CleanupIdleClientSessions(socket_key, now, session_idle_timeout);

        const proxyman::inbound::ReceiverSettings* listener =
            listener_slot && listener_slot->handler
                ? &listener_slot->handler->ReceiverSettings()
                : nullptr;

        udp_worker->ProcessDatagram(proxyman::inbound::UdpDatagramContext{
            .socket_key = socket_key,
            .sock = sock,
            .client_endpoint = client_ep,
            .payload = std::span<const uint8_t>(recv_buf->Tail().data(), n),
            .receiver = listener,
            .io_context = worker.runtime_->io_context,
            .dispatcher = *worker.runtime_->dispatcher,
            .stats = worker.runtime_->stats,
            .timeouts = runtime_snapshot->timeouts,
            .worker_id = worker.id_,
            .reply_sink = *this,
        });
    }
}

}  // namespace acpp
